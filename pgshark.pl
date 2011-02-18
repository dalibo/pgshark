#!/usr/bin/perl 

use strict;
use warnings;

#use Net::TcpDumpLog;
use Net::Pcap qw(:functions);
use NetPacket::Ethernet qw(:types);
use NetPacket::IP qw(:protos);
use NetPacket::TCP;
use Data::Hexdumper;
use Data::Dumper;
use Getopt::Long;
use Pod::Usage;

=head1 pgshark.pl

pgshark.pl - Mess with PostgreSQL client's traffic

=head1 SYNOPSIS

pgshark.pl [--debug] {--plugin plugin_name}
pgshark.pl --help
  
=head1 DESCRIPTION

This program study PostgreSQL traffic captured in tcpdump format and is able to make various things with extracted client's
activities.

B<pgshark> comes with various plugins to do various things with client's traffic.

Presently, B<pgshark> is only able to read tcpdump files from its standart input.

=over 2

=item * B<-h>, B<--help>
Show this help message and exit.

=item * B<-d>, B<--debug> 
Print some debug messages to the standart error. The more you repeat this option, the more B<pgshark> will be verbose.

=item * B<-p>, B<--plugin>
Select the traffic processing plugin

=back

=head1 EXAMPLES

cat some_capture.pcap | pgshark.pl --plugin SQL

=head1 Author

Dalibo's team. http://www.dalibo.org

=cut

my $err = '';
my %pckt_hdr;
my $pckt = {};
my $pckt_num = 0;
my $sessions = {};
my $pcap;

sub usage {
  pod2usage(-exitval => 1);
}

sub longusage {
  pod2usage(-verbose => 2, -exitval => 1);
}

# get options
my %o = (
	debug => 0,
	help => 0,
	plugin => ''
);

GetOptions(\%o, qw{
	help
	debug+
	plugin=s
}) or usage();

longusage() if ($o{help});
usage() if ($o{plugin} eq '' );


# load the plugin
if ($o{plugin} eq 'sql') { use SQL; }

# opening the pcap file 
# TODO support input file ?
# TODO support direct sniffing ?
$pcap = pcap_open_offline('-', \$err);

while (defined($pckt = pcap_next($pcap, \%pckt_hdr))) {
	
	$pckt_num++;
	my ($eth, $ip, $tcp);
	my ($sess_hash);
	
	$eth = NetPacket::Ethernet->decode($pckt);
	
	if (defined($eth->{data}) 
	and defined($eth->{type}) 
	and ($eth->{type} == ETH_TYPE_IP)) {
		# decode the IP payload
		$ip = NetPacket::IP->decode($eth->{data});

		if ($ip->{proto} == IP_PROTO_TCP) {
			# decode the TCP payload
			$tcp = NetPacket::TCP->decode($ip->{data});
			$sess_hash = $ip->{src_ip} . $tcp->{src_port} . $ip->{dest_ip} . $tcp->{dest_port};
			$sess_hash =~ s/\.//g; # useless but for better debug messages
		}

		# check if we have data
		if (length $tcp->{data}) {
			
			debug(2, "packet: #=%d len=%s, caplen=%s\n", $pckt_num, map { $pckt_hdr{$_} } qw(len caplen));
			debug(2, "IP:TCP %s:%d -> %s:%d\n", $ip->{src_ip}, $tcp->{src_port}, $ip->{dest_ip}, $tcp->{dest_port});
			
			if (! defined($sessions->{$sess_hash}) ) {
				# we are opening a new pg session, wait for a valid message type from frontend
				if (pack('A', $tcp->{data}) =~ /[BCdcfDEHFPpQSX]/) {
					debug(2, "PGSQL: creating a new session %s\n", $sess_hash);
					$sessions->{$sess_hash} = {
						data => '',
						pg_len => 0,
					};
				}
			}
			
			# if we have a session with data
			if (defined($sessions->{$sess_hash}) ) {
				# the session is already authenticated we should get type'd messages
				$sessions->{$sess_hash}->{data} .= $tcp->{data};
				my $data_len = length $sessions->{$sess_hash}->{data};
								
				# if we have at least 5 byte, we can analyze the begin of message
				while ($data_len >= 5) {
					my ($pg_type, $pg_len) = unpack('AN', $sessions->{$sess_hash}->{data});
					
					# pg_len includes itself (int32) in the message size
					$sessions->{$sess_hash}->{pg_len} = $pg_len;

					# pg_len is the size of the message length field + data. it doesn't include the message type char
					# so a full pgsql message is pg_len + 1
					if ($data_len >= $pg_len + 1) {
						# we have enough data for a message

						### do some processing here
						
						debug(1, "    PGSQL: pckt=%d session=%s type=%s, len=%d, data_len=%d\n", $pckt_num, $sess_hash, $pg_type, $pg_len, $data_len);
						my $pg_msg = substr($sessions->{$sess_hash}->{data}, 5, $pg_len);
						
						SWITCH: {
							if ( $pg_type eq 'P') {
								process_parse($sessions, $sess_hash);
								last SWITCH;
							}
							if ( $pg_type eq 'B') {
								process_bind($sessions, $sess_hash);
								last SWITCH;
							}
							if ( $pg_type eq 'E') {
								process_execute($sessions, $sess_hash);
								last SWITCH;
							}
							if ( $pg_type eq 'C') {
								process_close($sessions, $sess_hash);
								last SWITCH;
							}
							if ( $pg_type eq 'Q') {
								process_query($sessions, $sess_hash);
								last SWITCH;
							}
							if ( $pg_type eq 'X') {
								process_disconnect($sessions, $sess_hash);
								last SWITCH;
							}
							debug(2,"ignoring message type: %s\n", $pg_type);
						}

						### end of processing, remove processed data
						$sessions->{$sess_hash}->{data} = substr($sessions->{$sess_hash}->{data}, 1 + $pg_len);
						$data_len = length $sessions->{$sess_hash}->{data};
					}
					else {
						# we don't have the full message in available data.
						# stop the loop we'll wait for some more
						last;
					}
				}

				# remove the session if we have no trailing data
				# we can do way much better by tracking the session disconnection
				if ($data_len == 0) {
					debug(2, "PGSQL: data in session empty, destroying\n");
					undef $sessions->{$sess_hash};
				}
			}
		}
	}
}

sub debug {
	my $lvl = shift;
	my $format = shift;
	printf(STDERR $format, @_) if $o{debug} >= $lvl;
}

pcap_close($pcap);

debug(1, "bye.\n");


