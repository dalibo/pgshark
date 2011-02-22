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

=over 2

=item * pgshark.pl --help

=item * pgshark.pl [--debug] {--plugin plugin_name}

Where B<plugin_name> could be I<sql> or I<normalize>.

=back
  
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
(well, presently, only one level of debug from core only...)

=item * B<-p>, B<--plugin>

Select the traffic processing plugin. See section L</PLUGINS>.

=back

=head1 PLUGINS

=over 2

=item * B<sql>

The B<sql> plugin write captured queries on stdout. Because of limitation of SQL language it doesn't support unnamed 
prepared statement, so it actually name them.

Presently, this plugin doesn't support cursors.

=item * B<normalize>

The B<normalize> will try to normalize queries and prepared queries and output them to stdoud. It aims to give you a list
of unique queries, however the number of time they has been send by clients and whatever their parameters were.

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
# simple number of query processed
my $num_queries = 0;

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
# check if given plugin name exist (avoid loading potential dangerous external unknown files)
usage() if (not ($o{plugin} eq 'sql' or $o{plugin} eq 'normalize'));

debug (1, "Options:\n%s\n", Dumper(\%o));

# load the plugin
require "./$o{plugin}.pm";
$o{plugin}->import();

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
			# we could add "$ip->{dest_ip}$tcp->{dest_port}" to this hash, 
			# but we are suppose to work with only one server
			$sess_hash = $ip->{src_ip} . $tcp->{src_port};
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
					
					# hash about message informations
					my $pg_msg = {
						sess_hash => $sess_hash
					};
					($pg_msg->{type}, $pg_msg->{len}) = unpack('AN', $sessions->{$sess_hash}->{data});
					
					# pg_len is the size of the message length field + data. it doesn't include the message type char
					# so a full pgsql message is pg_len + 1
					if ($data_len >= $pg_msg->{len} + 1) {
						# we have enough data for a message
						
						debug(2, "    PGSQL: pckt=%d session=%s type=%s, len=%d, data_len=%d\n", $pckt_num, $sess_hash,
							$pg_msg->{type}, $pg_msg->{len}, $data_len
						);
						$pg_msg->{data} = substr($sessions->{$sess_hash}->{data}, 5, $pg_msg->{len} - 4);
						
						SWITCH: {
							# message: P
							#   name=String
							#   query=String 
							#   nun_params=int16
							#   params_types[]=int32[nb_formats] 
							if ( $pg_msg->{type} eq 'P') {
								my @params_types;
								($pg_msg->{name}, $pg_msg->{query},
									$pg_msg->{num_params}, @params_types
								) = unpack('Z*Z*nN*', $pg_msg->{data});
								$pg_msg->{params_types} = [@params_types];
								
								process_parse($pg_msg);
								last SWITCH;
							}
							
							# message: B
							#   portal=String 
							#   name=String
							#   nun_formats=int16 
							#   formats[]=int16[nb_formats] 
							#   nun_params=int16 
							#   params[]=(len=int32,value=char[len])[nb_params]
							if ( $pg_msg->{type} eq 'B') {
								my @params_formats;
								my @params;
								my $msg = $pg_msg->{data};
								
								($pg_msg->{portal}, $pg_msg->{name}, $pg_msg->{num_formats}) = unpack('Z* Z* n', $msg);
								# we add 1 bytes for both portal and name that are null-terminated
								# + 2 bytes of int16 for $num_formats
								$msg = substr($msg, length($pg_msg->{portal})+1 + length($pg_msg->{name})+1 +2);
								
								# catch formats and the $num_params as well
								@params_formats = unpack("n$pg_msg->{num_formats} n", $msg);
								$pg_msg->{num_params} = pop @params_formats;
								$pg_msg->{params_types} = [@params_formats];
								
								$msg = substr($msg, ($pg_msg->{num_formats}+1) * 2);
								
								for (my $i=0; $i < $pg_msg->{num_params}; $i++) {
									# unpack hasn't 32bit signed network template, so we use l>
									my ($len) = unpack('l>', $msg);
									
									# if len < 0; the value is NULL
									if ($len > 0) {
										push @params, unpack("x4 a$len", $msg);
										$msg = substr($msg, 4 + $len);
									}
									elsif ($len == 0) {
										push @params, '';
										$msg = substr($msg, 4);
									}
									else { # value is NULL
										push @params, undef;
										$msg = substr($msg, 4);
									}
									
								}
								
								$pg_msg->{params} = [@params];

								process_bind($pg_msg);
								last SWITCH;
							}
							
							# message: E
							#   name=String
							#   nb_rows=int32
							if ( $pg_msg->{type} eq 'E') {
								($pg_msg->{name}, $pg_msg->{nb_rows}) = unpack('Z*N', $pg_msg->{data});
								
								process_execute($pg_msg);
								last SWITCH;
							}
							
							# message: C
							#   type=char
							#   name=String
							if ( $pg_msg->{type} eq 'C') {
								
								($pg_msg->{type}, $pg_msg->{name}) = unpack('AZ*', $pg_msg->{data});
	
								process_close($pg_msg);
								last SWITCH;
							}
							
							# message: Q
							#    query=String
							if ( $pg_msg->{type} eq 'Q') {
								
								# we remove the last char:
								# query are null terminated in pgsql proto and pg_len includes it
								$pg_msg->{query} = substr($pg_msg->{data}, 0, -1);
								
								process_query($pg_msg);
								last SWITCH;
							}
							
							# message: X
							if ( $pg_msg->{type} eq 'X') {
								process_disconnect($pg_msg);
								last SWITCH;
							}
							
							debug(2,"ignoring message type: %s\n", $pg_msg->{type});
						}

						### end of processing, remove processed data
						$sessions->{$sess_hash}->{data} = substr($sessions->{$sess_hash}->{data}, 1 + $pg_msg->{len});
						$data_len = length $sessions->{$sess_hash}->{data};
						
						$num_queries++;
					}
					else {
						# we don't have the full message in available data.
						# stop the loop we'll wait for some more
						last;
					}
				}

				# remove the session if we have no trailing data. It helps keeping the code 
				# simple while tracking data splitted between many frame.
				# we can do way much better by tracking the session disconnection.
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

END {
	if ($? == 0) {
		debug(1, "-- core: Total number of queries processed: $num_queries\n");
		debug(1, "-- bye.\n");
	}
}
