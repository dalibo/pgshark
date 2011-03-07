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
use pgShark::Utils;

## TODO
# * Does not support authentication dissection

=head1 pgshark.pl

pgshark.pl - Mess with PostgreSQL client's traffic

=head1 SYNOPSIS

=over 2

=item pgshark.pl --help

=item pgshark.pl [--debug] [--read file] {--output plugin_name}

Where B<plugin_name> could be I<sql> or I<normalize>.

=back

=head1 DESCRIPTION

This program study PostgreSQL traffic captured in tcpdump format and is able to make various things with extracted client's
activities.

B<pgshark> comes with various output plugins to do various things with PostgreSQL client's traffic.

Presently, B<pgshark> is only able to read tcpdump files from its standart input.

=over 2

=item B<-d>, B<--debug>

Print some debug messages to the standart error. The more you repeat this option, the more B<pgshark> will be verbose.
(well, presently, only one level of debug from core only...)

=item B<--help>

Show this help message and exit.

=item B<--i>, B<--interface> <interface name>

Capture PostgreSQL traffic directly from the given network interface. Conflict with B<--read>.
By default, B<pgshark> will read from stdin if neither B<--read> or B<--interface> are given.

=item B<-o>, B<--output> <plugin name>

Select the traffic processing output plugin. This parameter value is case-insensitive
(eg. SQL, Sql and sql wil all select the SQL plugin output).
See section L</PLUGINS>.

=item B<-p>, B<--port> <port>

Give the port the PostgreSQL backend is listening on.

=item B<-r>, B<--read> <path to file>

Read PostgreSQL traffic from given pcap file. Conflict with B<--interface>.
By default, B<pgshark> will read from stdin if neither B<--read> or B<--interface> are given.

=back

=head1 PLUGINS

=over 2

=item B<sql>

The B<sql> plugin write captured queries on stdout. Because of limitation of SQL language it doesn't support unnamed
prepared statement, so it actually name them.

Presently, this plugin doesn't support cursors.

=item B<normalize>

The B<normalize> will try to normalize queries and prepared queries and output them to stdoud. It aims to give you a list
of unique queries, however the number of time they has been send by clients and whatever their parameters were.

=back

=head1 EXAMPLES

=over 2

=item C<cat some_capture.pcap* | pgshark.pl --output SQL>

Output all queries found in files C<some_capture.pcap*> in SQL to the standart output.

=item C<pgshark.pl --output SQL -r some_capture.pcap001>

Output all queries found in file C<some_capture.pcap001> in SQL to the standart output.

=item C<pgshark.pl --output normalize -i eth0>

Capture PostgreSQL traffic from interface eth0 and output normalized queries to the standart output.

=back

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
	my $msg = shift;
	print "$msg\n" if defined $msg and $msg ne '';
	pod2usage(-exitval => 1);
}

sub longusage {
	pod2usage(-verbose => 2, -exitval => 1);
}

# get options
my %args = (
	'debug' => 0,
	'help' => 0,
	'interface' => '',
	'output' => '',
	'host' => '127.0.0.1',
	'port' => 5432,
	'read' => '',
);

Getopt::Long::Configure('bundling');
GetOptions(\%args, qw{
	debug|d+
	help
	interface|i=s
	output|o=s
	host|p=s
	port|p=s
	read|r=s
}) or usage();


longusage() if ($args{'help'});

usage("Argument --output is mandatory.\n") if $args{'output'} eq '';

usage("Arguments --interface and --read are incompatible.\nEither listen from the networkor open a pcap file.\n")
	if $args{'interface'} ne '' and $args{'read'} ne '';

$args{'output'} = ucfirst lc $args{'output'};

# check if given plugin name exist (avoid loading potential dangerous external unknown files)
usage("This output plugin does not exist.\n") if ( not (
	   ($args{'output'} eq 'Sql')
	or ($args{'output'} eq 'Normalize')
));

# set debug level given in options
set_debug($args{'debug'});

debug (1, "Options:\n%s\n", Dumper(\%args));

## opening the pcap handler
# open a live capture on given interface
if ($args{'interface'} ne '') {

	unless ($pcap = pcap_open_live($args{'interface'}, 65535, 0, 0, \$err) ) {
		debug (0, "Can not open interface '%s':\n", $args{'interface'});
		die ($err);
	}

	debug(1, "Listening from network on interace '%s'.\n", $args{'interface'});
}
# we have no interface to listen on,
# either open given pcap file to read from or start reading from stdin
else {
	# read from stdin if no pcap file given
	$args{'read'} = '-' if $args{'read'} eq '';

	unless ($pcap = pcap_open_offline($args{'read'}, \$err)) {
		debug (0, "Can not read from file '%s':\n", $args{'read'});
		die ($err);
	}

	if ($args{'read'} eq '-') {
		debug(1, "Reading Pcap data from stdin.\n");
	}
	else {
		debug(1, "Reading from Pcap file '%s'.\n", $args{'read'});
	}
}

# load the plugin
require "./pgShark/$args{'output'}.pm";

my $processor = $args{'output'}->new(\%args, \$pcap);

while (defined($pckt = pcap_next($pcap, \%pckt_hdr))) {

	$pckt_num++;
	my ($eth, $ip, $tcp);
	my ($sess_hash);

	$eth = NetPacket::Ethernet->decode($pckt);

	if (defined($eth->{'data'})
	and defined($eth->{'type'})
	and ($eth->{'type'} == ETH_TYPE_IP)) {
		# decode the IP payload
		$ip = NetPacket::IP->decode($eth->{'data'});

		if ($ip->{'proto'} == IP_PROTO_TCP) {
			# decode the TCP payload
			$tcp = NetPacket::TCP->decode($ip->{'data'});
			# we could add server ip and port to this hash,
			# but we are suppose to work with only one server
			if ($ip->{'src_ip'} eq $args{'host'} and $tcp->{'src_port'} == $args{'port'}) {
				$sess_hash = $ip->{'dest_ip'} . $tcp->{'dest_port'};
			}
			else {
				$sess_hash = $ip->{'src_ip'} . $tcp->{'src_port'};
			}
			$sess_hash =~ s/\.//g; # FIXME perf ? useless but for better debug messages
		}

		# check if we have data
		if (length $tcp->{'data'}) {

			debug(3, "packet: #=%d len=%s, caplen=%s\n", $pckt_num, map { $pckt_hdr{$_} } qw(len caplen));
			debug(3, "IP:TCP %s:%d -> %s:%d\n", $ip->{'src_ip'}, $tcp->{'src_port'}, $ip->{'dest_ip'}, $tcp->{'dest_port'});

			if (! defined($sessions->{$sess_hash}) ) {
				# we are opening a new pg session, wait for a valid message type from frontend
				if (pack('A', $tcp->{'data'}) =~ /[BCdcfDEHFPpQSX]/) {
					debug(3, "PGSQL: creating a new session %s\n", $sess_hash);
					$sessions->{$sess_hash} = {
						data => '',
						pg_len => 0,
					};
				}
			}

			# if we have a session with data
			if (defined($sessions->{$sess_hash}) ) {
				# the session is already authenticated we should get type'd messages
				$sessions->{$sess_hash}->{'data'} .= $tcp->{'data'};
				my $data_len = length $sessions->{$sess_hash}->{'data'};

				# if we have at least 5 byte, we can analyze the begin of message
				while ($data_len >= 5) {

					# hash about message informations
					my $pg_msg = {
						'sess_hash' => $sess_hash,
						'timestamp' => "$pckt_hdr{'tv_sec'}.$pckt_hdr{'tv_usec'}"
					};
					($pg_msg->{'type'}, $pg_msg->{'len'}) = unpack('AN', $sessions->{$sess_hash}->{'data'});

					# pg_len is the size of the message length field + data. it doesn't include the message type char
					# so a full pgsql message is pg_len + 1
					if ($data_len >= $pg_msg->{'len'} + 1) {
						# we have enough data for a message

						debug(3, "    PGSQL: pckt=%d, timestamp=%s, session=%s type=%s, len=%d, data_len=%d \n",
							$pckt_num, $pg_msg->{'timestamp'}, $sess_hash, $pg_msg->{'type'}, $pg_msg->{'len'}, $data_len
						);
						$pg_msg->{'data'} = substr($sessions->{$sess_hash}->{'data'}, 5, $pg_msg->{'len'} - 4);

						SWITCH: {
							# message: F(P)
							#   name=String
							#   query=String
							#   num_params=int16
							#   params_types[]=int32[nb_formats]
							if ($tcp->{'dest_port'} == $args{'port'} and $pg_msg->{'type'} eq 'P') {
								my @params_types;
								($pg_msg->{'name'}, $pg_msg->{'query'},
									$pg_msg->{'num_params'}, @params_types
								) = unpack('Z*Z*nN*', $pg_msg->{'data'});
								$pg_msg->{'params_types'} = [@params_types];

								$processor->process_parse($pg_msg);
								last SWITCH;
							}

							# message: F(B)
							#   portal=String
							#   name=String
							#   num_formats=int16
							#   formats[]=int16[nb_formats]
							#   num_params=int16
							#   params[]=(len=int32,value=char[len])[nb_params]
							if ($tcp->{'dest_port'} == $args{'port'} and $pg_msg->{'type'} eq 'B') {
								my @params_formats;
								my @params;
								my $msg = $pg_msg->{'data'};

								($pg_msg->{'portal'}, $pg_msg->{'name'}, $pg_msg->{'num_formats'}) = unpack('Z* Z* n', $msg);
								# we add 1 bytes for both portal and name that are null-terminated
								# + 2 bytes of int16 for $num_formats
								$msg = substr($msg, length($pg_msg->{'portal'})+1 + length($pg_msg->{'name'})+1 +2);

								# catch formats and the $num_params as well
								@params_formats = unpack("n$pg_msg->{'num_formats'} n", $msg);
								$pg_msg->{'num_params'} = pop @params_formats;
								$pg_msg->{'params_types'} = [@params_formats];

								$msg = substr($msg, ($pg_msg->{'num_formats'}+1) * 2);

								for (my $i=0; $i < $pg_msg->{'num_params'}; $i++) {
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

								$pg_msg->{'params'} = [@params];

								$processor->process_bind($pg_msg);
								last SWITCH;
							}

							# message: F(E)
							#   name=String
							#   nb_rows=int32
							if ($tcp->{'dest_port'} == $args{'port'} and $pg_msg->{'type'} eq 'E') {
								($pg_msg->{'name'}, $pg_msg->{'nb_rows'}) = unpack('Z*N', $pg_msg->{'data'});

								$processor->process_execute($pg_msg);
								last SWITCH;
							}

							# message: B(C)
							#   type=char
							#   name=String
							if ($tcp->{'src_port'} == $args{'port'} and $pg_msg->{'type'} eq 'C') {

								$pg_msg->{'command'} = substr($pg_msg->{'data'}, 0, -1);;

								$processor->process_command_complete($pg_msg);
								last SWITCH;
							}

							# message: F(C)
							#   type=char
							#   name=String
							if ($tcp->{'dest_port'} == $args{'port'} and $pg_msg->{'type'} eq 'C') {

								($pg_msg->{'type'}, $pg_msg->{'name'}) = unpack('AZ*', $pg_msg->{'data'});

								$processor->process_close($pg_msg);
								last SWITCH;
							}

							# message: F(Q)
							#    query=String
							if ($tcp->{'dest_port'} == $args{'port'} and $pg_msg->{'type'} eq 'Q') {

								# we remove the last char:
								# query are null terminated in pgsql proto and pg_len includes it
								$pg_msg->{'query'} = substr($pg_msg->{'data'}, 0, -1);

								$processor->process_query($pg_msg);
								last SWITCH;
							}

							# message: F(X)
							if ($tcp->{'dest_port'} == $args{'port'} and $pg_msg->{'type'} eq 'X') {
								$processor->process_disconnect($pg_msg);
								last SWITCH;
							}

							# message: B(Z)
							#   status=Char
							if ($tcp->{'src_port'} == $args{'port'} and $pg_msg->{'type'} eq 'Z') {
								$pg_msg->{'status'} = $pg_msg->{'data'};

								$processor->process_ready($pg_msg);
								last SWITCH;
							}

							debug(3,"ignoring message type: %s\n", $pg_msg->{'type'});
						}

						### end of processing, remove processed data
						$sessions->{$sess_hash}->{'data'} = substr($sessions->{$sess_hash}->{'data'}, 1 + $pg_msg->{'len'});
						$data_len = length $sessions->{$sess_hash}->{'data'};

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
					debug(3, "PGSQL: data in session empty, destroying\n");
					delete $sessions->{$sess_hash};
				}
			}
		}
	}
}

pcap_close($pcap);

END {
	if ($? == 0) {
		debug(1, "-- core: Total number of queries processed: $num_queries\n");
		debug(1, "-- bye.\n");
	}
}
