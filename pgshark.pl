#!/usr/bin/perl

use strict;
use warnings;

#use Net::TcpDumpLog;
use Net::Pcap qw(:functions);
use Net::Pcap::Reassemble;
use NetPacket::Ethernet qw(:types);
use NetPacket::IP qw(:protos);
use NetPacket::TCP;
use Data::Hexdumper;
use Data::Dumper;
use Getopt::Long;
use Pod::Usage;
use pgShark::Utils;

my $err = '';
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
	or ($args{'output'} eq 'Debug')
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

my $processor = $args{'output'}->new(\%args, $pcap);

Net::Pcap::Reassemble::loop($pcap, -1, \&process_packet, '');

sub process_packet {
	my($user_data, $pckt_hdr, $pckt) = @_;

	$pckt_num++;
	my ($eth, $ip, $tcp);
	my ($sess_hash, $is_srv);

	$eth = NetPacket::Ethernet->decode($pckt);

	if (defined($eth->{'data'})
			and defined($eth->{'type'})
			and ($eth->{'type'} == ETH_TYPE_IP)
	) {
		# decode the IP payload
		$ip = NetPacket::IP->decode($eth->{'data'});

		if ($ip->{'proto'} == IP_PROTO_TCP) {
			# decode the TCP payload
			$tcp = NetPacket::TCP->decode($ip->{'data'});

			debug(2, "packet: #=%d len=%s, caplen=%s\n", $pckt_num, map { $pckt_hdr->{$_} } qw(len caplen));

			# check if we have data
			if (length $tcp->{'data'}) {

				debug(2, "IP:TCP %s:%d -> %s:%d\n", $ip->{'src_ip'}, $tcp->{'src_port'}, $ip->{'dest_ip'}, $tcp->{'dest_port'});

				# we could add server ip and port to this hash,
				# but we are suppose to work with only one server
				if ($ip->{'src_ip'} eq $args{'host'} and $tcp->{'src_port'} == $args{'port'}) {
					$is_srv = 1;
					$sess_hash = $ip->{'dest_ip'} . $tcp->{'dest_port'};
				}
				else {
					$is_srv = 0;
					$sess_hash = $ip->{'src_ip'} . $tcp->{'src_port'};
				}
				$sess_hash =~ s/\.//g; # FIXME perf ? useless but for better debug messages

				if (not defined($sessions->{$sess_hash})) {
					debug(3, "PGSQL: creating a new session %s\n", $sess_hash);
					$sessions->{$sess_hash} = {
						'data' => '',
						'pg_len' => 0,
					};
				}

				# the session is already authenticated we should get type'd messages
				$sessions->{$sess_hash}->{'data'} .= $tcp->{'data'};
				my $data_len = length $sessions->{$sess_hash}->{'data'};

				do {

					# hash about message informations
					my $pg_msg = {
						'sess_hash' => $sess_hash,
						'timestamp' => "$pckt_hdr->{'tv_sec'}.". sprintf('%06d', $pckt_hdr->{'tv_usec'}),
						## the following entries will be feeded bellow
						# 'type' => message type. Either one-char type or full message for special ones
						# 'data' =>  the message data (without the type and int32 length)
					};

					my $msg_len = 0;

					if (
						(not $is_srv and $sessions->{$sess_hash}->{'data'} =~ /^[BCfDEHFPpQSXdc].{4}/s)
						or ($is_srv and $sessions->{$sess_hash}->{'data'} =~ /^[RK23CGHDIEVnNAtS1sZTdc].{4}/s)
					) {
						# the message has a type byte
						($pg_msg->{'type'}, $msg_len) = unpack('AN', $sessions->{$sess_hash}->{'data'});

						# +1 for the message type
						$msg_len++;

						# we don't have the full message, waiting for more bits
						if ($data_len < $msg_len) {
							debug(2, "NOTICE: message fragmented (data available: %d, message length: %d), waiting for more bits.\n", $data_len, $msg_len);
							return;
						}

						$pg_msg->{'data'} = substr($sessions->{$sess_hash}->{'data'}, 5, $msg_len - 5);
					}
					elsif ($is_srv and $sessions->{$sess_hash}->{'data'} =~ /^N|S$/) {
						# SSL answer
						$pg_msg->{'type'} = 'SSLAnswer';

						$msg_len = 1;
						$pg_msg->{'data'} = $sessions->{$sess_hash}->{'data'};
					}
					elsif (not $is_srv and $sessions->{$sess_hash}->{'data'} =~ /^.{8}/s) {
						my $code;
						( $msg_len, $code) = unpack('NN', $sessions->{$sess_hash}->{'data'});
						if ($code == 80877102) {
							# CancelRequest
							$pg_msg->{'type'} = 'CancelRequest';
						}
						elsif ($code == 80877103) {
							# SSLRequest
							$pg_msg->{'type'} = 'SSLRequest';
						}
						elsif ($code == 196608) {
							# StartupMessage
							# we ignore the $code here as we try to support both pgsql protos v2 and v3.
							$pg_msg->{'type'} = 'StartupMessage3';
							# my $min = $code%65536; # == 0
							# my $maj = $code/65536; # == 3
						}
						elsif ($code == 131072) {
							# StartupMessage
							# we ignore the $code here as we try to support both pgsql protos v2 and v3.
							$pg_msg->{'type'} = 'StartupMessage2';
							# my $min = $code%65536; # == 0
							# my $maj = $code/65536; # == 2
						}
						else {
							$sessions->{$sess_hash}->{'data'} =~ tr/\x00-\x1F\x7F-\xFF/./;
							debug(1, "WARNING: dropped alien packet I was unable to mess with at timestamp %s:\n'%s'\n",
								$pg_msg->{'timestamp'}, $sessions->{$sess_hash}->{'data'}
							);
							$sessions->{$sess_hash}->{'data'} = '';
							return;
						}

						$pg_msg->{'data'} = substr($sessions->{$sess_hash}->{'data'}, 4, $msg_len - 4);
					}
					else {
						debug(2, "NOTICE: looks like we have either an incomplette header or some junk in the buffer (data available: %d)...waiting for more bits.\n", $data_len);
						return ;
					}

					debug(3, "PGSQL: pckt=%d, timestamp=%s, session=%s type=%s, len=%d, data_len=%d \n",
						$pckt_num, $pg_msg->{'timestamp'}, $sess_hash, $pg_msg->{'type'}, $msg_len, $data_len
					);

					SWITCH: {

						# message: B(1) "parse complete"
						if ($is_srv and $pg_msg->{'type'} eq '1') {
							$processor->process_parse_complete($pg_msg);
							last SWITCH;
						}

						# message: B(A) "notification response"
						#   pid=int32
						#   channel=String
						#   payload=String
						if ($is_srv and $pg_msg->{'type'} eq 'A') {
							($pg_msg->{'pid'}, $pg_msg->{'channel'}, $pg_msg->{'payload'}) = unpack('N Z* Z*', $pg_msg->{'data'});
							$processor->process_notif_response($pg_msg);
							last SWITCH;
						}

						# message: F(B) "bind"
						#   portal=String
						#   name=String
						#   num_formats=int16
						#   formats[]=int16[nb_formats]
						#   num_params=int16
						#   params[]=(len=int32,value=char[len])[nb_params]
						if (not $is_srv and $pg_msg->{'type'} eq 'B') {
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

							# TODO add some safety tests about available data in $msg ?
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

						# message: B(C) "command complete"
						#   type=char
						#   name=String
						if ($is_srv and $pg_msg->{'type'} eq 'C') {

							$pg_msg->{'command'} = substr($pg_msg->{'data'}, 0, -1);;

							$processor->process_command_complete($pg_msg);
							last SWITCH;
						}

						# message: F(C) "close"
						#   type=char
						#   name=String
						if (not $is_srv and $pg_msg->{'type'} eq 'C') {

							($pg_msg->{'type'}, $pg_msg->{'name'}) = unpack('AZ*', $pg_msg->{'data'});

							$processor->process_close($pg_msg);
							last SWITCH;
						}

						# message: B(D) "data row"
						#   num_values=int16
						#   (
						#   value_len=int32
						#   value=Byte[value_len] (TODO give the format given in previous message B(T) ?)
						#   )[num_values]
						if ($is_srv and $pg_msg->{'type'} eq 'D') {
							my @values;
							my $msg = substr($pg_msg->{'data'}, 2);
							my $i = 0;

							$pg_msg->{'num_values'} = unpack('n', $pg_msg->{'data'});

							while ($i < $pg_msg->{'num_values'}) {
								my $val_len = unpack('N', $msg);
								my $val = undef;
								if ($val_len != -1) {
									$val = substr($msg, 5, $val_len);
								}
								else {
									$val = undef;
								}

								push @values, [ $val_len, $val];
								$msg = substr($msg, 4 + $val_len);
								$i++;
							}

							$pg_msg->{'values'} = [ @values ];

							$processor->process_data_row($pg_msg);
							last SWITCH;
						}

						# message: B(E) "error response"
						#   (code=char
						#   value=String){1,}\x00
						if ($is_srv and $pg_msg->{'type'} eq 'E') {
							my @fields;
							my $msg = $pg_msg->{'data'};

							FIELDS: while ($msg ne '') {
								my ($code, $value) = unpack('AZ*', $msg);
								last FIELDS if ($code eq '');
								push @fields, ($code, $value);
								$msg = substr($msg, 2 + length($value));
							}

							$pg_msg->{'fields'} = [@fields];

							$processor->process_error_response($pg_msg);
							last SWITCH;
						}

						# message: F(E) "execute"
						#   name=String
						#   nb_rows=int32
						if (not $is_srv and $pg_msg->{'type'} eq 'E') {
							($pg_msg->{'name'}, $pg_msg->{'nb_rows'}) = unpack('Z*N', $pg_msg->{'data'});

							$processor->process_execute($pg_msg);
							last SWITCH;
						}

						# message: B(I) "Empty Query Response"
						if ($is_srv and $pg_msg->{'type'} eq 'I') {

							$processor->process_empty_query($pg_msg);
							last SWITCH;
						}

						# message: B(N) "notice response"
						#   (code=char
						#   value=String){1,}\x00
						if ($is_srv and $pg_msg->{'type'} eq 'N') {
							my @fields;
							my $msg = $pg_msg->{'data'};

							FIELDS: while ($msg ne '') {
								my ($code, $value) = unpack('AZ*', $msg);
								last FIELDS if ($code eq '');
								push @fields, ($code, $value);
								$msg = substr($msg, 2 + length($value));
							}

							$pg_msg->{'fields'} = [@fields];

							$processor->process_notice_response($pg_msg);
							last SWITCH;
						}

						# message: B(n) "no data"
						if ($is_srv and $pg_msg->{'type'} eq 'n') {
							$processor->process_no_data($pg_msg);
							last SWITCH;
						}

						# message: F(P) "parse"
						#   name=String
						#   query=String
						#   num_params=int16
						#   params_types[]=int32[nb_formats]
						if (not $is_srv and $pg_msg->{'type'} eq 'P') {
							my @params_types;
							($pg_msg->{'name'}, $pg_msg->{'query'},
								$pg_msg->{'num_params'}, @params_types
							) = unpack('Z*Z*nN*', $pg_msg->{'data'});
							$pg_msg->{'params_types'} = [@params_types];

							$processor->process_parse($pg_msg);
							last SWITCH;
						}

						# message: F(Q) "query"
						#    query=String
						if (not $is_srv and $pg_msg->{'type'} eq 'Q') {

							# we remove the last char:
							# query are null terminated in pgsql proto and pg_len includes it
							$pg_msg->{'query'} = substr($pg_msg->{'data'}, 0, -1);

							$processor->process_query($pg_msg);
							last SWITCH;
						}

						# message: B(R) "authentication request"
						if ($is_srv and $pg_msg->{'type'} eq 'R') {
							$pg_msg->{'code'} = unpack('N', $pg_msg->{'data'});
							$pg_msg->{'data'} = undef;

							# md5 salt
							if ($pg_msg->{'code'} == 5) {
									$pg_msg->{'data'} = unpack('xxxxZ*', $pg_msg->{'data'});
							}
							# GSSAPI or SSPI authentication data
							elsif ($pg_msg->{'code'} == 8) {
									$pg_msg->{'data'} = substr($pg_msg->{'data'}, 5);
							}

							$processor->process_auth_request($pg_msg);
							last SWITCH;
						}

						# message: B(s) "portal suspended"
						if ($is_srv and $pg_msg->{'type'} eq 's') {
							$processor->process_portal_suspended($pg_msg);
							last SWITCH;
						}

						# message: F(S) "sync"
						if (not $is_srv and $pg_msg->{'type'} eq 'S') {
							$processor->process_sync($pg_msg);
							last SWITCH;
						}

						# message: B(T) "row description"
						#   num_fields=int16
						#   (
						#     field=String
						#     relid=int32 (0 if not associated to a table)
						#     attnum=int16 (0 if not associated to a table)
						#     type=int32
						#     type_len=int16 (-1 if variable, see pg_type.typlen)
						#     type_mod=int32 (see pg_attribute.atttypmod)
						#     format=int16 (0:text or 1:binary)
						#   )[num_fields]
						if ($is_srv and $pg_msg->{'type'} eq 'T') {
							my @fields;
							my $i=0;
							my $msg = $pg_msg->{'data'};

							$pg_msg->{'num_fields'} = unpack('n', $msg);

							ROWS: while ($i < $pg_msg->{'num_fields'}) {
								my @field = unpack('Z*NnNnNn', $msg);
								push @fields, [ @field ];
								$msg = substr($msg, 19 + length($field[0]));

								$i++;
							}

							$pg_msg->{'fields'} = [ @fields ];
							$processor->process_row_desc($pg_msg);
							last SWITCH;
						}

						# message: B(t) "parameter description"
						#   num_params=int16
						#   params_types[]=int32[nb_formats]
						if ($is_srv and $pg_msg->{'type'} eq 't') {
							my @params_types;
							($pg_msg->{'num_params'}, @params_types) = unpack('nN*', $pg_msg->{'data'});
							$pg_msg->{'params_types'} = [@params_types];
							$processor->process_param_desc($pg_msg);
							last SWITCH;
						}

						# message: F(X) "disconnect"
						if (not $is_srv and $pg_msg->{'type'} eq 'X') {
							$processor->process_disconnect($pg_msg);
							last SWITCH;
						}

						# message: B(Z) "ready for query"
						#   status=Char
						if ($is_srv and $pg_msg->{'type'} eq 'Z') {
							$pg_msg->{'status'} = $pg_msg->{'data'};
							$processor->process_ready($pg_msg);
							last SWITCH;
						}

						## messages with no 1-char type

						# message: CancelRequest (F)
						#   status=Char
						if (not $is_srv and $pg_msg->{'type'} eq 'CancelRequest') {
							$processor->process_cancel_request($pg_msg);
							last SWITCH;
						}

						# message: SSLAnswer (B)
						if ($is_srv and $pg_msg->{'type'} eq 'SSLAnswer') {
							$pg_msg->{'ssl_answer'} = $pg_msg->{'data'};
							$processor->process_ssl_answer($pg_msg);
							last SWITCH;
						}

						# message: SSLRequest (F)
						#   status=Char
						if (not $is_srv and $pg_msg->{'type'} eq 'SSLRequest') {
							$processor->process_ssl_request($pg_msg);
							last SWITCH;
						}

						# message: StartupMessage2 (F)
						#   status=Char
						if (not $is_srv and $pg_msg->{'type'} eq 'StartupMessage2') {
							$pg_msg->{'version'} = 2;
							$processor->process_startup_message($pg_msg);
							last SWITCH;
						}

						# message: StartupMessage3 (F)
						#   status=Char
						if (not $is_srv and $pg_msg->{'type'} eq 'StartupMessage3') {
							$pg_msg->{'version'} = 3;
							$processor->process_startup_message($pg_msg);
							last SWITCH;
						}

						# Default
						debug(3, "PGSQL: not implemented message type: %s(%s)\n", ($is_srv?'B':'F'), $pg_msg->{'type'});
					}

					### end of processing, remove processed data
					$sessions->{$sess_hash}->{'data'} = substr($sessions->{$sess_hash}->{'data'}, $msg_len);
					$data_len -= $msg_len;

					if ($pg_msg->{'type'} eq 'X') {
						debug(3, "PGSQL: destroying session %s (remaining buffer was %d byte long).\n", $sess_hash, $data_len);
						delete $sessions->{$sess_hash};
					}

					$num_queries++;
				} while ($data_len > 0);
			}
			else {
				debug(2, "TCP: no data\n");
			}
		}
		else {
			debug(2, "IP: not TCP\n");
		}
	}
}

pcap_close($pcap);

END {
	if ($? == 0) {
		debug(1, "-- core: Total number of messages: $num_queries\n");
		debug(1, "-- bye.\n");
	}
}

=head1 pgshark.pl

pgshark.pl - Messing with PostgreSQL network traffic

=head1 SYNOPSIS

=over 2

=item pgshark.pl --help

=item pgshark.pl [--debug] [--read file] {--output plugin_name}

Where B<plugin_name> could be I<sql> or I<normalize> or I<debug>.

=back

=head1 DESCRIPTION

This program study PostgreSQL traffic captured from the network and is able to make various things with it. The network
dump could be live or from a pcap file (usingtcpdump as instance).

B<pgshark> comes with various output plugins able to do various things with these network dumps.

=over 2

=item B<-d>, B<--debug>

Print debug informations to the standart error. The more you repeat this option, the more B<pgshark> will be verbose.
There is 3 level of debug presently.

=item B<--help>

Show this help message and exit.

=item B<-h>, B<--host> <ip address>

Gives the IP address of the PostgreSQL server. By default, set to 127.0.0.1.

=item B<--i>, B<--interface> <interface name>

Capture PostgreSQL traffic directly from the given network interface. Conflict with B<--read>.
By default, B<pgshark> will read from stdin if neither B<--read> or B<--interface> are given.

=item B<-o>, B<--output> <plugin name>

Select the dump processing output plugin. This parameter value is case-insensitive
(eg. SQL, Sql and sql will all select the SQL plugin output).
See section L</PLUGINS>.

=item B<-p>, B<--port> <port>

Gives the port the PostgreSQL backend is listening on. Be default, set to 5432

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

The B<normalize> plugin will try to normalize queries and prepared queries and output them to stdoud. It aims to give you a list
of unique queries, however the number of time they has been send by clients and whatever their parameters were.

=item B<debug>

The B<debug> plugin will output the PostgreSQL messages in human readable format. Usefull to analyze what is in a network
dump before using pgshark on some other duties.

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
