##
# This program is open source, licensed under the simplified BSD license.  For license terms, see the LICENSE file.
##
package pgShark::Core;

use strict;
use warnings;
use Net::Pcap qw(:functions);
use Net::Pcap::Reassemble;
use NetPacket::Ethernet qw(:types);
use NetPacket::IP qw(:protos);
use NetPacket::TCP;
use Data::Hexdumper;
use Data::Dumper;
use pgShark::Utils;

sub new {
	my $class = shift;
	my $args = shift;
	my $filter = undef;

	my $self = {
		'host' => defined($args->{'host'}) ? $args->{'host'} : 'localhost',
		'pcap' => undef,
		'pckt_count' => 0,
		'port' => defined($args->{'port'}) ? $args->{'port'} : '5432',
		'queries_count' => 0,
		'sessions' => {}
	};

	foreach my $func (keys %{ $args->{'procs'} } ) {
		$self->{$func} = $args->{'procs'}->{$func};
	}

	debug(1, "Core: loaded.\n");

	return bless($self, $class);
}

# set the pcap filter
sub setFilter {
	my $self = shift;
	my $filter = shift;
	my $c_filter = undef;

	if ($filter) {
		# the following filter reject TCP-only stuff and capture only frontend messages
		pcap_compile($self->{'pcap'}, \$c_filter, $filter, 0, 0);
		pcap_setfilter($self->{'pcap'}, $c_filter);
	}
}

# open a live capture on given interface
sub live {
	my $self = shift;
	my $interface = shift;
	my $err = shift;

	return 1 unless $self->{'pcap'} = pcap_open_live($interface, 65535, 0, 0, $err);

	return 0;
}

# given pcap file
sub open {
	my $self = shift;
	my $file = shift;
	my $err = shift;

	return 1 unless $self->{'pcap'} = pcap_open_offline($file, \$err);

	return 0;
}

sub close {
	my $self = shift;
	pcap_close($self->{'pcap'});

	return 0;
}

sub process_all {
	my $self = shift;
	Net::Pcap::Reassemble::loop($self->{'pcap'}, -1, \&process_packet, $self);
	# pcap_loop($pcap, -1, \&process_packet, $self);
}

sub process_packet {
	my($self, $pckt_hdr, $pckt) = @_;

	$self->{'pckt_count'}++;
	my ($eth, $ip, $tcp);
	my ($sess_hash, $from_backend);

	$eth = NetPacket::Ethernet->decode($pckt);

	return unless (defined($eth->{'data'})
			and defined($eth->{'type'})
			and ($eth->{'type'} == ETH_TYPE_IP)
	);

	# decode the IP payload
	$ip = NetPacket::IP->decode($eth->{'data'});

	unless ($ip->{'proto'} == IP_PROTO_TCP) {
		debug(2, "IP: not TCP\n");
		return;
	}

	# decode the TCP payload
	$tcp = NetPacket::TCP->decode($ip->{'data'});

	debug(2, "packet: #=%d len=%s, caplen=%s\n", $self->{'pckt_count'}, map { $pckt_hdr->{$_} } qw(len caplen));

	# check if we have data

	unless (length $tcp->{'data'}) {
		debug(2, "TCP: no data\n");
		return;
	}

	debug(2, "IP:TCP %s:%d -> %s:%d\n", $ip->{'src_ip'}, $tcp->{'src_port'}, $ip->{'dest_ip'}, $tcp->{'dest_port'});

	# we could add server ip and port to this hash,
	# but we are suppose to work with only one server
	if ($ip->{'src_ip'} eq $self->{'host'} and $tcp->{'src_port'} == $self->{'port'}) {
		$from_backend = 1;
		$sess_hash = $ip->{'dest_ip'} . $tcp->{'dest_port'};
	}
	else {
		$from_backend = 0;
		$sess_hash = $ip->{'src_ip'} . $tcp->{'src_port'};
	}
	$sess_hash =~ s/\.//g; # FIXME perf ? useless but for better debug messages

	if (not defined($self->{'sessions'}->{$sess_hash})) {
		debug(3, "PGSQL: creating a new session %s\n", $sess_hash);
		$self->{'sessions'}->{$sess_hash} = {
			'data' => '',
			'pg_len' => 0,
		};
	}

	# the session is already authenticated we should get type'd messages
	$self->{'sessions'}->{$sess_hash}->{'data'} .= $tcp->{'data'};
	my $data_len = length $self->{'sessions'}->{$sess_hash}->{'data'};

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
			(not $from_backend and $self->{'sessions'}->{$sess_hash}->{'data'} =~ /^[BCfDEHFPpQSXdc].{4}/s)
			or ($from_backend and $self->{'sessions'}->{$sess_hash}->{'data'} =~ /^[RK23CGHDIEVnNAtS1sZTdc].{4}/s)
		) {
			# the message has a type byte
			($pg_msg->{'type'}, $msg_len) = unpack('AN', $self->{'sessions'}->{$sess_hash}->{'data'});

			# +1 for the message type
			$msg_len++;

			# we don't have the full message, waiting for more bits
			if ($data_len < $msg_len) {
				debug(2, "NOTICE: message fragmented (data available: %d, message length: %d), waiting for more bits.\n", $data_len, $msg_len);
				return;
			}

			$pg_msg->{'data'} = substr($self->{'sessions'}->{$sess_hash}->{'data'}, 5, $msg_len - 5);
		}
		elsif ($from_backend and $self->{'sessions'}->{$sess_hash}->{'data'} =~ /^N|S$/) {
			# SSL answer
			$pg_msg->{'type'} = 'SSLAnswer';

			$msg_len = 1;
			$pg_msg->{'data'} = $self->{'sessions'}->{$sess_hash}->{'data'};
		}
		elsif (not $from_backend and $self->{'sessions'}->{$sess_hash}->{'data'} =~ /^.{8}/s) {
			my $code;
			( $msg_len, $code) = unpack('NN', $self->{'sessions'}->{$sess_hash}->{'data'});
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
				$self->{'sessions'}->{$sess_hash}->{'data'} =~ tr/\x00-\x1F\x7F-\xFF/./;
				debug(1, "WARNING: dropped alien packet I was unable to mess with at timestamp %s:\n'%s'\n",
					$pg_msg->{'timestamp'}, $self->{'sessions'}->{$sess_hash}->{'data'}
				);
				$self->{'sessions'}->{$sess_hash}->{'data'} = '';
				return;
			}

			$pg_msg->{'data'} = substr($self->{'sessions'}->{$sess_hash}->{'data'}, 4, $msg_len - 4);
		}
		else {
			debug(2, "NOTICE: looks like we have either an incomplette header or some junk in the buffer (data available: %d)...waiting for more bits.\n", $data_len);
			return ;
		}

		debug(3, "PGSQL: pckt=%d, timestamp=%s, session=%s type=%s, len=%d, data_len=%d \n",
			$self->{'pckt_count'}, $pg_msg->{'timestamp'}, $sess_hash, $pg_msg->{'type'}, $msg_len, $data_len
		);

		SWITCH: {

			# message: B(R) "Authentication*"
			if ($from_backend and $pg_msg->{'type'} eq 'R') {
				$pg_msg->{'code'} = unpack('N', $pg_msg->{'data'});

				# AuthenticationOk
				if ($pg_msg->{'code'} == 0) {
					$self->{'AuthenticationOk'}->($pg_msg) if defined $self->{'AuthenticationOk'};
					last SWITCH;
				}
				# AuthenticationKerberosV5
				if ($pg_msg->{'code'} == 2) {
					$self->{'AuthenticationKerberosV5'}->($pg_msg) if defined $self->{'AuthenticationKerberosV5'};
					last SWITCH;
				}
				# AuthenticationCleartextPassword
				if ($pg_msg->{'code'} == 3) {
					$self->{'AuthenticationCleartextPassword'}->($pg_msg) if defined $self->{'AuthenticationCleartextPassword'};
					last SWITCH;
				}
				# AuthenticationMD5Password
				if ($pg_msg->{'code'} == 5) {
					$pg_msg->{'salt'} = substr($pg_msg->{'data'}, 4);
					$self->{'AuthenticationMD5Password'}->($pg_msg) if defined $self->{'AuthenticationMD5Password'};
					last SWITCH;
				}
				# AuthenticationSCMCredential
				if ($pg_msg->{'code'} == 6) {
					$self->{'AuthenticationSCMCredential'}->($pg_msg) if defined $self->{'AuthenticationSCMCredential'};
					last SWITCH;
				}
				# AuthenticationGSS
				if ($pg_msg->{'code'} == 7) {
					$self->{'AuthenticationGSS'}->($pg_msg) if defined $self->{'AuthenticationGSS'};
					last SWITCH;
				}
				# AuthenticationSSPI
				if ($pg_msg->{'code'} == 9) {
					$self->{'AuthenticationSSPI'}->($pg_msg) if defined $self->{'AuthenticationSSPI'};
					last SWITCH;
				}
				# GSSAPI or SSPI authentication data
				if ($pg_msg->{'code'} == 8) {
					$pg_msg->{'auth_data'} = substr($pg_msg->{'data'}, 4);
					$self->{'AuthenticationKerberosV5'}->($pg_msg) if defined $self->{'AuthenticationKerberosV5'};
					last SWITCH;
				}

				# FIXME Add a catch all ?
			}

			# message: B(K) "BackendKeyData"
			if ($from_backend and $pg_msg->{'type'} eq 'K') {
				($pg_msg->{'pid'}, $pg_msg->{'key'}) = unpack('NN', $pg_msg->{'data'});

				$self->{'BackendKeyData'}->($pg_msg) if defined $self->{'BackendKeyData'};
				last SWITCH;
			}

			# message: F(B) "Bind"
			#   portal=String
			#   name=String
			#   num_formats=int16
			#   formats[]=int16[nb_formats]
			#   num_params=int16
			#   params[]=(len=int32,value=char[len])[nb_params]
			if (not $from_backend and $pg_msg->{'type'} eq 'B') {
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

				$self->{'Bind'}->($pg_msg) if defined $self->{'Bind'};
				last SWITCH;
			}

			# message: B(2) "BindComplete"
			if ($from_backend and $pg_msg->{'type'} eq '2') {
				$self->{'BindComplete'}->($pg_msg) if defined $self->{'BindComplete'};
				last SWITCH;
			}

			# message: CancelRequest (F)
			#   status=Char
			if (not $from_backend and $pg_msg->{'type'} eq 'CancelRequest') {
				($pg_msg->{'pid'}, $pg_msg->{'key'}) = unpack('xxxxNN', $pg_msg->{'data'});
				$self->{'CancelRequest'}->($pg_msg) if defined $self->{'CancelRequest'};
				last SWITCH;
			}

			# message: F(C) "Close"
			#   type=char
			#   name=String
			if (not $from_backend and $pg_msg->{'type'} eq 'C') {

				($pg_msg->{'type'}, $pg_msg->{'name'}) = unpack('AZ*', $pg_msg->{'data'});

				$self->{'Close'}->($pg_msg) if defined $self->{'Close'};
				last SWITCH;
			}

			# message: B(3) "CloseComplete"
			if ($from_backend and $pg_msg->{'type'} eq '3') {

				$self->{'CloseComplete'}->($pg_msg) if defined $self->{'CloseComplete'};
				last SWITCH;
			}

			# message: B(C) "CommandComplete"
			#   type=char
			#   name=String
			if ($from_backend and $pg_msg->{'type'} eq 'C') {

				$pg_msg->{'command'} = substr($pg_msg->{'data'}, 0, -1);

				$self->{'CommandComplete'}->($pg_msg) if defined $self->{'CommandComplete'};
				last SWITCH;
			}

			# message: B(d) or F(d) "CopyData"
			#   data=Byte[n]
			if ($pg_msg->{'type'} eq 'd') {
				my @fields;

				$self->{'CopyData'}->($pg_msg, $from_backend) if defined $self->{'CopyData'};
				last SWITCH;
			}

			# message: B(c) or F(c) "CopyDone"
			#   data=Byte[n]
			if ($pg_msg->{'type'} eq 'c') {
				my @fields;

				$self->{'CopyDone'}->($pg_msg, $from_backend) if defined $self->{'CopyDone'};
				last SWITCH;
			}

			# message: F(f) "CopyFail"
			#   error=String
			if (not $from_backend and $pg_msg->{'type'} eq 'f') {
				($pg_msg->{'error'}) = unpack('Z*', $pg_msg->{'data'});

				$self->{'CopyFail'}->($pg_msg) if defined $self->{'CopyFail'};
				last SWITCH;
			}

			# message: B(G) "CopyInResponse"
			#   copy_format=int8
			#   num_fields=int16
			#   fields_formats[]=int16[num_fields]
			if ($from_backend and $pg_msg->{'type'} eq 'G') {
				my @fields_formats;

				($pg_msg->{'copy_format'}, $pg_msg->{'num_fields'}, @fields_formats)
					= unpack('Cnn*', $pg_msg->{'data'});
				$pg_msg->{'fields_formats'} = [@fields_formats];

				$self->{'CopyInResponse'}->($pg_msg) if defined $self->{'CopyInResponse'};
				last SWITCH;
			}

			# message: B(H) "CopyOutResponse"
			#   copy_format=int8
			#   num_fields=int16
			#   fields_formats[]=int16[num_fields]
			if ($from_backend and $pg_msg->{'type'} eq 'H') {
				my @fields_formats;

				($pg_msg->{'copy_format'}, $pg_msg->{'num_fields'}, @fields_formats)
					= unpack('Cnn*', $pg_msg->{'data'});
				$pg_msg->{'fields_formats'} = [@fields_formats];

				$self->{'CopyOutResponse'}->($pg_msg) if defined $self->{'CopyOutResponse'};
				last SWITCH;
			}

			# message: B(D) "DataRow"
			#   num_values=int16
			#   (
			#   value_len=int32
			#   value=Byte[value_len] (TODO give the format given in previous message B(T) ?)
			#   )[num_values]
			if ($from_backend and $pg_msg->{'type'} eq 'D') {
				my @values;
				my $msg = substr($pg_msg->{'data'}, 2);
				my $i = 0;

				$pg_msg->{'num_values'} = unpack('n', $pg_msg->{'data'});

				while ($i < $pg_msg->{'num_values'}) {
					my $val_len = unpack('l>', $msg);
					my $val = undef;
					if ($val_len != -1) {
						$val = substr($msg, 4, $val_len);
						$msg = substr($msg, 4 + $val_len);
					}
					else {
						$val = undef;
						$msg = substr($msg, 4);
					}

					push @values, [ $val_len, $val];

					$i++;
				}

				$pg_msg->{'values'} = [ @values ];

				$self->{'DataRow'}->($pg_msg) if defined $self->{'DataRow'};
				last SWITCH;
			}

			# message: F(D) "Describe"
			#   type=char
			#   name=String
			if (not $from_backend and $pg_msg->{'type'} eq 'D') {

				($pg_msg->{'type'}, $pg_msg->{'name'}) = unpack('AZ*', $pg_msg->{'data'});

				$self->{'Describe'}->($pg_msg) if defined $self->{'Describe'};
				last SWITCH;
			}

			# message: B(I) "EmptyQueryResponse"
			if ($from_backend and $pg_msg->{'type'} eq 'I') {

				$self->{'EmptyQueryResponse'}->($pg_msg) if defined $self->{'EmptyQueryResponse'};
				last SWITCH;
			}

			# message: B(E) "ErrorResponse"
			#   (code=char
			#   value=String){1,}\x00
			if ($from_backend and $pg_msg->{'type'} eq 'E') {
				my $fields = {};
				my $msg = $pg_msg->{'data'};

				FIELDS: while ($msg ne '') {
					my ($code, $value) = unpack('AZ*', $msg);
					last FIELDS if ($code eq '');
					$fields->{$code} = $value;
					$msg = substr($msg, 2 + length($value));
				}

				$pg_msg->{'fields'} = $fields;

				$self->{'ErrorResponse'}->($pg_msg);
				last SWITCH;
			}

			# message: F(E) "Execute"
			#   name=String
			#   nb_rows=int32
			if (not $from_backend and $pg_msg->{'type'} eq 'E') {
				($pg_msg->{'name'}, $pg_msg->{'nb_rows'}) = unpack('Z*N', $pg_msg->{'data'});

				$self->{'Execute'}->($pg_msg) if defined $self->{'Execute'};
				last SWITCH;
			}

			# message: F(H) "Flush"
			if (not $from_backend and $pg_msg->{'type'} eq 'H') {

				$self->{'Flush'}->($pg_msg) if defined $self->{'Flush'};
				last SWITCH;
			}

			# message: "FunctionCall"
			# FIXME TODO

			# message: "FunctionCallResponse"
			# FIXME TODO

			# message: B(n) "NoData"
			if ($from_backend and $pg_msg->{'type'} eq 'n') {
				$self->{'NoData'}->($pg_msg) if defined $self->{'NoData'};
				last SWITCH;
			}

			# message: B(N) "NoticeResponse"
			#   (code=char
			#   value=String){1,}\x00
			if ($from_backend and $pg_msg->{'type'} eq 'N') {
				my $fields = {};
				my $msg = $pg_msg->{'data'};

				FIELDS: while ($msg ne '') {
					my ($code, $value) = unpack('AZ*', $msg);
					last FIELDS if ($code eq '');
					$fields->{$code} = $value;
					$msg = substr($msg, 2 + length($value));
				}

				$pg_msg->{'fields'} = $fields;

				$self->{'NoticeResponse'}->($pg_msg) if defined $self->{'NoticeResponse'};
				last SWITCH;
			}

			# message: B(A) "NotificationResponse"
			#   pid=int32
			#   channel=String
			#   payload=String
			if ($from_backend and $pg_msg->{'type'} eq 'A') {
				($pg_msg->{'pid'}, $pg_msg->{'channel'}, $pg_msg->{'payload'}) = unpack('N Z* Z*', $pg_msg->{'data'});
				$self->{'NotificationResponse'}->($pg_msg) if defined $self->{'NotificationResponse'};
				last SWITCH;
			}

			# message: B(t) "ParameterDescription"
			#   num_params=int16
			#   params_types[]=int32[nb_formats]
			if ($from_backend and $pg_msg->{'type'} eq 't') {
				my @params_types;
				($pg_msg->{'num_params'}, @params_types) = unpack('nN*', $pg_msg->{'data'});
				$pg_msg->{'params_types'} = [@params_types];
				$self->{'ParameterDescription'}->($pg_msg) if defined $self->{'ParameterDescription'};
				last SWITCH;
			}

			# message: B(S) "ParameterStatus"
			#   name=String
			#   value=String
			if ($from_backend and $pg_msg->{'type'} eq 'S') {
				($pg_msg->{'name'}, $pg_msg->{'value'}) = unpack('Z*Z*', $pg_msg->{'data'});
				$self->{'ParameterStatus'}->($pg_msg) if defined $self->{'ParameterStatus'};
				last SWITCH;
			}

			# message: F(P) "Parse"
			#   name=String
			#   query=String
			#   num_params=int16
			#   params_types[]=int32[nb_formats]
			if (not $from_backend and $pg_msg->{'type'} eq 'P') {
				my @params_types;
				($pg_msg->{'name'}, $pg_msg->{'query'},
					$pg_msg->{'num_params'}, @params_types
				) = unpack('Z*Z*nN*', $pg_msg->{'data'});
				$pg_msg->{'params_types'} = [@params_types];

				$self->{'Parse'}->($pg_msg) if defined $self->{'Parse'};
				last SWITCH;
			}

			# message: B(1) "ParseComplete"
			if ($from_backend and $pg_msg->{'type'} eq '1') {
				$self->{'ParseComplete'}->($pg_msg) if defined $self->{'ParseComplete'};
				last SWITCH;
			}

			# message: F(p) "PasswordMessage"
			#    password=String
			if (not $from_backend and $pg_msg->{'type'} eq 'p') {

				# we remove the last char:
				# query are null terminated in pgsql proto and pg_len includes it
				$pg_msg->{'password'} = substr($pg_msg->{'data'}, 0, -1);

				$self->{'PasswordMessage'}->($pg_msg) if defined $self->{'PasswordMessage'};
				last SWITCH;
			}

			# message: B(s) "PortalSuspended"
			if ($from_backend and $pg_msg->{'type'} eq 's') {
				$self->{'PortalSuspended'}->($pg_msg) if defined $self->{'PortalSuspended'};
				last SWITCH;
			}

			# message: F(Q) "Query"
			#    query=String
			if (not $from_backend and $pg_msg->{'type'} eq 'Q') {

				# we remove the last char:
				# query are null terminated in pgsql proto and pg_len includes it
				$pg_msg->{'query'} = substr($pg_msg->{'data'}, 0, -1);

				$self->{'Query'}->($pg_msg) if defined $self->{'Query'};
				last SWITCH;
			}

			# message: B(Z) "ReadyForQuery"
			#   status=Char
			if ($from_backend and $pg_msg->{'type'} eq 'Z') {
				$pg_msg->{'status'} = $pg_msg->{'data'};
				$self->{'ReadyForQuery'}->($pg_msg) if defined $self->{'ReadyForQuery'};
				last SWITCH;
			}

			# message: B(T) "RowDescription"
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
			if ($from_backend and $pg_msg->{'type'} eq 'T') {
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
				$self->{'RowDescription'}->($pg_msg) if defined $self->{'RowDescription'};
				last SWITCH;
			}

			# message: SSLAnswer (B)
			if ($from_backend and $pg_msg->{'type'} eq 'SSLAnswer') {
				$pg_msg->{'ssl_answer'} = $pg_msg->{'data'};
				$self->{'SSLAnswer'}->($pg_msg) if defined $self->{'SSLAnswer'};
				last SWITCH;
			}

			# message: SSLRequest (F)
			#   status=Char
			if (not $from_backend and $pg_msg->{'type'} eq 'SSLRequest') {
				$self->{'SSLRequest'}->($pg_msg) if defined $self->{'SSLRequest'};
				last SWITCH;
			}

			# message: StartupMessage2 (F)
			#   status=Char
			if (not $from_backend and $pg_msg->{'type'} eq 'StartupMessage2') {
				$pg_msg->{'version'} = 2;

				# TODO add given parameters from frontend

				$self->{'StartupMessage'}->($pg_msg) if defined $self->{'StartupMessage'};
				last SWITCH;
			}

			# message: StartupMessage3 (F)
			#   status=Char
			#   (param=String
			#   value=String){1,}\x00
			if (not $from_backend and $pg_msg->{'type'} eq 'StartupMessage3') {
				my $msg = substr($pg_msg->{'data'}, 4); # ignore the version fields
				my $params = {};

				$pg_msg->{'version'} = 3;

				PARAMS: while ($msg ne '') {
					my ($param, $value) = unpack('Z*Z*', $msg);
					last PARAMS if ($param eq '');
					$params->{$param} = $value;
					$msg = substr($msg, 2 + length($param) + length($value));
				}

				$pg_msg->{'params'} = $params;

				$self->{'StartupMessage'}->($pg_msg) if defined $self->{'StartupMessage'};
				last SWITCH;
			}

			# message: F(S) "Sync"
			if (not $from_backend and $pg_msg->{'type'} eq 'S') {
				$self->{'Sync'}->($pg_msg) if defined $self->{'Sync'};
				last SWITCH;
			}

			# message: F(X) "Terminate"
			if (not $from_backend and $pg_msg->{'type'} eq 'X') {
				$self->{'Terminate'}->($pg_msg) if defined $self->{'Terminate'};
				last SWITCH;
			}

			# Default
			debug(3, "PGSQL: not implemented message type: %s(%s)\n", ($from_backend?'B':'F'), $pg_msg->{'type'});
		}

		### end of processing, remove processed data
		$self->{'sessions'}->{$sess_hash}->{'data'} = substr($self->{'sessions'}->{$sess_hash}->{'data'}, $msg_len);
		$data_len -= $msg_len;

		if ($pg_msg->{'type'} eq 'X') {
			debug(3, "PGSQL: destroying session %s (remaining buffer was %d byte long).\n", $sess_hash, $data_len);
			delete $self->{'sessions'}->{$sess_hash};
		}

		$self->{'queries_count'}++;
	} while ($data_len > 0);
}

DESTROY {
	my $self = shift;
	debug(1, "-- Core: Total number of messages: $self->{'queries_count'}\n");
	debug(1, "-- bye.\n");
}

1
