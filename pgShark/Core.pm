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

## Constructor
# @param $args a hash ref of settings:
# {
#   'host' => IP address of the server
#   'port' => Port of the PostgreSQL server
#   'procs' => {
#	   # Hash of callbacks for each messages.
#      'message name' => \&function_to_call
#      ...
#   }
# }
# See the following link about available message name:
#   http://www.postgresql.org/docs/8.4/static/protocol-message-formats.html
# TODO add check about mandatory option 'procs' => {}
sub new {
	my $class = shift;
	my $args = shift;

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

## Set the pcap filter. See pcap-filter(7)
# @param $filter the filter to apply
sub setFilter {
	my $self = shift;
	my $filter = shift;
	my $c_filter = undef;

	if ($filter) {
		pcap_compile($self->{'pcap'}, \$c_filter, $filter, 0, 0);
		pcap_setfilter($self->{'pcap'}, $c_filter);
	}
}

## Open a live capture on given interface
# @param $interface the interface to listen on
# @param $err a reference to a string. It will be filled with the error message if the function fail.
# @returns 0 on success, 1 on failure
sub live {
	my $self = shift;
	my $interface = shift;
	my $err = shift;

	return 1 unless $self->{'pcap'} = pcap_open_live($interface, 65535, 0, 0, $err);

	return 0;
}

## Open a pcap file
# @param $file the pcap file to open
# @param $err a reference to a string. It will be filled with the error message if the function fail.
# @returns 0 on success, 1 on failure
sub open {
	my $self = shift;
	my $file = shift;
	my $err = shift;

	return 1 unless $self->{'pcap'} = pcap_open_offline($file, \$err);

	return 0;
}

## Close the current pcap handle
sub close {
	my $self = shift;
	pcap_close($self->{'pcap'}) if $self->{'pcap'};

	$self->{'pcap'} = undef;
}

## Loop over all available packets from the pcap handle
sub process_all {
	my $self = shift;
	Net::Pcap::Reassemble::loop($self->{'pcap'}, -1, \&process_packet, $self)
		if $self->{'pcap'};

	## slightly better perfs without Net::Pcap::Reassemble
	# pcap_loop($pcap, -1, \&process_packet, $self);
}

## Main callback called to dissect a network packet
# It dissects the given network packet looking for PostgreSQL data.
# If one or more PostgreSQL message is found, call the appropriate callback (from $self)
# for each messages.
sub process_packet {
	my($self, $pckt_hdr, $pckt) = @_;

	$self->{'pckt_count'}++;
	my ($eth, $ip, $tcp);
	my ($sess_hash, $from_backend);

	$eth = NetPacket::Ethernet->decode($pckt);

	# ignore non-IP packets
	return unless (defined($eth->{'data'})
		and defined($eth->{'type'})
		and ($eth->{'type'} == ETH_TYPE_IP)
	);

	# decode the IP payload
	$ip = NetPacket::IP->decode($eth->{'data'});

	# ignore non-TCP packets
	unless ($ip->{'proto'} == IP_PROTO_TCP) {
		debug(2, "IP: not TCP\n");
		return;
	}

	# decode the TCP payload
	$tcp = NetPacket::TCP->decode($ip->{'data'});

	debug(2, "packet: #=%d len=%s, caplen=%s\n", $self->{'pckt_count'}, map { $pckt_hdr->{$_} } qw(len caplen));

	# ignore tcp without data
	unless (length $tcp->{'data'}) {
		debug(2, "TCP: no data\n");
		return;
	}

	debug(2, "IP:TCP %s:%d -> %s:%d\n", $ip->{'src_ip'}, $tcp->{'src_port'}, $ip->{'dest_ip'}, $tcp->{'dest_port'});

	# pgShark must track every sessions to be able to dissect their data without
	# mixing them. Sessions related data are kept in "$self->{'sessions'}", each
	# session is identified with its hash, composed by its IP and origin port.
	# We could add server ip and port to this hash, but we are suppose to work
	# with only one server.
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
			'data' => '', # raw data of the message
		};
	}

	# add data to the current session's buffer
	$self->{'sessions'}->{$sess_hash}->{'data'} .= $tcp->{'data'};

	# buffer length. It helps tracking if we have enough data in session's
	# buffer to process the current message
	my $data_len = length $self->{'sessions'}->{$sess_hash}->{'data'};

	do {

		# hash about message informations
		my $pg_msg = {
			# the session this message belongs to
			'sess_hash' => $sess_hash,
			# timestamps of the message
			'timestamp' => "$pckt_hdr->{'tv_sec'}.". sprintf('%06d', $pckt_hdr->{'tv_usec'}),
			## the following entries will be feeded bellow
			# 'type' => message type. Either one-char type or full message for special ones
			# 'data' =>  the message data (without the type and int32 length)
			## other fields specifics to each messages are added bellow
		};

		# the message current total length
		my $msg_len = 0;

		if (
			(not $from_backend and $self->{'sessions'}->{$sess_hash}->{'data'} =~ /^[BCfDEHFPpQSXdc].{4}/s)
			or ($from_backend and $self->{'sessions'}->{$sess_hash}->{'data'} =~ /^[RK23CGHDIEVnNAtS1sZTdc].{4}/s)
		) {
			# the message has a type byte
			($pg_msg->{'type'}, $msg_len) = unpack('AN', $self->{'sessions'}->{$sess_hash}->{'data'});

			# message length given in the proto doesn't include the message type
			# Char, +1 for this type
			$msg_len++;

			# we don't have the full message, waiting for more bits
			if ($data_len < $msg_len) {
				debug(2, "NOTICE: message fragmented (data available: %d, message length: %d), waiting for more bits.\n", $data_len, $msg_len);
				return;
			}

			# record the raw message without type + length bytes
			$pg_msg->{'data'} = substr($self->{'sessions'}->{$sess_hash}->{'data'}, 5, $msg_len - 5);
		}
		elsif ($from_backend and $self->{'sessions'}->{$sess_hash}->{'data'} =~ /^N|S$/) {
			# SSL answer
			$pg_msg->{'type'} = 'SSLAnswer';

			$msg_len = 1;
			$pg_msg->{'data'} = substr($self->{'sessions'}->{$sess_hash}->{'data'}, 0, 1);
		}
		elsif (not $from_backend and $self->{'sessions'}->{$sess_hash}->{'data'} =~ /^.{8}/s) {
			my $code;
			($msg_len, $code) = unpack('NN', $self->{'sessions'}->{$sess_hash}->{'data'});
			if ($code == 80877102) {
				$pg_msg->{'type'} = 'CancelRequest';
			}
			elsif ($code == 80877103) {
				$pg_msg->{'type'} = 'SSLRequest';
			}
			elsif ($code == 196608) {
				# we ignore the $code here as we try to support both pgsql protos v2 and v3.
				$pg_msg->{'type'} = 'StartupMessage3';
				# my $min = $code%65536; # == 0
				# my $maj = $code/65536; # == 3
			}
			elsif ($code == 131072) {
				# we ignore the $code here as we try to support both pgsql protos v2 and v3.
				$pg_msg->{'type'} = 'StartupMessage2';
				# my $min = $code%65536; # == 0
				# my $maj = $code/65536; # == 2
			}
			else {
				if (get_debug_lvl()) {
					$self->{'sessions'}->{$sess_hash}->{'data'} =~ tr/\x00-\x1F\x7F-\xFF/./;
					debug(1, "WARNING: dropped alien packet I was unable to mess with at timestamp %s:\n'%s'\n",
						$pg_msg->{'timestamp'}, $self->{'sessions'}->{$sess_hash}->{'data'}
					);
				}
				$self->{'sessions'}->{$sess_hash}->{'data'} = '';
				return;
			}

			# these special messages don't have type byte, only the message length on 4 bytes.
			$pg_msg->{'data'} = substr($self->{'sessions'}->{$sess_hash}->{'data'}, 4, $msg_len - 4);
		}
		else {
			debug(2, "NOTICE: looks like we have either an incomplette header or some junk in the buffer (data available: %d)...waiting for more bits.\n", $data_len);
			return ;
		}

		debug(3, "PGSQL: pckt=%d, timestamp=%s, session=%s type=%s, len=%d, data_len=%d \n",
			$self->{'pckt_count'}, $pg_msg->{'timestamp'}, $sess_hash, $pg_msg->{'type'}, $msg_len, $data_len
		);

		# message: B(R) "Authentication*"
		if ($from_backend and $pg_msg->{'type'} eq 'R') {
			$pg_msg->{'code'} = unpack('N', $pg_msg->{'data'});

			# AuthenticationOk
			if ($pg_msg->{'code'} == 0) {
				$self->{'AuthenticationOk'}->($pg_msg) if defined $self->{'AuthenticationOk'};
			}
			# AuthenticationKerberosV5
			elsif ($pg_msg->{'code'} == 2) {
				$self->{'AuthenticationKerberosV5'}->($pg_msg) if defined $self->{'AuthenticationKerberosV5'};
			}
			# AuthenticationCleartextPassword
			elsif ($pg_msg->{'code'} == 3) {
				$self->{'AuthenticationCleartextPassword'}->($pg_msg) if defined $self->{'AuthenticationCleartextPassword'};
			}
			# AuthenticationMD5Password
			elsif ($pg_msg->{'code'} == 5) {
				$pg_msg->{'salt'} = substr($pg_msg->{'data'}, 4);
				$self->{'AuthenticationMD5Password'}->($pg_msg) if defined $self->{'AuthenticationMD5Password'};
			}
			# AuthenticationSCMCredential
			elsif ($pg_msg->{'code'} == 6) {
				$self->{'AuthenticationSCMCredential'}->($pg_msg) if defined $self->{'AuthenticationSCMCredential'};
			}
			# AuthenticationGSS
			elsif ($pg_msg->{'code'} == 7) {
				$self->{'AuthenticationGSS'}->($pg_msg) if defined $self->{'AuthenticationGSS'};
			}
			# AuthenticationSSPI
			elsif ($pg_msg->{'code'} == 9) {
				$self->{'AuthenticationSSPI'}->($pg_msg) if defined $self->{'AuthenticationSSPI'};
			}
			# GSSAPI or SSPI authentication data
			elsif ($pg_msg->{'code'} == 8) {
				$pg_msg->{'auth_data'} = substr($pg_msg->{'data'}, 4);
				$self->{'AuthenticationKerberosV5'}->($pg_msg) if defined $self->{'AuthenticationKerberosV5'};
			}

			# FIXME Add a catch all ?
		}

		# message: B(K) "BackendKeyData"
		elsif ($from_backend and $pg_msg->{'type'} eq 'K') {
			($pg_msg->{'pid'}, $pg_msg->{'key'}) = unpack('NN', $pg_msg->{'data'});

			$self->{'BackendKeyData'}->($pg_msg) if defined $self->{'BackendKeyData'};
		}

		# message: F(B) "Bind"
		#   portal=String
		#   name=String
		#   num_formats=int16
		#   formats[]=int16[nb_formats]
		#   num_params=int16
		#   params[]=(len=int32,value=char[len])[nb_params]
		elsif (not $from_backend and $pg_msg->{'type'} eq 'B') {
			my @params_formats;
			my @params;
			my $msg = $pg_msg->{'data'};

			($pg_msg->{'portal'}, $pg_msg->{'name'}, $pg_msg->{'num_formats'}) = unpack('Z*Z*n', $msg);

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
					push @params, substr($msg, 4, $len);
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
		}

		# message: B(2) "BindComplete"
		elsif ($from_backend and $pg_msg->{'type'} eq '2') {
			$self->{'BindComplete'}->($pg_msg) if defined $self->{'BindComplete'};
		}

		# message: CancelRequest (F)
		#   status=Char
		elsif (not $from_backend and $pg_msg->{'type'} eq 'CancelRequest') {
			($pg_msg->{'pid'}, $pg_msg->{'key'}) = unpack('xxxxNN', $pg_msg->{'data'});
			$self->{'CancelRequest'}->($pg_msg) if defined $self->{'CancelRequest'};
		}

		# message: F(C) "Close"
		#   type=char
		#   name=String
		elsif (not $from_backend and $pg_msg->{'type'} eq 'C') {

			($pg_msg->{'type'}, $pg_msg->{'name'}) = unpack('AZ*', $pg_msg->{'data'});

			$self->{'Close'}->($pg_msg) if defined $self->{'Close'};
		}

		# message: B(3) "CloseComplete"
		elsif ($from_backend and $pg_msg->{'type'} eq '3') {

			$self->{'CloseComplete'}->($pg_msg) if defined $self->{'CloseComplete'};
		}

		# message: B(C) "CommandComplete"
		#   type=char
		#   name=String
		elsif ($from_backend and $pg_msg->{'type'} eq 'C') {

			$pg_msg->{'command'} = substr($pg_msg->{'data'}, 0, -1);

			$self->{'CommandComplete'}->($pg_msg) if defined $self->{'CommandComplete'};
		}

		# message: B(d) or F(d) "CopyData"
		#   data=Byte[n]
		elsif ($pg_msg->{'type'} eq 'd') {
			my @fields;

			$self->{'CopyData'}->($pg_msg, $from_backend) if defined $self->{'CopyData'};
		}

		# message: B(c) or F(c) "CopyDone"
		#   data=Byte[n]
		elsif ($pg_msg->{'type'} eq 'c') {
			my @fields;

			$self->{'CopyDone'}->($pg_msg, $from_backend) if defined $self->{'CopyDone'};
		}

		# message: F(f) "CopyFail"
		#   error=String
		elsif (not $from_backend and $pg_msg->{'type'} eq 'f') {
			($pg_msg->{'error'}) = unpack('Z*', $pg_msg->{'data'});

			$self->{'CopyFail'}->($pg_msg) if defined $self->{'CopyFail'};
		}

		# message: B(G) "CopyInResponse"
		#   copy_format=int8
		#   num_fields=int16
		#   fields_formats[]=int16[num_fields]
		elsif ($from_backend and $pg_msg->{'type'} eq 'G') {
			my @fields_formats;

			($pg_msg->{'copy_format'}, $pg_msg->{'num_fields'}, @fields_formats)
				= unpack('Cnn*', $pg_msg->{'data'});
			$pg_msg->{'fields_formats'} = [@fields_formats];

			$self->{'CopyInResponse'}->($pg_msg) if defined $self->{'CopyInResponse'};
		}

		# message: B(H) "CopyOutResponse"
		#   copy_format=int8
		#   num_fields=int16
		#   fields_formats[]=int16[num_fields]
		elsif ($from_backend and $pg_msg->{'type'} eq 'H') {
			my @fields_formats;

			($pg_msg->{'copy_format'}, $pg_msg->{'num_fields'}, @fields_formats)
				= unpack('Cnn*', $pg_msg->{'data'});
			$pg_msg->{'fields_formats'} = [@fields_formats];

			$self->{'CopyOutResponse'}->($pg_msg) if defined $self->{'CopyOutResponse'};
		}

		# message: B(D) "DataRow"
		#   num_values=int16
		#   (
		#   value_len=int32
		#   value=Byte[value_len] (TODO give the format given in previous message B(T) ?)
		#   )[num_values]
		elsif ($from_backend and $pg_msg->{'type'} eq 'D') {
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
		}

		# message: F(D) "Describe"
		#   type=char
		#   name=String
		elsif (not $from_backend and $pg_msg->{'type'} eq 'D') {

			($pg_msg->{'type'}, $pg_msg->{'name'}) = unpack('AZ*', $pg_msg->{'data'});

			$self->{'Describe'}->($pg_msg) if defined $self->{'Describe'};
		}

		# message: B(I) "EmptyQueryResponse"
		elsif ($from_backend and $pg_msg->{'type'} eq 'I') {

			$self->{'EmptyQueryResponse'}->($pg_msg) if defined $self->{'EmptyQueryResponse'};
		}

		# message: B(E) "ErrorResponse"
		#   (code=char
		#   value=String){1,}\x00
		elsif ($from_backend and $pg_msg->{'type'} eq 'E') {
			my $fields = {};
			my $msg = $pg_msg->{'data'};

			while ($msg ne '') {
				my ($code, $value) = unpack('AZ*', $msg);
				last if ($code eq '');
				$fields->{$code} = $value;
				$msg = substr($msg, 2 + length($value));
			}

			$pg_msg->{'fields'} = $fields;

			$self->{'ErrorResponse'}->($pg_msg);
		}

		# message: F(E) "Execute"
		#   name=String
		#   nb_rows=int32
		elsif (not $from_backend and $pg_msg->{'type'} eq 'E') {
			($pg_msg->{'name'}, $pg_msg->{'nb_rows'}) = unpack('Z*N', $pg_msg->{'data'});

			$self->{'Execute'}->($pg_msg) if defined $self->{'Execute'};
		}

		# message: F(H) "Flush"
		elsif (not $from_backend and $pg_msg->{'type'} eq 'H') {

			$self->{'Flush'}->($pg_msg) if defined $self->{'Flush'};
		}

		# message: F(F) "FunctionCall"
		#   func_oid=Int32
		#   num_args_formats=Int16
		#   args_formats[]=int16[nb_formats]
		#   num_args=Int16
		#   args[]=(len=int32,value=Byte[len])[nb_args]
		#   result_format=Int16
		# TODO: NOT TESTED yet
		elsif (not $from_backend and $pg_msg->{'type'} eq 'F') {
			my @args_formats;
			my @args;
			my $msg = $pg_msg->{'data'};

			($pg_msg->{'func_oid'}, $pg_msg->{'num_args_formats'}) = unpack('NN', $msg);

			$msg = substr($msg, 8);

			# catch formats and the $num_args as well
			@args_formats = unpack("n$pg_msg->{'num_args_formats'} n", $msg);
			$pg_msg->{'num_args'} = pop @args_formats;
			$pg_msg->{'args_formats'} = [@args_formats];

			$msg = substr($msg, ($pg_msg->{'num_args_formats'}+1) * 2);

			for (my $i=0; $i < $pg_msg->{'num_args'}; $i++) {
				# unpack hasn't 32bit signed network template, so we use l>
				my ($len) = unpack('l>', $msg);

				# if len < 0; the value is NULL
				if ($len > 0) {
					push @args, substr($msg, 4, $len);
					$msg = substr($msg, 4 + $len);
				}
				elsif ($len == 0) {
					push @args, '';
					$msg = substr($msg, 4);
				}
				else { # value is NULL
					push @args, undef;
					$msg = substr($msg, 4);
				}
			}

			$pg_msg->{'params'} = [@args];

			$pg_msg->{'result_format'} = unpack('n', $msg);

			$self->{'FunctionCall'}->($pg_msg) if defined $self->{'FunctionCall'};
		}

		# message: B(V) "FunctionCallResponse"
		#   len=Int32
		#   value=Byte[len]
		# TODO: NOT TESTED yet
		elsif ($from_backend and $pg_msg->{'type'} eq 'V') {
			($pg_msg->{'len'}) = unpack('l>', $pg_msg->{'data'});

			# if len < 0; the value is NULL
			if ($pg_msg->{'len'} > 0) {
				$pg_msg->{'value'} = substr($pg_msg->{'data'}, 4, $pg_msg->{'len'});
			}
			elsif ($pg_msg->{'len'} == 0) {
				$pg_msg->{'value'} = '';
			}
			else { # value is NULL
				$pg_msg->{'value'} = undef;
			}

			$self->{'FunctionCallResponse'}->($pg_msg) if defined $self->{'FunctionCallResponse'};
		}

		# message: B(n) "NoData"
		elsif ($from_backend and $pg_msg->{'type'} eq 'n') {
			$self->{'NoData'}->($pg_msg) if defined $self->{'NoData'};
		}

		# message: B(N) "NoticeResponse"
		#   (code=char
		#   value=String){1,}\x00
		elsif ($from_backend and $pg_msg->{'type'} eq 'N') {
			my $fields = {};
			my $msg = $pg_msg->{'data'};

			while ($msg ne '') {
				my ($code, $value) = unpack('AZ*', $msg);
				last if ($code eq '');
				$fields->{$code} = $value;
				$msg = substr($msg, 2 + length($value));
			}

			$pg_msg->{'fields'} = $fields;

			$self->{'NoticeResponse'}->($pg_msg) if defined $self->{'NoticeResponse'};
		}

		# message: B(A) "NotificationResponse"
		#   pid=int32
		#   channel=String
		#   payload=String
		elsif ($from_backend and $pg_msg->{'type'} eq 'A') {
			($pg_msg->{'pid'}, $pg_msg->{'channel'}, $pg_msg->{'payload'}) = unpack('N Z* Z*', $pg_msg->{'data'});
			$self->{'NotificationResponse'}->($pg_msg) if defined $self->{'NotificationResponse'};
		}

		# message: B(t) "ParameterDescription"
		#   num_params=int16
		#   params_types[]=int32[nb_formats]
		elsif ($from_backend and $pg_msg->{'type'} eq 't') {
			my @params_types;
			($pg_msg->{'num_params'}, @params_types) = unpack('nN*', $pg_msg->{'data'});
			$pg_msg->{'params_types'} = [@params_types];
			$self->{'ParameterDescription'}->($pg_msg) if defined $self->{'ParameterDescription'};
		}

		# message: B(S) "ParameterStatus"
		#   name=String
		#   value=String
		elsif ($from_backend and $pg_msg->{'type'} eq 'S') {
			($pg_msg->{'name'}, $pg_msg->{'value'}) = unpack('Z*Z*', $pg_msg->{'data'});
			$self->{'ParameterStatus'}->($pg_msg) if defined $self->{'ParameterStatus'};
		}

		# message: F(P) "Parse"
		#   name=String
		#   query=String
		#   num_params=int16
		#   params_types[]=int32[nb_formats]
		elsif (not $from_backend and $pg_msg->{'type'} eq 'P') {
			my @params_types;
			($pg_msg->{'name'}, $pg_msg->{'query'},
				$pg_msg->{'num_params'}, @params_types
			) = unpack('Z*Z*nN*', $pg_msg->{'data'});
			$pg_msg->{'params_types'} = [@params_types];

			$self->{'Parse'}->($pg_msg) if defined $self->{'Parse'};
		}

		# message: B(1) "ParseComplete"
		elsif ($from_backend and $pg_msg->{'type'} eq '1') {
			$self->{'ParseComplete'}->($pg_msg) if defined $self->{'ParseComplete'};
		}

		# message: F(p) "PasswordMessage"
		#    password=String
		elsif (not $from_backend and $pg_msg->{'type'} eq 'p') {

			# we remove the last char:
			# query are null terminated in pgsql proto
			$pg_msg->{'password'} = substr($pg_msg->{'data'}, 0, -1);

			$self->{'PasswordMessage'}->($pg_msg) if defined $self->{'PasswordMessage'};
		}

		# message: B(s) "PortalSuspended"
		elsif ($from_backend and $pg_msg->{'type'} eq 's') {
			$self->{'PortalSuspended'}->($pg_msg) if defined $self->{'PortalSuspended'};
		}

		# message: F(Q) "Query"
		#    query=String
		elsif (not $from_backend and $pg_msg->{'type'} eq 'Q') {

			# we remove the last char:
			# query are null terminated
			$pg_msg->{'query'} = substr($pg_msg->{'data'}, 0, -1);

			$self->{'Query'}->($pg_msg) if defined $self->{'Query'};
		}

		# message: B(Z) "ReadyForQuery"
		#   status=Char
		elsif ($from_backend and $pg_msg->{'type'} eq 'Z') {
			$pg_msg->{'status'} = $pg_msg->{'data'};
			$self->{'ReadyForQuery'}->($pg_msg) if defined $self->{'ReadyForQuery'};
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
		elsif ($from_backend and $pg_msg->{'type'} eq 'T') {
			my @fields;
			my $i=0;
			my $msg = $pg_msg->{'data'};

			$pg_msg->{'num_fields'} = unpack('n', $msg);

			while ($i < $pg_msg->{'num_fields'}) {
				my @field = unpack('Z*NnNnNn', $msg);
				push @fields, [ @field ];
				$msg = substr($msg, 19 + length($field[0]));

				$i++;
			}

			$pg_msg->{'fields'} = [ @fields ];
			$self->{'RowDescription'}->($pg_msg) if defined $self->{'RowDescription'};
		}

		# message: SSLAnswer (B)
		elsif ($from_backend and $pg_msg->{'type'} eq 'SSLAnswer') {
			$pg_msg->{'ssl_answer'} = $pg_msg->{'data'};
			$self->{'SSLAnswer'}->($pg_msg) if defined $self->{'SSLAnswer'};
		}

		# message: SSLRequest (F)
		#   status=Char
		elsif (not $from_backend and $pg_msg->{'type'} eq 'SSLRequest') {
			$self->{'SSLRequest'}->($pg_msg) if defined $self->{'SSLRequest'};
		}

		# message: StartupMessage2 (F)
		#   status=Char
		elsif (not $from_backend and $pg_msg->{'type'} eq 'StartupMessage2') {
			$pg_msg->{'version'} = 2;

			# TODO add given parameters from frontend

			$self->{'StartupMessage'}->($pg_msg) if defined $self->{'StartupMessage'};
		}

		# message: StartupMessage3 (F)
		#   status=Char
		#   (param=String
		#   value=String){1,}\x00
		elsif (not $from_backend and $pg_msg->{'type'} eq 'StartupMessage3') {
			my $msg = substr($pg_msg->{'data'}, 4); # ignore the version fields
			my $params = {};

			$pg_msg->{'version'} = 3;

			while ($msg ne '') {
				my ($param, $value) = unpack('Z*Z*', $msg);
				last if ($param eq '');
				$params->{$param} = $value;
				$msg = substr($msg, 2 + length($param) + length($value));
			}

			$pg_msg->{'params'} = $params;

			$self->{'StartupMessage'}->($pg_msg) if defined $self->{'StartupMessage'};
		}

		# message: F(S) "Sync"
		elsif (not $from_backend and $pg_msg->{'type'} eq 'S') {
			$self->{'Sync'}->($pg_msg) if defined $self->{'Sync'};
		}

		# message: F(X) "Terminate"
		elsif (not $from_backend and $pg_msg->{'type'} eq 'X') {
			$self->{'Terminate'}->($pg_msg) if defined $self->{'Terminate'};
		}

		# Default catchall
		else {
			debug(3, "PGSQL: not implemented message type: %s(%s)\n", ($from_backend?'B':'F'), $pg_msg->{'type'});
		}

		### end of processing, remove processed data
		$self->{'sessions'}->{$sess_hash}->{'data'} = substr($self->{'sessions'}->{$sess_hash}->{'data'}, $msg_len);
		$data_len -= $msg_len;

		# if the message was Terminate, destroy the session
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
