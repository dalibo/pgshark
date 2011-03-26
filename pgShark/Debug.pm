##
# This program is open source, licensed under the simplified BSD license.  For license terms, see the LICENSE file.
##
package Debug;

use strict;
use warnings;
use pgShark::Utils;
use Net::Pcap qw(:functions);

## TODO
#  * ...

sub new {
	my $class = shift;
	my $args = shift;
	my $pcap = shift;

	my $self = {
	};

	my $filter = undef;

	pcap_compile($pcap, \$filter,
		"(tcp and port $args->{'port'}) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)", 0, 0
	);
	pcap_setfilter($pcap, $filter);

	debug(1, "Debug: Plugin loaded.\n");

	return bless($self, $class);
}

# prints formated trace with mandatored fields
sub header {
	my $self = shift;
	my $pg_msg = shift;
	my $is_srv = shift;
	printf "Packet: t=%s, session=%s\n", $pg_msg->{'timestamp'}, $pg_msg->{'sess_hash'};
	printf "PGSQL: type=%s, ", $pg_msg->{'type'};
	if ($is_srv) {
		printf "B -> F\n";
	}
	else {
		printf "F -> B\n";
	}
}

sub code_response {
	my $self = shift;
	my $pg_msg = shift;

	while (@{ $pg_msg->{'fields'} } > 0) {
		my ($code, $value) = splice(@{ $pg_msg->{'fields'} }, 0, 2);
		SWITCH: {
			#S C M D H P p q W F L R
			if ($code eq 'S') {
				printf "Severity: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'C') {
				printf "Code: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'M') {
				printf "Message: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'D') {
				printf "Detail: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'H') {
				printf "Hint: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'P') {
				printf "Position: '%s'n", $value;
				last SWITCH;
			}
			if ($code eq 'p') {
				printf "Internal position: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'q') {
				printf "Internal query: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'W') {
				printf "Where: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'F') {
				printf "File: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'L') {
				printf "Line: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'R') {
				printf "Routine: '%s'\n", $value;
				last SWITCH;
			}
		}
	}
}

## handle F(P) command (parse)
# @param $pg_msg hash with pg message properties
sub process_parse {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 0);

	printf "PARSE name='%s', num_params=%d, params_type=%s, query=%s\n\n",
		$pg_msg->{'name'}, $pg_msg->{'num_params'}, join(',', @{ $pg_msg->{'params_types'} }), $pg_msg->{'query'};
}

## handle command F(B) (bind)
# @param $pg_msg hash with pg message properties
sub process_bind {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 0);

	map {$_='NULL' if not defined} @{ $pg_msg->{'params'} };

	printf "BIND portal='%s', name='%s', num_formats=%d, formats=%s, num_params=%d, params=%s\n\n",
		$pg_msg->{'portal'}, $pg_msg->{'name'}, $pg_msg->{'num_formats'}, join(',', @{ $pg_msg->{'params_types'} }),
		$pg_msg->{'num_params'}, join(',', @{ $pg_msg->{'params'} });
}

## handle command F(D) (Describe)
# @param $pg_msg hash with pg message properties
sub process_describe {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 0);

	printf "DESCRIBE type='%s', name='%s'\n\n", $pg_msg->{'type'}, $pg_msg->{'name'};
}
## handle command F(E) (execute)
# @param $pg_msg hash with pg message properties
sub process_execute {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 0);

	printf "EXECUTE name='%s', nb_rows=%d\n\n", $pg_msg->{'name'}, $pg_msg->{'nb_rows'};
}

## handle command F(C) (close)
# @param $pg_msg hash with pg message properties
sub process_close {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 0);

	printf "CLOSE type='%s', name='%s'\n\n", $pg_msg->{'type'}, $pg_msg->{'name'};
}

## handle command F(Q) (query)
# @param $pg_msg hash with pg message properties
sub process_query {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 0);

	printf "QUERY query=%s\n\n", $pg_msg->{'query'};
}

## handle command F(X) (terminate)
# @param $pg_msg hash with pg message properties
sub process_disconnect {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 0);

	printf "DISCONNECT\n\n";
}

## handle command F(S) (sync)
# @param $pg_msg hash with pg message properties
sub process_sync {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 0);

	printf "SYNC\n\n";
}

## handle command B(1) (Parse Complete)
# @param $pg_msg hash with pg message properties
sub process_parse_complete {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 1);

	printf "PARSE COMPLETE\n\n";
}

## handle command B(2) (Bind Complete)
# @param $pg_msg hash with pg message properties
sub process_bind_complete {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 1);

	printf "BIND COMPLETE\n\n";
}

## handle command B(A) (Notification Response)
# @param $pg_msg hash with pg message properties
sub process_notif_response {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 1);

	printf "NOTIFICATION RESPONSE pid=%d, channel='%s', payload='%s'\n\n",
		$pg_msg->{'pid'}, $pg_msg->{'channel'}, $pg_msg->{'payload'},;
}

## handle command B(C) (command complete)
# @param $pg_msg hash with pg message properties
sub process_command_complete {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 1);

	printf "COMMAND COMPLETE command='%s'\n\n", $pg_msg->{'command'};
}

## handle command B(D) (data row)
# @param $pg_msg hash with pg message properties
sub process_data_row {
	my $self = shift;
	my $pg_msg = shift;
	my $i = 0;
	$self->header($pg_msg, 1);

	printf "DATA ROW num_values=%d\n", $pg_msg->{'num_values'};

	for my $value ( @{ $pg_msg->{'values'} } ) {
		$i++;
		if (defined $value->[1]) {
			$value->[1] =~ tr/\x00-\x1F\x80-\xFF/./;
			$value->[1] = "'$value->[1]'";
		}
		else {
			$value->[1] = 'NULL';
		}
		printf "---[Value %02d]---\nlength=%d\nvalue=%s\n", $i, @{ $value } ;
	}
	print "\n";
}

## handle command B(E) (error response)
# @param $pg_msg hash with pg message properties
sub process_error_response {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 1);

	printf "ERROR RESPONSE\n\n";
	$self->code_response($pg_msg);

	print "\n";
}

## handle command B(I) (empty query response)
# @param $pg_msg hash with pg message properties
sub process_empty_query {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 1);

	printf "EMPTY QUERY RESPONSE\n\n";
}

## handle command B(K) (BackendKeyData)
# @param $pg_msg hash with pg message properties
sub process_key_data {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 1);

	printf "BACKEND KEY DATA pid=%d, key=%d\n\n", $pg_msg->{'pid'}, $pg_msg->{'key'};
}

## handle command B(n) (no data)
# @param $pg_msg hash with pg message properties
sub process_no_data {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 1);

	printf "NO DATA\n\n";
}

## handle command B(N) (notice response)
# @param $pg_msg hash with pg message properties
sub process_notice_response {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 1);

	printf "NOTICE RESPONSE\n\n";
	$self->code_response($pg_msg);

	print "\n";
}

## handle command B(R) (authentification request)
# @param $pg_msg hash with pg message properties
sub process_auth_request {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 1);

	printf "AUTHENTIFICATION REQUEST code=%d ", $pg_msg->{'code'};

	SWITCH: {
		if ($pg_msg->{'code'} == 0) {
			printf "(SUCCESS)\n\n";
			last SWITCH;
		}
		if ($pg_msg->{'code'} == 2) {
			printf "(Kerberos V5)\n\n";
			last SWITCH;
		}
		if ($pg_msg->{'code'} == 3) {
			printf "(clear-text password)\n\n";
			last SWITCH;
		}
		if ($pg_msg->{'code'} == 5) {
			printf "(MD5 salt='%s')\n\n", $pg_msg->{'data'};
			last SWITCH;
		}
		if ($pg_msg->{'code'} == 6) {
			printf "(SCM)\n\n";
			last SWITCH;
		}
		if ($pg_msg->{'code'} == 7) {
			printf "(GSSAPI)\n\n";
			last SWITCH;
		}
		if ($pg_msg->{'code'} == 9) {
			printf "(SSPI)\n\n";
			last SWITCH;
		}
		if ($pg_msg->{'code'} == 8) {
			printf "(contains GSSAPI or SSPI data)\n\n";
			last SWITCH;
		}
	}
}

## handle command B(s) (portal suspended)
# @param $pg_msg hash with pg message properties
sub process_portal_suspended {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 1);

	printf "PORTAL SUSPENDED\n\n";
}

## handle command B(T) (row description)
# @param $pg_msg hash with pg message properties
sub process_row_desc {
	my $self = shift;
	my $pg_msg = shift;
	my $i=0;
	$self->header($pg_msg, 1);

	printf "ROW DESCRIPTION: num_fields=%d\n",
		$pg_msg->{'num_fields'};

	for my $field ( @{ $pg_msg->{'fields'} } ) {
		$i++;
		printf "---[Field %02d]---\nname='%s'\nrelid=%d\nattnum=%d\ntype=%d\ntype_len=%d\ntype_mod=%d\nformat=%d\n", $i, @{ $field };
	}
	print "\n";
}

## handle command B(t) (parameter description)
# @param $pg_msg hash with pg message properties
sub process_param_desc {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 1);

	printf "PARAMETER DESCRIPTION: num_param=%d, params_oids=%s\n\n",
		$pg_msg->{'num_params'}, join(',', @{ $pg_msg->{'params_types'} });
}

## handle command B(Z) (ready for query)
# @param $pg_msg hash with pg message properties
sub process_ready {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 1);

	if ($pg_msg->{'status'} eq 'I') {
		printf "READY FOR QUERY type=<IDLE>\n\n";
	}
	elsif ($pg_msg->{'status'} eq 'T') {
		printf "READY FOR QUERY type=<IDLE> in transaction\n\n";
	}
	elsif ($pg_msg->{'status'} eq 'E') {
		printf "READY FOR QUERY type=<IDLE> in transaction (aborted)\n\n";
	}
}

## handle command CancelRequest (F)
# @param $pg_msg hash with pg message properties
sub process_cancel_request {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 0);

	printf "CANCEL REQUEST\n\n";
}

## handle command SSLRequest (F)
# @param $pg_msg hash with pg message properties
sub process_ssl_request {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 0);

	printf "SSL REQUEST\n\n";
}

## handle command StartupMessage (F)
# @param $pg_msg hash with pg message properties
sub process_startup_message {
	my $self = shift;
	my $pg_msg = shift;
	$self->header($pg_msg, 0);

	printf "STARTUP MESSAGE version: %s\n\n", $pg_msg->{'version'};
}

## this one doesn't exists as a backend answer
# but pgshark call this method when backend answers to SSLRequest
sub process_ssl_answer {
	my $self = shift;
	my $pg_msg = shift;

	$self->header($pg_msg, 0);

	printf "SSL BACKEND ANSWER: %s\n\n", $pg_msg->{'ssl_answer'};
}


sub DESTROY {
	my $self = shift;
#	debug(1, "Xxx: output something usefull here ?\n");
}

1;
