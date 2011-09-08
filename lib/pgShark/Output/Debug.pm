##
# This program is open source, licensed under the simplified BSD license.  For license terms, see the LICENSE file.
##
package pgShark::Output::Debug;

use strict;
use warnings;
use pgShark::Utils;
use Net::Pcap qw(:functions);
use Data::Dumper;


use Exporter;
our $VERSION = 0.1;
our @ISA = ('Exporter');
our @EXPORT = qw/getCallbacks getFilter Authentication BackendKeyData Bind BindComplete CancelRequest Close CloseComplete CommandComplete CopyData CopyDone
CopyFail CopyInResponse CopyOutResponse DataRow Describe EmptyQueryResponse ErrorResponse Execute Flush NoData NoticeResponse
NotificationResponse ParameterDescription ParameterStatus Parse ParseComplete PasswordMessage PortalSuspended Query ReadyForQuery
RowDescription SSLAnswer SSLRequest StartupMessage Sync Terminate/;
our @EXPORT_OK = qw/getCallbacks getFilter Authentication BackendKeyData Bind BindComplete CancelRequest Close CloseComplete CommandComplete CopyData CopyDone
CopyFail CopyInResponse CopyOutResponse DataRow Describe EmptyQueryResponse ErrorResponse Execute Flush NoData NoticeResponse
NotificationResponse ParameterDescription ParameterStatus Parse ParseComplete PasswordMessage PortalSuspended Query ReadyForQuery
RowDescription SSLAnswer SSLRequest StartupMessage Sync Terminate/;

## TODO
# ...

my $from_backend = 1;

sub getCallbacks {
	return {
		'AuthenticationOk' => \&Authentication,
		'AuthenticationKerberosV5' => \&Authentication,
		'AuthenticationCleartextPassword' => \&Authentication,
		'AuthenticationMD5Password' => \&Authentication,
		'AuthenticationSCMCredential' => \&Authentication,
		'AuthenticationGSS' => \&Authentication,
		'AuthenticationSSPI' => \&Authentication,
		'AuthenticationGSSContinue' => \&Authentication,
		'BackendKeyData' => \&BackendKeyData,
		'Bind' => \&Bind,
		'BindComplete' => \&BindComplete,
		'CancelRequest' => \&CancelRequest,
		'Close' => \&Close,
		'CloseComplete' => \&CloseComplete,
		'CommandComplete' => \&CommandComplete,
		'CopyData' => \&CopyData,
		'CopyDone' => \&CopyDone,
		'CopyFail' => \&CopyFail,
		'CopyInResponse' => \&CopyInResponse,
		'CopyOutResponse' => \&CopyOutResponse,
		'DataRow' => \&DataRow,
		'Describe' => \&Describe,
		'EmptyQueryResponse' => \&EmptyQueryResponse,
		'ErrorResponse' => \&ErrorResponse,
		'Execute' => \&Execute,
		'Flush' => \&Flush,
		'FunctionCall' => sub {},
		'FunctionCallResponse' => sub {},
		'NoData' => \&NoData,
		'NoticeResponse' => \&NoticeResponse,
		'NotificationResponse' => \&NotificationResponse,
		'ParameterDescription' => \&ParameterDescription,
		'ParameterStatus' => \&ParameterStatus,
		'Parse' => \&Parse,
		'ParseComplete' => \&ParseComplete,
		'PasswordMessage' => \&PasswordMessage,
		'PortalSuspended' => \&PortalSuspended,
		'Query' => \&Query,
		'ReadyForQuery' => \&ReadyForQuery,
		'RowDescription' => \&RowDescription,
		'SSLAnswer' => \&SSLAnswer,
		'SSLRequest' => \&SSLRequest,
		'StartupMessage' => \&StartupMessage,
		'Sync' => \&Sync,
		'Terminate' => \&Terminate
	};
}

sub getFilter {
	my $host = shift;
	my $port = shift;
	return "(tcp and port $port) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
}

# prints formated trace with mandatored fields
sub header {
	my $pg_msg = shift;
	my $from_backend = shift;

	printf "Packet: t=%s, session=%s\n", $pg_msg->{'timestamp'}, $pg_msg->{'sess_hash'};
	printf "PGSQL: type=%s, ", $pg_msg->{'type'};
	if ($from_backend) {
		printf "B -> F\n";
	}
	else {
		printf "F -> B\n";
	}
}

sub code_response {
	my $pg_msg = shift;

	foreach my $code (keys %{ $pg_msg->{'fields'} }) {
		my $value = $pg_msg->{'fields'}->{$code};
		SWITCH: {
			#S C M D H P p q W F L R
			if ($code eq 'S') {
				printf "  Severity: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'C') {
				printf "  Code: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'M') {
				printf "  Message: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'D') {
				printf "  Detail: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'H') {
				printf "  Hint: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'P') {
				printf "  Position: '%s'n", $value;
				last SWITCH;
			}
			if ($code eq 'p') {
				printf "  Internal position: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'q') {
				printf "  Internal query: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'W') {
				printf "  Where: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'F') {
				printf "  File: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'L') {
				printf "  Line: '%s'\n", $value;
				last SWITCH;
			}
			if ($code eq 'R') {
				printf "  Routine: '%s'\n", $value;
				last SWITCH;
			}
		}
	}
}

## handle command B(R)
# @param $pg_msg hash with pg message properties
sub Authentication {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

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
			printf "(MD5 salt='%s')\n\n", unpack('h*', $pg_msg->{'salt'});
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

## handle command B(K)
# @param $pg_msg hash with pg message properties
sub BackendKeyData {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "BACKEND KEY DATA pid=%d, key=%d\n\n", $pg_msg->{'pid'}, $pg_msg->{'key'};
}

## handle command F(B)
# @param $pg_msg hash with pg message properties
sub Bind {
	my $pg_msg = shift;
	header($pg_msg, not $from_backend);

	map {$_='NULL' if not defined} @{ $pg_msg->{'params'} };

	printf "BIND portal='%s', name='%s', num_formats=%d, formats=%s, num_params=%d, params=%s\n\n",
		$pg_msg->{'portal'}, $pg_msg->{'name'}, $pg_msg->{'num_formats'}, join(', ', @{ $pg_msg->{'params_types'} }),
		$pg_msg->{'num_params'}, join(', ', @{ $pg_msg->{'params'} });
}

## handle command B(2)
# @param $pg_msg hash with pg message properties
sub BindComplete {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "BIND COMPLETE\n\n";
}

## handle command CancelRequest (F)
# @param $pg_msg hash with pg message properties
sub CancelRequest {
	my $pg_msg = shift;
	header($pg_msg, not $from_backend);

	printf "CANCEL REQUEST pid=%s, key=%s\n\n", $pg_msg->{'pid'}, $pg_msg->{'key'};
}

## handle command F(C)
# @param $pg_msg hash with pg message properties
sub Close {
	my $pg_msg = shift;
	header($pg_msg, not $from_backend);

	printf "CLOSE kind='%s', name='%s'\n\n", $pg_msg->{'kind'}, $pg_msg->{'name'};
}

## handle command B(3)
# @param $pg_msg hash with pg message properties
sub CloseComplete {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "CLOSE COMPLETE\n\n";
}

## handle command B(C)
# @param $pg_msg hash with pg message properties
sub CommandComplete {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "COMMAND COMPLETE command='%s'\n\n", $pg_msg->{'command'};
}

## handle commande B & F (d)
# @param $pg_msg hash with pg message properties
# @param $from_backend (boolean) wether the message comes from the backend or not
sub CopyData {
	my $pg_msg = shift;

	header($pg_msg, $pg_msg->{'from_backend'});

	printf "COPY DATA len=%d\n\n", length($pg_msg->{'row'});
}

## handle commande B & F (c)
# @param $pg_msg hash with pg message properties
# @param $from_backend (boolean) wether the message comes from the backend or not
sub CopyDone {
	my $pg_msg = shift;

	header($pg_msg, $pg_msg->{'from_backend'});

	printf "COPY DONE\n\n";
}

## handle command F(f)
# @param $pg_msg hash with pg message properties
sub CopyFail {
	my $pg_msg = shift;
	header($pg_msg, not $from_backend);

	printf "COPY FAIL error='%s'\n\n", $pg_msg->{'error'};
}

## handle command B(G)
# @param $pg_msg hash with pg message properties
sub CopyInResponse {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "COPY IN RESPONSE copy format=%d, num_fields=%d, fields_formats=%s\n\n", $pg_msg->{'copy_format'}, $pg_msg->{'num_fields'},
		join(', ', @{ $pg_msg->{'fields_formats'} });
}

## handle command B(H)
# @param $pg_msg hash with pg message properties
sub CopyOutResponse {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "COPY OUT RESPONSE copy format=%d, num_fields=%d, fields_formats=%s\n\n", $pg_msg->{'copy_format'}, $pg_msg->{'num_fields'},
		join(', ', @{ $pg_msg->{'fields_formats'} });
}

## handle command B(D)
# @param $pg_msg hash with pg message properties
sub DataRow {
	my $pg_msg = shift;
	my $i = 0;
	header($pg_msg, $from_backend);

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
		printf "  ---[Value %02d]---\n  length=%d\n  value=%s\n", $i, @{ $value } ;
	}
	print "\n";
}

## handle command F(D)
# @param $pg_msg hash with pg message properties
sub Describe {
	my $pg_msg = shift;
	header($pg_msg, not $from_backend);

	printf "DESCRIBE kind='%s', name='%s'\n\n", $pg_msg->{'kind'}, $pg_msg->{'name'};
}

## handle command B(I)
# @param $pg_msg hash with pg message properties
sub EmptyQueryResponse {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "EMPTY QUERY RESPONSE\n\n";
}

## handle command B(E)
# @param $pg_msg hash with pg message properties
sub ErrorResponse {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "ERROR RESPONSE\n";
	code_response($pg_msg);

	print "\n";
}

## handle command F(E)
# @param $pg_msg hash with pg message properties
sub Execute {
	my $pg_msg = shift;
	header($pg_msg, not $from_backend);

	printf "EXECUTE name='%s', nb_rows=%d\n\n", $pg_msg->{'name'}, $pg_msg->{'nb_rows'};
}

## handle command F(H)
# @param $pg_msg hash with pg message properties
sub Flush {
	my $pg_msg = shift;
	header($pg_msg, not $from_backend);

	printf "FLUSH\n\n";
}

## handle command B(n)
# @param $pg_msg hash with pg message properties
sub NoData {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "NO DATA\n\n";
}

## handle command B(N)
# @param $pg_msg hash with pg message properties
sub NoticeResponse {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "NOTICE RESPONSE\n\n";
	code_response($pg_msg);

	print "\n";
}

## handle command B(A)
# @param $pg_msg hash with pg message properties
sub NotificationResponse {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "NOTIFICATION RESPONSE pid=%d, channel='%s', payload='%s'\n\n",
		$pg_msg->{'pid'}, $pg_msg->{'channel'}, $pg_msg->{'payload'},;
}

## handle command B(t)
# @param $pg_msg hash with pg message properties
sub ParameterDescription {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "PARAMETER DESCRIPTION: num_param=%d, params_oids=%s\n\n",
		$pg_msg->{'num_params'}, join(', ', @{ $pg_msg->{'params_types'} });
}

## handle command B(S)
# @param $pg_msg hash with pg message properties
sub ParameterStatus {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "PARAMETER STATUS name='%s', value='%s'\n\n", $pg_msg->{'name'}, $pg_msg->{'value'};
}

## handle command F(P)
# @param $pg_msg hash with pg message properties
sub Parse {
	my $pg_msg = shift;
	header($pg_msg, not $from_backend);

	printf "PARSE name='%s', num_params=%d, params_type=%s, query=%s\n\n",
		$pg_msg->{'name'}, $pg_msg->{'num_params'}, join(', ', @{ $pg_msg->{'params_types'} }), $pg_msg->{'query'};
}

## handle command B(1)
# @param $pg_msg hash with pg message properties
sub ParseComplete {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "PARSE COMPLETE\n\n";
}

## handle command F(p)
# @param $pg_msg hash with pg message properties
sub PasswordMessage {
	my $pg_msg = shift;
	header($pg_msg, not $from_backend);

	printf "PASSWORD MESSAGE password=%s\n\n", $pg_msg->{'password'};
}

## handle command B(s)
# @param $pg_msg hash with pg message properties
sub PortalSuspended {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	printf "PORTAL SUSPENDED\n\n";
}

## handle command F(Q)
# @param $pg_msg hash with pg message properties
sub Query {
	my $pg_msg = shift;
	header($pg_msg, not $from_backend);

	printf "QUERY query=%s\n\n", $pg_msg->{'query'};
}

## handle command B(Z)
# @param $pg_msg hash with pg message properties
sub ReadyForQuery {
	my $pg_msg = shift;
	header($pg_msg, $from_backend);

	$pg_msg->{'status'} = '?' if not defined $pg_msg->{'status'};

	if ($pg_msg->{'status'} eq 'I') {
		printf "READY FOR QUERY type=<IDLE>\n\n";
	}
	elsif ($pg_msg->{'status'} eq 'T') {
		printf "READY FOR QUERY type=<IDLE> in transaction\n\n";
	}
	elsif ($pg_msg->{'status'} eq 'E') {
		printf "READY FOR QUERY type=<IDLE> in transaction (aborted)\n\n";
	}
	else {
		# protocol v2 has no status
		printf "READY FOR QUERY\n\n";
	}
}

## handle command B(T)
# @param $pg_msg hash with pg message properties
sub RowDescription {
	my $pg_msg = shift;
	my $i=0;
	header($pg_msg, $from_backend);

	printf "ROW DESCRIPTION: num_fields=%d\n",
		$pg_msg->{'num_fields'};

	for my $field ( @{ $pg_msg->{'fields'} } ) {
		$i++;
		printf "  ---[Field %02d]---\n  name='%s'\n  type=%d\n  type_len=%d\n  type_mod=%d\n",
			$i, $field->[0], $field->[3], $field->[4], $field->[5];

		printf("  relid=%d\n  attnum=%d\n  format=%d\n", $field->[1], $field->[2], $field->[6]) if defined $field->[1];
	}
	print "\n";
}

## this one doesn't exists as a backend answer
# but pgshark call this method when backend answers to SSLRequest
# @param $pg_msg hash with pg message properties
sub SSLAnswer {
	my $pg_msg = shift;

	header($pg_msg, $from_backend);

	printf "SSL BACKEND ANSWER: %s\n\n", $pg_msg->{'ssl_answer'};
}

## handle command SSLRequest (F)
# @param $pg_msg hash with pg message properties
sub SSLRequest {
	my $pg_msg = shift;
	header($pg_msg, not $from_backend);

	printf "SSL REQUEST\n\n";
}

## handle command StartupMessage (F)
# @param $pg_msg hash with pg message properties
sub StartupMessage {
	my $pg_msg = shift;
	my $i=0;
	header($pg_msg, not $from_backend);

	printf "STARTUP MESSAGE version: %s\n", $pg_msg->{'version'};

	foreach my $param ( keys %{ $pg_msg->{'params'} } ) {
		printf "  %s=%s\n", $param, $pg_msg->{'params'}->{$param};
	}
	print "\n";
}

## handle command F(S)
# @param $pg_msg hash with pg message properties
sub Sync {
	my $pg_msg = shift;
	header($pg_msg, not $from_backend);

	printf "SYNC\n\n";
}

## handle command F(X)
# @param $pg_msg hash with pg message properties
sub Terminate {
	my $pg_msg = shift;
	header($pg_msg, not $from_backend);

	printf "DISCONNECT\n\n";
}

sub END {
#	debug(1, "Debug: output something usefull here ?\n");
}

1;
