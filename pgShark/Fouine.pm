##
# This program is open source, licensed under the simplified BSD license.  For license terms, see the LICENSE file.
##

##
# TODOs
# == FIXes ==
#
# * Pay attention to NoData, EmptyQueryResponse, ...
# * a session should be busy from some given (any ?) messages to the readyForQuery backend message
#
# == options ==
#
# * filter by session / IP / date
#
# == globals ==
#
# * top 10 roles
# * top 10 appli / IP
# * average number of cols per query
# * auth types (clear, md5, password, ...)
#
# == prepd stmt ==
#
# * add prepare/bind/exec times to prepd stmt the top-10s tables
#
# == repli ==
#
# * stats repli ?
#
# == session stats ==
#
# == graph ==
#
# * error / notice
# * commit/rollback
# * cnx by appli / IP
# * nb of rows OUT
# * nb of bytes IN/OUT
# * nb of queries IN
# * cnx roles
#
##
package Fouine;

use strict;
use warnings;
use pgShark::Utils;
use Digest::MD5 qw(md5_base64);
use Net::Pcap qw(:functions);
use Data::Dumper;

use Exporter;
our $VERSION = 0.1;
our @ISA = ('Exporter');
our @EXPORT = qw/getCallbacks getFilter AuthenticationOk Bind BindComplete CancelRequest Close CloseComplete
CommandComplete DataRow ErrorResponse Execute NoticeResponse Parse ParseComplete Query RowDescription StartupMessage
Terminate/;

our @EXPORT_OK = qw/getCallbacks getFilter AuthenticationOk Bind BindComplete CancelRequest Close CloseComplete
CommandComplete DataRow ErrorResponse Execute NoticeResponse Parse ParseComplete Query RowDescription StartupMessage
Terminate/;

my $sessions = {};
my $stats = {
		'first_message' => 0,
		'last_message' => 0,
		'total_notices' => 0,
		'min_notices' => 9**9**9, # min notices seen per session
		'max_notices' => 0, # max notices seen per session
		'total_errors' => 0,
		'min_errors' => 9**9**9, # min errors seen per session
		'max_errors' => 0, # max errors seen per session
		'cancels_count' => 0,
		'queries_total' => 0,
		'errors' => {},
		'notices' => {},
		'prepd' => {},
		'queries' => {},
		'query_types' => {
			'SELECT' => 0,
			'INSERT' => 0,
			'UPDATE' => 0,
			'DELETE' => 0,
			'BEGIN' => 0,
			'COMMIT' => 0,
			'ROLLBACK' => 0,
			'MOVE' => 0,
			'FETCH' => 0,
			'COPY' => 0,
			'VACUUM' => 0,
			'TRUNCATE' => 0,
			'DECLARE' => 0,
			'CLOSE' => 0,
			'others' => 0
		},
		'sessions' => {
			'total' => 0,
			'cnx' => 0,
			'discnx' => 0,
			'min_time' => 9**9**9,
			'avg_time' => 0,
			'max_time' => 0,
			'total_time' => 0,
			'total_busy_time' => 0,
			'auth_min_time' => 9**9**9,
			'auth_avg_time' => 0,
			'auth_max_time' => 0,
			'min_queries' => 9**9**9,
			'avg_queries' => 0,
			'max_queries' => 0,
			'min_rows' => 9**9**9,
			'avg_rows' => 0,
			'max_rows' => 0,
			'total_rows' => 0,
			'min_fields' => 9**9**9,
			'max_fields' => 0,

		},
	};

sub getCallbacks {
	return {
		'AuthenticationOk' => \&AuthenticationOk,
		'Bind' => \&Bind,
		'BindComplete' => \&BindComplete,
		'CancelRequest' => \&CancelRequest,
		'Close' => \&Close,
		'CloseComplete' => \&CloseComplete,
		'CommandComplete' => \&CommandComplete,
		'DataRow' => \&DataRow,
		'ErrorResponse' => \&ErrorResponse,
		'Execute' => \&Execute,
		'NoticeResponse' => \&NoticeResponse,
		'Parse' => \&Parse,
		'ParseComplete' => \&ParseComplete,
		'Query' => \&Query,
		'RowDescription' => \&RowDescription,
		'StartupMessage' => \&StartupMessage,
		'Terminate' => \&Terminate
	};
}

sub getFilter {
	my $host = shift;
	my $port = shift;
	return "(tcp and port $port) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
}

sub get_session {
	my $pg_msg = shift;
	my $hash = $pg_msg->{'sess_hash'};

	if (not defined $sessions->{$hash}) {
		$sessions->{$hash} = {
			'stats' => {
				'ts_start' => $pg_msg->{'timestamp'},
				'busy_time' => 0,
				'queries_count' => 0,
				'notices_count' => 0,
				'errors_count' => 0,
				'rows_count' => 0,
				'min_fields' => 9**9**9,
				'max_fields' => 0,
			}
		};

		$stats->{'sessions'}->{'total'}++;
	}

	$stats->{'first_message'} = $pg_msg->{'timestamp'}
		unless $stats->{'first_message'};

	$stats->{'last_message'} = $pg_msg->{'timestamp'};

	return $sessions->{$hash};
}

sub record_session_stats {
	my $session = shift;

	my $interval = $session->{'stats'}->{'ts_end'} - $session->{'stats'}->{'ts_start'};
	my $sessions_stats = $stats->{'sessions'};

	$sessions_stats->{'total_time'} += $interval;
	$sessions_stats->{'min_time'}    = $interval if $sessions_stats->{'min_time'} > $interval;
	$sessions_stats->{'max_time'}    = $interval if $sessions_stats->{'max_time'} < $interval;
	$sessions_stats->{'avg_time'}    = (($sessions_stats->{'avg_time'} * ($sessions_stats->{'total'} - 1)) + $interval) / $sessions_stats->{'total'};
	$sessions_stats->{'total_busy_time'} += $session->{'stats'}->{'busy_time'};

	$sessions_stats->{'min_queries'} = $session->{'stats'}->{'queries_count'} if $sessions_stats->{'min_queries'} > $session->{'stats'}->{'queries_count'};
	$sessions_stats->{'max_queries'} = $session->{'stats'}->{'queries_count'} if $sessions_stats->{'max_queries'} < $session->{'stats'}->{'queries_count'};
	$sessions_stats->{'avg_queries'} = (($sessions_stats->{'avg_queries'} * ($sessions_stats->{'total'} - 1)) + $session->{'stats'}->{'queries_count'}) / $sessions_stats->{'total'};

	$stats->{'queries_total'} += $session->{'stats'}->{'queries_count'};
	$stats->{'total_notices'} += $session->{'stats'}->{'notices_count'};
	$stats->{'min_notices'} = $session->{'stats'}->{'notices_count'} if $session->{'stats'}->{'notices_count'} < $stats->{'min_notices'};
	$stats->{'max_notices'} = $session->{'stats'}->{'notices_count'} if $session->{'stats'}->{'notices_count'} > $stats->{'max_notices'};
	$stats->{'total_errors'} += $session->{'stats'}->{'errors_count'};
	$stats->{'min_errors'} = $session->{'stats'}->{'errors_count'} if $stats->{'min_errors'} > $session->{'stats'}->{'errors_count'};
	$stats->{'max_errors'} = $session->{'stats'}->{'errors_count'} if $stats->{'max_errors'} < $session->{'stats'}->{'errors_count'};

	$sessions_stats->{'min_rows'} = $session->{'stats'}->{'rows_count'} if $sessions_stats->{'min_rows'} > $session->{'stats'}->{'rows_count'};
	$sessions_stats->{'max_rows'} = $session->{'stats'}->{'rows_count'} if $sessions_stats->{'max_rows'} < $session->{'stats'}->{'rows_count'};
	$sessions_stats->{'avg_rows'} = (($sessions_stats->{'avg_rows'} * ($sessions_stats->{'total'} - 1)) + $session->{'stats'}->{'rows_count'}) / $sessions_stats->{'total'};
	$sessions_stats->{'total_rows'} += $session->{'stats'}->{'rows_count'};

	$sessions_stats->{'min_fields'} = $session->{'stats'}->{'min_fields'} if $sessions_stats->{'min_fields'} > $session->{'stats'}->{'min_fields'};
	$sessions_stats->{'max_fields'} = $session->{'stats'}->{'max_fields'} if $sessions_stats->{'max_fields'} < $session->{'stats'}->{'max_fields'};
}

## handle command F(B) (Bind)
# @param $pg_msg hash with pg message properties
sub Bind {
	my $pg_msg = shift;

	my $session = get_session($pg_msg);

	if (defined $session->{'prepd'}->{$pg_msg->{'name'}}) {
		my $query_hash = $session->{'prepd'}->{$pg_msg->{'name'}};

		$session->{'portals'}->{$pg_msg->{'portal'}} = $session->{'prepd'}->{$pg_msg->{'name'}};

		$session->{'running'}->{'bind'} = {
			'ts_start' => $pg_msg->{'timestamp'},
			'query_stat' => $stats->{'prepd'}->{$query_hash}
		};
	}
}

## handle command B(2) (BindComplete)
# @param $pg_msg hash with pg message properties
sub BindComplete {
	my $pg_msg = shift;

	my $session = get_session($pg_msg);

	if (defined $session->{'running'}->{'bind'}) {
		my $interval = $pg_msg->{'timestamp'} - $session->{'running'}->{'bind'}->{'ts_start'};
		my $prep_stat = $session->{'running'}->{'bind'}->{'query_stat'};

		$prep_stat->{'bind_count'}++;
		$prep_stat->{'bind_min_time'} = $interval if ($prep_stat->{'bind_min_time'} > $interval);
		$prep_stat->{'bind_max_time'} = $interval if ($prep_stat->{'bind_max_time'} < $interval);
		$prep_stat->{'bind_avg_time'} = (($prep_stat->{'bind_avg_time'} * ($prep_stat->{'bind_count'} - 1)) + $interval) / $prep_stat->{'bind_count'};
		$prep_stat->{'bind_total'} += $interval;
		$prep_stat->{'bind_disp'} += abs($prep_stat->{'bind_avg_time'} - $interval)/$prep_stat->{'bind_count'};

		delete $session->{'running'}->{'bind'};

		$session->{'stats'}->{'busy_time'} += $interval if (not keys % { $session->{'running'} });
		$session->{'stats'}->{'queries_count'}++;
	}
}

## handle command CancelRequest (F)
# @param $pg_msg hash with pg message properties
sub CancelRequest {
	my $pg_msg = shift;
	my $session = get_session($pg_msg);

	$stats->{'cancels_count'}++;
}


## handle command F(C)
# @param $pg_msg hash with pg message properties
sub Close {
	my $pg_msg = shift;
	my $session = get_session($pg_msg);

	# TODO support stat for closing a portal or a prep stmt
	# Presently we just set it for busy time
	# we don't need to check if the prep stmt/portal exists for this stat as
	# "It is not an error to issue Close against a nonexistent statement or portal name."
	$session->{'running'}->{'close'} = {
		'ts_start' => $pg_msg->{'timestamp'},
	}
}

## handle command B(3)
# @param $pg_msg hash with pg message properties
sub CloseComplete {
	my $pg_msg = shift;
	my $session = get_session($pg_msg);

	if (defined $session->{'running'}->{'close'}) {
		my $interval = $pg_msg->{'timestamp'} - $session->{'running'}->{'bind'}->{'ts_start'};

		delete $session->{'running'}->{'close'};

		$session->{'stats'}->{'busy_time'} += $interval if (not keys % { $session->{'running'} });
	}
}

## handle command B(C) (CommandComplete)
# @param $pg_msg hash with pg message properties
sub CommandComplete {
	my $pg_msg = shift;

	my $session = get_session($pg_msg);
	my @command = split(' ', $pg_msg->{'command'});

	if (defined $stats->{'query_types'}->{$command[0]}) {
		$stats->{'query_types'}->{$command[0]}++;
	}
	else {
		debug(1, "Unknown command complete answer: %s\n", $command[0]);
		$stats->{'query_types'}->{'others'}++;
	}

	if (defined $session->{'running'}->{'exec'}) {
		my $interval = $pg_msg->{'timestamp'} - $session->{'running'}->{'exec'}->{'ts_start'};
		my $query_stat = $session->{'running'}->{'exec'}->{'query_stat'};

		$query_stat->{'count'}++;
		$query_stat->{'min_time'} = $interval if ($query_stat->{'min_time'} > $interval);
		$query_stat->{'max_time'} = $interval if ($query_stat->{'max_time'} < $interval);
		$query_stat->{'avg_time'} = (($query_stat->{'avg_time'} * ($query_stat->{'count'} - 1)) + $interval) / $query_stat->{'count'};
		$query_stat->{'total_time'} += $interval;
		$query_stat->{'disp'} += abs($query_stat->{'avg_time'} - $interval)/$query_stat->{'count'};

		delete $session->{'running'}->{'exec'};

		$session->{'stats'}->{'busy_time'} += $interval if (not keys % { $session->{'running'} });

		$session->{'stats'}->{'queries_count'}++;
	}
	else {
		# we complete smth that was executed earlier ??
		$stats->{'queries_total'}++;
	}
}

## handle command B(D)
# @param $pg_msg hash with pg message properties
sub DataRow {
	my $pg_msg = shift;
	my $session = get_session($pg_msg);

	$session->{'stats'}->{'rows_count'}++;
}

## handle command B(E) (ErrorResponse)
# @param $pg_msg hash with pg message properties
sub ErrorResponse {
	my $pg_msg = shift;
	my $session = get_session($pg_msg);
	my $error_stats = $stats->{'errors'};
	my $hash = md5_base64($pg_msg->{'fields'}->{'M'});

	if (not defined $error_stats->{$hash}) {
		$error_stats->{$hash}->{'fields'} = $pg_msg->{'fields'};
		$error_stats->{$hash}->{'count'} = 0;
	}

	$error_stats->{$hash}->{'count'}++;
	$session->{'stats'}->{'errors_count'}++;
}

## handle command F(E) (Execute)
# @param $pg_msg hash with pg message properties
sub Execute {
	my $pg_msg = shift;

	my $session = get_session($pg_msg);

	if (defined $session->{'portals'}->{$pg_msg->{'name'}}) {

		$session->{'running'}->{'exec'} = {
			'ts_start' => $pg_msg->{'timestamp'},
			'query_stat' => $stats->{'prepd'}->{$session->{'portals'}->{$pg_msg->{'name'}}}
		};
	}
}

## handle command B(N) (NoticeResponse)
# @param $pg_msg hash with pg message properties
sub NoticeResponse {
	my $pg_msg = shift;
	my $session = get_session($pg_msg);
	my $notice_stats = $stats->{'notices'};
	my $hash = md5_base64($pg_msg->{'fields'}->{'M'});

	if (not defined $notice_stats->{$hash}) {
		$notice_stats->{$hash}->{'fields'} = $pg_msg->{'fields'};
		$notice_stats->{$hash}->{'count'} = 0;
	}

	$session->{'stats'}->{'notices_count'}++;
	$notice_stats->{$hash}->{'count'}++;
}

## handle F(P) command (Parse)
# @param $pg_msg hash with pg message properties
sub Parse {
	my $pg_msg = shift;

	my $norm_query = normalize_query($pg_msg->{'query'});
	my $query_hash = md5_base64($norm_query);

	my $session = get_session($pg_msg);

	if (not defined $stats->{'prepd'}->{$query_hash}) {
		$stats->{'prepd'}->{$query_hash} = {
			'query' => $norm_query,
			'prep_count' => 0,
			'count' => 0,  # will be increased when result received
			'prep_count' => 0,
			'prep_min_time' => 9**9**9,
			'prep_max_time' => -1,
			'prep_avg_time' => 0,
			'prep_disp' => 0,
			'prep_total' => 0,
			'bind_count' => 0,
			'bind_min_time' => 9**9**9,
			'bind_max_time' => -1,
			'bind_avg_time' => 0,
			'bind_disp' => 0,
			'bind_total' => 0,
			'min_time' => 9**9**9,
			'max_time' => -1,
			'avg_time' => 0,
			'total_time' => 0,
			'disp' => 0,
			## TODO
			# add samples
			# add min/max/avg nb of records returned
		};
	}

	$session->{'prepd'}->{$pg_msg->{'name'}} = $query_hash;

	$session->{'running'}->{'parse'} = {
		'ts_start' => $pg_msg->{'timestamp'},
		'query_stat' => $stats->{'prepd'}->{$query_hash}
	};
}

## handle command B(1) (ParseComplete)
# @param $pg_msg hash with pg message properties
sub ParseComplete {
	my $pg_msg = shift;

	my $session = get_session($pg_msg);

	if (defined $session->{'running'}->{'parse'}) {
		my $interval = $pg_msg->{'timestamp'} - $session->{'running'}->{'parse'}->{'ts_start'};
		my $prep_stat = $session->{'running'}->{'parse'}->{'query_stat'};

		$prep_stat->{'prep_count'}++;
		$prep_stat->{'prep_min_time'} = $interval if ($prep_stat->{'prep_min_time'} > $interval);
		$prep_stat->{'prep_max_time'} = $interval if ($prep_stat->{'prep_max_time'} < $interval);
		$prep_stat->{'prep_avg_time'} = (($prep_stat->{'prep_avg_time'} * ($prep_stat->{'prep_count'} - 1)) + $interval) / $prep_stat->{'prep_count'};
		$prep_stat->{'prep_total'} += $interval;
		$prep_stat->{'prep_disp'} += abs($prep_stat->{'prep_avg_time'} - $interval)/$prep_stat->{'prep_count'};

		delete $session->{'running'}->{'parse'};

		$session->{'stats'}->{'busy_time'} += $interval if (not keys % { $session->{'running'} });
		$session->{'stats'}->{'queries_count'}++;
	}
}

## handle command F(Q) (query)
# @param $pg_msg hash with pg message properties
sub Query {
	my $pg_msg = shift;

	my $session = get_session($pg_msg);

	my $norm_query = normalize_query($pg_msg->{'query'});
	my $query_hash = md5_base64($norm_query);

	if (not defined $stats->{'queries'}->{$query_hash}) {

		$stats->{'queries'}->{$query_hash} = {
			'query' => $norm_query,
			'count' => 0,  # will be increased when result received
			'min_time' => 9**9**9,
			'max_time' => -1,
			'avg_time' => 0,
			'disp' => 0,
			'total_time' => 0,
			## TODO
			# add samples
			# add min/max/avg nb of records returned
		};
	}

	$session->{'running'}->{'exec'} = {
		'ts_start' => $pg_msg->{'timestamp'},
		'query_stat' => $stats->{'queries'}->{$query_hash}
	};
}

## handle command B(R) (AuthenticationOk)
# @param $pg_msg hash with pg message properties
sub AuthenticationOk {
	my $pg_msg = shift;

	my $session = get_session($pg_msg);

	## Auth succeed
	#if ($pg_msg->{'code'} == 0) {
		my $session_stat = $stats->{'sessions'};
		my $interval = $pg_msg->{'timestamp'} - $session->{'stats'}->{'ts_start'};

		$session_stat->{'cnx'}++;

		$session_stat->{'auth_min_time'} = $interval if ($session_stat->{'auth_min_time'} > $interval);
		$session_stat->{'auth_avg_time'} = (($session_stat->{'auth_avg_time'} * ($session_stat->{'cnx'} - 1)) + $interval) / $session_stat->{'cnx'};
		$session_stat->{'auth_max_time'} = $interval if ($session_stat->{'auth_max_time'} < $interval);
	#}
}

## handle command B(T)
# @param $pg_msg hash with pg message properties
sub RowDescription {
	my $pg_msg = shift;
	my $session = get_session($pg_msg);
	my $num_fields = scalar(@{ $pg_msg->{'fields'} });

	$session->{'stats'}->{'min_fields'} = $num_fields if $session->{'stats'}->{'min_fields'} > $num_fields;
	$session->{'stats'}->{'max_fields'} = $num_fields if $session->{'stats'}->{'max_fields'} < $num_fields;
}

## handle command StartupMessage (F)
# @param $pg_msg hash with pg message properties
sub StartupMessage {
	my $pg_msg = shift;

	# build the session and set its start time
	my $session = get_session($pg_msg);
}

## handle command F(X) (Terminate)
# @param $pg_msg hash with pg message properties
sub Terminate {
	my $pg_msg = shift;

	my $session = get_session($pg_msg);

	$stats->{'sessions'}->{'discnx'}++;

	$session->{'stats'}->{'ts_end'} = $pg_msg->{'timestamp'};

	record_session_stats($session);

	delete $sessions->{$pg_msg->{'sess_hash'}};
}

sub END {

	my @top_slowest;
	my @top_most_time;
	my @top_most_frequent;

	my $sessions_stats = $stats->{'sessions'};

	foreach my $hash (keys %{ $sessions }) {
		my $session = $sessions->{$hash};

		$session->{'stats'}->{'ts_end'} = $stats->{'last_message'};

		record_session_stats($session);

		delete $sessions->{$hash};
	}

	print "===== Overall stats =====\n\n";

	printf "First message:              %s\n", scalar(localtime($stats->{'first_message'}));
	printf "Last message:               %s\n", scalar(localtime($stats->{'last_message'}));
	printf "Number of cancel requests:  %s\n", $stats->{'cancels_count'};
	printf "Total number of sessions:   %d\n", $sessions_stats->{'total'};
	printf "Number connections:         %d\n", $sessions_stats->{'cnx'};
	printf "Number of disconnections:   %d\n", $sessions_stats->{'discnx'};
	printf "Cumulated sessions time:    %.6f s\n", $sessions_stats->{'total_time'};
	printf "Cumulated busy time:        %.6f s\n", $sessions_stats->{'total_busy_time'};
	printf "Total busy ratio:           %.6f %%\n", 100 * $sessions_stats->{'total_busy_time'} / $sessions_stats->{'total_time'};
	printf "Total number of rows:       %d\n", $sessions_stats->{'total_rows'};

	print "\n\n==== Notices & Errors ====\n\n";

	printf "Total notices:                %d\n",  $stats->{'total_notices'};
	printf "Min/Max notices per sessions: %d/%d\n",  $stats->{'min_notices'}, $stats->{'max_notices'};
	printf "Total errors:                 %d\n",  $stats->{'total_errors'};
	printf "Min/Max errors per sessions:  %d/%d\n",  $stats->{'min_errors'}, $stats->{'max_errors'};

	print "\n\n=== Most frequent notices ===\n\n";

	@top_most_frequent = sort { $b->{'count'} <=> $a->{'count'} } values %{ $stats->{'notices'} };

	print "Rank\tTimes raised\t     Level\t      Code\tMessage\n";
	for(my $i=0; $i < 10; $i++) {
		if (defined $top_most_frequent[$i]) {
			printf "%4d\t%12d\t%10s\t%10s\t%s\n",
				$i+1, $top_most_frequent[$i]->{'count'}, $top_most_frequent[$i]->{'fields'}->{'S'},
				$top_most_frequent[$i]->{'fields'}->{'C'}, $top_most_frequent[$i]->{'fields'}->{'M'};
		}
	}

	print "\n\n=== Most frequent errors ===\n\n";

	@top_most_frequent = sort { $b->{'count'} <=> $a->{'count'} } values %{ $stats->{'errors'} };

	print "Rank\tTimes raised\t     Level\t      Code\tMessage\n";
	for(my $i=0; $i < 10; $i++) {
		if (defined $top_most_frequent[$i]) {
			printf "%4d\t%12d\t%10s\t%10s\t%s\n",
				$i+1, $top_most_frequent[$i]->{'count'}, $top_most_frequent[$i]->{'fields'}->{'S'},
				$top_most_frequent[$i]->{'fields'}->{'C'}, $top_most_frequent[$i]->{'fields'}->{'M'};
		}
	}

	print "\n\n==== Sessions ====\n\n";

	printf "Min/Avg/Max authentication time (s):              %.6f / %.6f / %.6f\n",
		$sessions_stats->{'auth_min_time'},
		$sessions_stats->{'auth_avg_time'},
		$sessions_stats->{'auth_max_time'};
	printf "Min/Avg/Max sessions time (s):                    %.6f / %.6f / %.6f\n",
		$sessions_stats->{'min_time'},
		$sessions_stats->{'avg_time'},
		$sessions_stats->{'max_time'};
	printf "Min/Avg/Max number of queries per sessions:       %d / %.2f / %d\n",
		$sessions_stats->{'min_queries'},
		$sessions_stats->{'avg_queries'},
		$sessions_stats->{'max_queries'};
	printf "Min/Max number of fields per session and queries: %d / %d\n",
		$sessions_stats->{'min_fields'},
		$sessions_stats->{'max_fields'};
	printf "Min/Avg/Max number of rows per sessions:          %d / %.2f / %d\n",
		$sessions_stats->{'min_rows'},
		$sessions_stats->{'avg_rows'},
		$sessions_stats->{'max_rows'};

	print "\n===== Queries =====\n\n";

	print "==== Queries by type ====\n\n";

	if ($stats->{'queries_total'}) {
		@top_most_frequent = sort { $stats->{'query_types'}->{$b} <=> $stats->{'query_types'}->{$a} }
			keys %{ $stats->{'query_types'} };
		print "Rank\t        Type\t     Count\tPercentage\n";
		my $i = 1;
		foreach (@top_most_frequent) {
			printf "%4d\t%12s\t%10d\t%10.2f\n",
				$i, $_, $stats->{'query_types'}->{$_}, 100*($stats->{'query_types'}->{$_} / $stats->{'queries_total'});
			$i++;
		}

		print "\n\nTotal queries: $stats->{'queries_total'}\n\n";
	}
	else {
		print "\n\nBackend answers were not found.\n\n";
	}

	print "\n==== Prepared Statements ====\n\n";

	@top_slowest = sort { $b->{'max_time'} <=> $a->{'max_time'} } values %{ $stats->{'prepd'} };
	@top_most_time = sort { $b->{'total_time'} <=> $a->{'total_time'} } values %{ $stats->{'prepd'} };
	@top_most_frequent = sort { $b->{'count'} <=> $a->{'count'} } values %{ $stats->{'prepd'} };

	print "=== Top slowest queries ===\n\n";
	print "Rank\tDuration(s)\tQuery\n";
	for(my $i=0; $i < 10; $i++) {
		if (defined $top_slowest[$i]) {
			printf "%4d\t%12.5f\t%s\n",
				$i+1, $top_slowest[$i]->{'max_time'}, $top_slowest[$i]->{'query'};
		}
	}

	print "\n\n=== Queries that took up the most time ===\n\n";
	print "Rank\ttotal Duration(s)\ttimes executed\tAv. duration (s)\tQuery\n";
	for(my $i=0; $i < 10; $i++) {
		if (defined $top_most_time[$i]) {
			printf "%4d\t%18.5f\t%14d\t%17.5f\t%s\n",
				$i+1, $top_most_time[$i]->{'total_time'}, $top_most_time[$i]->{'count'},
				$top_most_time[$i]->{'avg_time'}, $top_most_time[$i]->{'query'};
		}
	}

	print "\n\n=== Most frequent queries ===\n\n";
	print "Rank\ttimes executed\ttotal Duration(s)\tAv. duration (s)\tQuery\n";
	for(my $i=0; $i < 10; $i++) {
		if (defined $top_most_frequent[$i]) {
			printf "%4d\t%14d\t%18.5f\t%17.5f\t%s\n",
				$i+1, $top_most_frequent[$i]->{'count'}, $top_most_frequent[$i]->{'total_time'},
				$top_most_frequent[$i]->{'avg_time'}, $top_most_frequent[$i]->{'query'};
		}
	}

	print "\n\n==== Simple Queries ====\n\n";

	@top_slowest = sort { $b->{'max_time'} <=> $a->{'max_time'} } values %{ $stats->{'queries'} };
	@top_most_time = sort { $b->{'total_time'} <=> $a->{'total_time'} } values %{ $stats->{'queries'} };
	@top_most_frequent = sort { $b->{'count'} <=> $a->{'count'} } values %{ $stats->{'queries'} };

	print "=== Top slowest queries ===\n\n";
	print "Rank\tDuration(s)\tQuery\n";
	for(my $i=0; $i < 10; $i++) {
		if (defined $top_slowest[$i]) {
			printf "%4d\t%12.5f\t%s\n",
				$i+1, $top_slowest[$i]->{'max_time'}, $top_slowest[$i]->{'query'};
		}
	}

	print "\n\n=== Queries that took up the most time ===\n\n";
	print "Rank\ttotal Duration(s)\ttimes executed\tAv. duration (s)\tQuery\n";
	for(my $i=0; $i < 10; $i++) {
		if (defined $top_most_time[$i]) {
			printf "%4d\t%18.5f\t%14d\t%17.5f\t%s\n",
				$i+1, $top_most_time[$i]->{'total_time'}, $top_most_time[$i]->{'count'},
				$top_most_time[$i]->{'avg_time'}, $top_most_time[$i]->{'query'};
		}
	}

	print "\n\n=== Most frequent queries ===\n\n";
	print "Rank\ttimes executed\ttotal Duration(s)\tAv. duration (s)\tQuery\n";
	for(my $i=0; $i < 10; $i++) {
		if (defined $top_most_frequent[$i]) {
			printf "%4d\t%14d\t%18.5f\t%17.5f\t%s\n",
				$i+1, $top_most_frequent[$i]->{'count'}, $top_most_frequent[$i]->{'total_time'},
				$top_most_frequent[$i]->{'avg_time'}, $top_most_frequent[$i]->{'query'};
		}
	}
	# print Dumper($stats->{'query_types'});
}

1;
