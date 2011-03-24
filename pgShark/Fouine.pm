##
# This program is open source, licensed under the simplified BSD license.  For license terms, see the LICENSE file.
##

##
# TODOs
#
# == options ==
#
# * filter by session / IP / date
#
# == globals ==
#
# * top 10 errors (+ any other useful fields given with them, SQL code as instance)
# * top 10 notices  (+ any other useful fields given with them, SQL code as instance)
# * number of query canceled/kill
# * top 10 roles
# * top 10 appli / IP
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
# * sessions times
# * average number of query per session
# * ratio activity/session time
# * total exec time & total IDLE time
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

sub new {
	my $class = shift;
	my $args = shift;
	my $pcap = shift;

	my $self = {
		'sessions' => {},
		'stats' => {
			'prepd' => {},
			'queries' => {},
			'globals' => {
				'sessions' => 0,
				'total' => 0,
				'types' => {
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
					'TRUNCATE' => 0
				},
				'others' => {}

			}
		}
	};

	# set the pcap filter to remove unneeded backend answer
	my $filter = undef;

	# the following filter reject TCP-only stuff and capture only frontend messages
	pcap_compile($pcap, \$filter,
		"(tcp and port $args->{'port'}) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)", 0, 0
	);
	pcap_setfilter($pcap, $filter);

	debug(1, "Fouine: Plugin loaded.\n");

	return bless($self, $class);
}

## handle command B(1) (Parse Complete)
# @param $pg_msg hash with pg message properties
sub process_parse_complete {
	my $self = shift;
	my $pg_msg = shift;
	my $session = $self->{'sessions'}->{$pg_msg->{'sess_hash'}};

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
	}
}

## handle command B(2) (Bind Complete)
# @param $pg_msg hash with pg message properties
sub process_bind_complete {
	my $self = shift;
	my $pg_msg = shift;
	my $session = $self->{'sessions'}->{$pg_msg->{'sess_hash'}};

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
	}
}

## handle command B(A) (notification response)
# @param $pg_msg hash with pg message properties
sub process_notif_response {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle command F(B) (bind)
# @param $pg_msg hash with pg message properties
sub process_bind {
	my $self = shift;
	my $pg_msg = shift;
	my $session = $self->{'sessions'}->{$pg_msg->{'sess_hash'}};

	if (defined $session->{'prepd'}->{$pg_msg->{'name'}}) {
		my $query_hash = $session->{'prepd'}->{$pg_msg->{'name'}};

		$session->{'portals'}->{$pg_msg->{'portal'}} = $session->{'prepd'}->{$pg_msg->{'name'}};

		$session->{'running'}->{'bind'} = {
			'ts_start' => $pg_msg->{'timestamp'},
			'query_stat' => $self->{'stats'}->{'prepd'}->{$query_hash}
		};
	}
}

## handle command B(C) (command complete)
# @param $pg_msg hash with pg message properties
sub process_command_complete {
	my $self = shift;
	my $pg_msg = shift;

	my $session = $self->{'sessions'}->{$pg_msg->{'sess_hash'}};
	my @command = split(' ', $pg_msg->{'command'});

	if (defined $self->{'stats'}->{'globals'}->{'types'}->{$command[0]}) {
		$self->{'stats'}->{'globals'}->{'types'}->{$command[0]}++;
	}
	else {
		$self->{'stats'}->{'globals'}->{'others'}->{$command[0]}++;
	}
	$self->{'stats'}->{'globals'}->{'total'}++;

	if (defined $session->{'running'}->{'exec'}) {
		my $interval = $pg_msg->{'timestamp'} - $session->{'running'}->{'exec'}->{'ts_start'};
		my $query_stat = $session->{'running'}->{'exec'}->{'query_stat'};

		$query_stat->{'count'}++;
		$query_stat->{'min_time'} = $interval if ($query_stat->{'min_time'} > $interval);
		$query_stat->{'max_time'} = $interval if ($query_stat->{'max_time'} < $interval);
		$query_stat->{'avg_time'} = (($query_stat->{'avg_time'} * ($query_stat->{'count'} - 1)) + $interval) / $query_stat->{'count'};
		$query_stat->{'total'} += $interval;
		$query_stat->{'disp'} += abs($query_stat->{'avg_time'} - $interval)/$query_stat->{'count'};

		delete $session->{'running'}->{'exec'};
	}
}

## handle command F(C) (close)
# @param $pg_msg hash with pg message properties
sub process_close {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle command B(D) (data row)
# @param $pg_msg hash with pg message properties
sub process_data_row {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle command B(E) (error response)
# @param $pg_msg hash with pg message properties
sub process_error_response {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle command F(E) (execute)
# @param $pg_msg hash with pg message properties
sub process_execute {
	my $self = shift;
	my $pg_msg = shift;
	my $session = $self->{'sessions'}->{$pg_msg->{'sess_hash'}};

	if (defined $session->{'portals'}->{$pg_msg->{'name'}}) {

		$session->{'running'}->{'exec'} = {
			'ts_start' => $pg_msg->{'timestamp'},
			'query_stat' => $self->{'stats'}->{'prepd'}->{$session->{'portals'}->{$pg_msg->{'name'}}}
		};
	}
}

## handle command B(I) (empty query response)
# @param $pg_msg hash with pg message properties
sub process_empty_query {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle command B(K) (BackendKeyData)
# @param $pg_msg hash with pg message properties
sub process_key_data {
	my $self = shift;
	my $pg_msg = shift;
}

## handle command B(N) (notice response)
# @param $pg_msg hash with pg message properties
sub process_notice_response {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle command B(n) (no data)
# @param $pg_msg hash with pg message properties
sub process_no_data {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle F(P) command (parse)
# @param $pg_msg hash with pg message properties
sub process_parse {
	my $self = shift;
	my $pg_msg = shift;

	my $norm_query = normalize_query($pg_msg->{'query'});
	my $query_hash = md5_base64($norm_query);

	$self->{'sessions'}->{$pg_msg->{'sess_hash'}} = {}
		if not defined $self->{'sessions'}->{$pg_msg->{'sess_hash'}};

	my $session = $self->{'sessions'}->{$pg_msg->{'sess_hash'}};

	if (not defined $self->{'stats'}->{'prepd'}->{$query_hash}) {
		$self->{'stats'}->{'prepd'}->{$query_hash} = {
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
			'disp' => 0,
			'total' => 0,
			## TODO
			# add samples
			# add min/max/avg nb of records returned
		};
	}

	$session->{'prepd'}->{$pg_msg->{'name'}} = $query_hash;

	$session->{'running'}->{'parse'} = {
		'ts_start' => $pg_msg->{'timestamp'},
		'query_stat' => $self->{'stats'}->{'prepd'}->{$query_hash}
	};
}

## handle command F(Q) (query)
# @param $pg_msg hash with pg message properties
sub process_query {
	my $self = shift;
	my $pg_msg = shift;

	$self->{'sessions'}->{$pg_msg->{'sess_hash'}} = {}
		if not defined $self->{'sessions'}->{$pg_msg->{'sess_hash'}};

	my $session = $self->{'sessions'}->{$pg_msg->{'sess_hash'}};

	my $norm_query = normalize_query($pg_msg->{'query'});
	my $query_hash = md5_base64($norm_query);

	if (not defined $self->{'stats'}->{'queries'}->{$query_hash}) {

		$self->{'stats'}->{'queries'}->{$query_hash} = {
			'query' => $norm_query,
			'count' => 0,  # will be increased when result received
			'min_time' => 9**9**9,
			'max_time' => -1,
			'avg_time' => 0,
			'disp' => 0,
			'total' => 0,
			## TODO
			# add samples
			# add min/max/avg nb of records returned
		};
	}

	$session->{'running'}->{'exec'} = {
		'ts_start' => $pg_msg->{'timestamp'},
		'query_stat' => $self->{'stats'}->{'queries'}->{$query_hash}
	};
}

## handle command B(R) (authentification request)
# @param $pg_msg hash with pg message properties
sub process_auth_request {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle command B(s) (portal suspended)
# @param $pg_msg hash with pg message properties
sub process_portal_suspended {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle command F(S) (sync)
# @param $pg_msg hash with pg message properties
sub process_sync {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle command B(T) (row description)
# @param $pg_msg hash with pg message properties
sub process_row_desc {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle command B(t) (parameter description)
# @param $pg_msg hash with pg message properties
sub process_param_desc {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle command F(X) (terminate)
# @param $pg_msg hash with pg message properties
sub process_disconnect {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle command B(Z) (ready for query)
# @param $pg_msg hash with pg message properties
sub process_ready {
	# my $self = shift;
	# my $pg_msg = shift;
}

### specials messages without 1-byte type

## handle command CancelRequest (F)
# @param $pg_msg hash with pg message properties
sub process_cancel_request {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle command SSLRequest (F)
# @param $pg_msg hash with pg message properties
sub process_ssl_request {
	# my $self = shift;
	# my $pg_msg = shift;
}

## handle command StartupMessage (F)
# @param $pg_msg hash with pg message properties
sub process_startup_message {
	# my $self = shift;
	# my $pg_msg = shift;
}

## this one doesn't exists as a backend answer
# but pgshark call this method when backend answers to SSLRequest
sub process_ssl_answer {
	# my $self = shift;
	# my $pg_msg = shift;
}

sub DESTROY {
	my $self = shift;


	my @top_slowest;
	my @top_most_time;
	my @top_most_frequent;

	print "==== Queries by type ====\n\n";

	if ($self->{'stats'}->{'globals'}->{'total'}) {
		@top_most_frequent = sort { $self->{'stats'}->{'globals'}->{'types'}->{$b} <=> $self->{'stats'}->{'globals'}->{'types'}->{$a} }
			keys %{ $self->{'stats'}->{'globals'}->{'types'} };
		print "Rank\t        Type\t     Count\tPercentage\n";
		my $i = 1;
		foreach (@top_most_frequent) {
			printf "%4d\t%12s\t%10d\t%10.2f\n",
				$i, $_, $self->{'stats'}->{'globals'}->{'types'}->{$_}, 100*($self->{'stats'}->{'globals'}->{'types'}->{$_} / $self->{'stats'}->{'globals'}->{'total'});
			$i++;
		}

		print "\n\nTotal queries: $self->{'stats'}->{'globals'}->{'total'}\n\n";
	}
	else {
		print "\n\nBackend answers were not found.\n\n";
	}

	print "\n\n==== Prepared Statements ====\n\n";

	@top_slowest = sort { $b->{'max_time'} <=> $a->{'max_time'} } values %{ $self->{'stats'}->{'prepd'} };
	@top_most_time = sort { $b->{'total'} <=> $a->{'total'} } values %{ $self->{'stats'}->{'prepd'} };
	@top_most_frequent = sort { $b->{'count'} <=> $a->{'count'} } values %{ $self->{'stats'}->{'prepd'} };

	print "=== Top slowest queries ===\n\n";
	print "Rank\tDuration(ms)\tQuery\n";
	for(my $i=0; $i < 10; $i++) {
		if (defined $top_slowest[$i]) {
			printf "%4d\t%12.5f\t%s\n",
				$i+1, $top_slowest[$i]->{'max_time'}, $top_slowest[$i]->{'query'};
		}
	}

	print "\n\n=== Queries that took up the most time ===\n\n";
	print "Rank\ttotal Duration(ms)\ttimes executed\tAv. duration (ms)\tQuery\n";
	for(my $i=0; $i < 10; $i++) {
		if (defined $top_most_time[$i]) {
			printf "%4d\t%18.5f\t%14d\t%17.5f\t%s\n",
				$i+1, $top_most_time[$i]->{'total'}, $top_most_time[$i]->{'count'},
				$top_most_time[$i]->{'avg_time'}, $top_most_time[$i]->{'query'};
		}
	}

	print "\n\n=== Most frequent queries ===\n\n";
	print "Rank\ttimes executed\ttotal Duration(ms)\tAv. duration (ms)\tQuery\n";
	for(my $i=0; $i < 10; $i++) {
		if (defined $top_most_frequent[$i]) {
			printf "%4d\t%14d\t%18.5f\t%17.5f\t%s\n",
				$i+1, $top_most_frequent[$i]->{'count'}, $top_most_frequent[$i]->{'total'},
				$top_most_frequent[$i]->{'avg_time'}, $top_most_frequent[$i]->{'query'};
		}
	}

	print "\n\n==== Simple Queries ====\n\n";

	@top_slowest = sort { $b->{'max_time'} <=> $a->{'max_time'} } values %{ $self->{'stats'}->{'queries'} };
	@top_most_time = sort { $b->{'total'} <=> $a->{'total'} } values %{ $self->{'stats'}->{'queries'} };
	@top_most_frequent = sort { $b->{'count'} <=> $a->{'count'} } values %{ $self->{'stats'}->{'queries'} };

	print "=== Top slowest queries ===\n\n";
	print "Rank\tDuration(ms)\tQuery\n";
	for(my $i=0; $i < 10; $i++) {
		if (defined $top_slowest[$i]) {
			printf "%4d\t%12.5f\t%s\n",
				$i+1, $top_slowest[$i]->{'max_time'}, $top_slowest[$i]->{'query'};
		}
	}

	print "\n\n=== Queries that took up the most time ===\n\n";
	print "Rank\ttotal Duration(ms)\ttimes executed\tAv. duration (ms)\tQuery\n";
	for(my $i=0; $i < 10; $i++) {
		if (defined $top_most_time[$i]) {
			printf "%4d\t%18.5f\t%14d\t%17.5f\t%s\n",
				$i+1, $top_most_time[$i]->{'total'}, $top_most_time[$i]->{'count'},
				$top_most_time[$i]->{'avg_time'}, $top_most_time[$i]->{'query'};
		}
	}

	print "\n\n=== Most frequent queries ===\n\n";
	print "Rank\ttimes executed\ttotal Duration(ms)\tAv. duration (ms)\tQuery\n";
	for(my $i=0; $i < 10; $i++) {
		if (defined $top_most_frequent[$i]) {
			printf "%4d\t%14d\t%18.5f\t%17.5f\t%s\n",
				$i+1, $top_most_frequent[$i]->{'count'}, $top_most_frequent[$i]->{'total'},
				$top_most_frequent[$i]->{'avg_time'}, $top_most_frequent[$i]->{'query'};
		}
	}
}

1;
