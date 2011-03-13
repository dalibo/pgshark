package Normalize;

use strict;
use warnings;
use Digest::MD5 qw(md5_base64);
use Net::Pcap qw(:functions);
use pgShark::Utils;
use Data::Dumper;

## TODO
#  add some option to control what we want to catch:
#   * queries ? prepd stmt ? portals ? ALL (deallocate as instance ?) ??
#   * add some query samples if asked by option (commented ?)
#   * support $str$strings here$str$ notation

sub new {
	my $class = shift;
	my $args = shift;
	my $pcap = shift;

	my $self = {
		## hash handling normalized queries
		# $normalized = {
		# 	query md5 hash => {
		#		query => normalized query,
		#		count => # of occurrences
		# }
		'normalized' => {}
	};

	# set the pcap filter to remove unneeded backend answer
	my $filter = undef;

	# the following filter reject TCP-only stuff and capture only frontend messages
	pcap_compile($pcap, \$filter,
		"(tcp and dst port $args->{'port'}) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)", 0, 0
	);
	pcap_setfilter($pcap, $filter);

	debug(1, "Normalize: Plugin loaded.\n");

	return bless($self, $class);
}

## 
# normalize query and record them in the $normalized hash
# @return the hash of the query
sub normalize {
	my $self = shift;
	my $query = shift;

	$query = normalize_query($query);

	my $query_hash = md5_base64($query);

	if (not defined $self->{'normalized'}->{$query_hash}) {
		$self->{'normalized'}->{$query_hash} = {
			'query' => $query,
			'count' => 1
		};
	}
	else {
		$self->{'normalized'}->{$query_hash}->{count}++;
	}

	return $query_hash;
}

# handle C command (close)
# @param $pg_msg hash with pg message properties
sub deallocate {
	# my $self = shift;
	# my $pg_msg = shift;
	# Nothing to do...yet
}

## handle P command (parse)
# @param $pg_msg hash with pg message properties
sub process_parse {
	my $self = shift;
	# maybe we should do something fancier ?
	my $pg_msg = shift;

	my $query_hash = $self->normalize($pg_msg->{query});

	if ($self->{'normalized'}->{$query_hash}->{count} == 1) {
		print "PREPARE xxx(...) AS $self->{'normalized'}->{$query_hash}->{query}\n\n";
	}
}

## handle command B (bind)
# @param $pg_msg hash with pg message properties
sub process_bind {
	# my $self = shift;
	# my $pg_msg = shift;
	# Nothing to do...yet
}

## handle command E (execute)
# @param $pg_msg hash with pg message properties
sub process_execute {
	# my $self = shift;
	# my $pg_msg = shift;
	# Nothing to do...yet
}

## handle command C (close)
# @param $pg_msg hash with pg message properties
sub process_close {
	# my $self = shift;
	# my $pg_msg = shift;
	# Nothing to do...yet
}

## handle command Q (query)
# @param $pg_msg hash with pg message properties
sub process_query {
	my $self = shift;
	my $pg_msg = shift;

	my $query_hash = $self->normalize($pg_msg->{query});

	if ($self->{'normalized'}->{$query_hash}->{count} == 1) {
		print "$self->{'normalized'}->{$query_hash}->{query}\n\n";
	}
}

## handle command F(S) (sync)
# @param $pg_msg hash with pg message properties
sub process_sync {
	# my $self = shift;
	# my $pg_msg = shift;
	# Nothing to do...yet
}

## handle command X (terminate)
# @param $pg_msg hash with pg message properties
sub process_disconnect {
	# my $self = shift;
	# my $pg_msg = shift;
	# Nothing to do...yet
}

## handle command CancelRequest (F)
# @param $pg_msg hash with pg message properties
sub process_cancel_request {
	# my $self = shift;
	# my $pg_msg = shift;
	# Nothing to do...yet
}

## handle command SSLRequest (F)
# @param $pg_msg hash with pg message properties
sub process_ssl_request {
	# my $self = shift;
	# my $pg_msg = shift;
	# Nothing to do...yet
}

## handle command StartupMessage (F)
# @param $pg_msg hash with pg message properties
sub process_startup_message {
	# my $self = shift;
	# my $pg_msg = shift;
	# Nothing to do...yet
}

sub DESTROY {
	my $self = shift;

# we could do something funnier like this trivial report...
# 	print "$normalized->{$_}->{count} :\n$normalized->{$_}->{query}\n\n"
# 		foreach (keys %{ $normalized });

	debug(1, "-- normalize: Number of normalized queries found: ". scalar(keys %{ $self->{'normalized'} }) ."\n");
}

1;

