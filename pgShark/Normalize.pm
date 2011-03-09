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

	chomp $query;

	# remove bad escaped quotes in text so they are not in our way
	# for other cleaning stuffs. We'll take care of others '' later
	$query =~ s/\\'//g;
	# remove multi spaces
	$query =~ s/\s+/ /g;
	# empty text
	$query =~ s/'[^']*'/''/g;
	# remove all remaining '' (that were escaping ')
	# left behind the previous substitution
	$query =~ s/''('')+/''/g;
	# remove numbers
	$query =~ s/([^a-zA-Z0-9_\$-])-?([0-9]+)/${1}0/g;
	# remove hexa numbers
	$query =~ s/([^a-z_\$-])0x[0-9a-f]{1,10}/${1}0x/gi;
	# remove IN (values)
	$query =~ s/(IN\s*)\([^\)]*\)/${1}0x/gi;
	#rewrite params, some of them might have been drop in a IN parameter
	my $pi=1;
	$query =~ s/\$[0-9]+/'$'.$pi++/gie;

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
	# Nothing to do...yet
}

## handle command E (execute)
# @param $pg_msg hash with pg message properties
sub process_execute {
	# my $self = shift;
	# Nothing to do...yet
}

## handle command C (close)
# @param $pg_msg hash with pg message properties
sub process_close {
	# my $self = shift;
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

## handle command X (terminate)
# @param $pg_msg hash with pg message properties
sub process_disconnect {
	# my $self = shift;
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

