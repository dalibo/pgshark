use strict;
use warnings;
use Digest::MD5 qw(md5_base64);
use pgShark::Utils;

## TODO
#  add some option to control what we want to catch:
#   * queries ? prepd stmt ? portals ? ALL (deallocate as instance ?) ??
#   * add some query samples if asked by option (commented ?)
#   * support $str$strings here$str$ notation

use Exporter;
our $VERSION = 0.1;
our @ISA = ('Exporter');
our @EXPORT = qw/process_parse process_bind process_execute process_close process_query process_disconnect/;

BEGIN {
	debug(1, "normalize: Plugin loaded.\n");
}

## hash handling normalized queries
# $normalized = {
# 	query md5 hash => {
#		query => normalized query,
#		count => # of occurrences
# }
my $normalized = {};

## 
# normalize query and record them in the $normalized hash
# @return the hash of the query
sub normalize {
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

	if (not defined $normalized->{$query_hash}) {
		$normalized->{$query_hash} = {
			'query' => $query,
			'count' => 1
		};
	}
	else {
		$normalized->{$query_hash}->{count}++;
	}
	
	return $query_hash;
}

# handle C command (close)
# @param $pg_msg hash with pg message properties
sub deallocate {
	# Nothing to do...yet
}

## handle P command (parse)
# @param $pg_msg hash with pg message properties
sub process_parse {
	# maybe we should do something fancier ?
	my $pg_msg = shift;

	my $query_hash = normalize($pg_msg->{query});
	
	if ($normalized->{$query_hash}->{count} == 1) {
		print "PREPARE xxx(...) AS $normalized->{$query_hash}->{query}\n\n";
	}
}

## handle command B (bind)
# @param $pg_msg hash with pg message properties
sub process_bind {
	# Nothing to do...yet
}

## handle command E (execute)
# @param $pg_msg hash with pg message properties
sub process_execute {
	# Nothing to do...yet
}

## handle command C (close)
# @param $pg_msg hash with pg message properties
sub process_close {
	# Nothing to do...yet
}

## handle command Q (query)
# @param $pg_msg hash with pg message properties
sub process_query {
	my $pg_msg = shift;

	my $query_hash = normalize($pg_msg->{query});
	
	if ($normalized->{$query_hash}->{count} == 1) {
		print "$normalized->{$query_hash}->{query}\n\n";
	}
}

## handle command X (terminate)
# @param $pg_msg hash with pg message properties
sub process_disconnect {
	# Nothing to do...yet
}

END {
# we could do something funnier like this trivial report...
# 	print "$normalized->{$_}->{count} :\n$normalized->{$_}->{query}\n\n"
# 		foreach (keys %{ $normalized });

	debug(1, "-- normalize: Number of normalized queries found: ". scalar(keys %{ $normalized }) ."\n");
}

1;

