##
# This program is open source, licensed under the simplified BSD license.  For license terms, see the LICENSE file.
##
package Normalize;

use strict;
use warnings;
use Digest::MD5 qw(md5_base64);
use Net::Pcap qw(:functions);
use pgShark::Utils;
use Data::Dumper;
use Getopt::Long;

use Exporter;
our $VERSION = 0.1;
our @ISA = ('Exporter');
our @EXPORT = qw/$callbacks $filter getCallbacks getFilter Parse Query/;
our @EXPORT_OK = qw/$callbacks $filter getCallbacks getFilter Parse Query/;

## TODO
#  * support parameters in extended protocol
#  * add some option to control what we want to catch:
#   * queries ? prepd stmt ? portals ? ALL (deallocate as instance ?) ??
#   * support $str$strings here$str$ notation

my %args = (
	'output-queries' => undef,
	'output-norm' => undef
);

my $OUT_NORM;
my $OUT_RAW = undef;

Getopt::Long::Configure('bundling');
GetOptions(\%args, qw{
	output-queries|O=s
	output-norm|o=s
});

if (defined $args{'output-norm'}) {

	$args{'output-norm'} = '&STDOUT' if $args{'output-norm'} eq '-';

	open($OUT_NORM, ">$args{'output-norm'}")
		or die("Can not open file $args{'output-norm'}: $!");
}
else {
	open($OUT_NORM, '>&STDOUT');
}

if (defined $args{'output-queries'}) {

	$args{'output-queries'} = '&STDOUT' if $args{'output-queries'} eq '-';

	open($OUT_RAW, ">$args{'output-queries'}")
		or die("Can not open file $args{'output-queries'}: $!");
}

my $normalized = {};

sub getCallbacks {
	return {
		'Parse' => \&Parse,
		'Query' => \&Query
	};
}

sub getFilter {
	my $host = shift;
	my $port = shift;
	return "(tcp and dst port $port) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
}

## 
# normalize query and record them in the $normalized hash
# @return the hash of the query
sub normalize {
	my $query = shift;

	$query = normalize_query($query);

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

## handle P command
# @param $pg_msg hash with pg message properties
sub Parse {
	# maybe we should do something fancier ?
	my $pg_msg = shift;

	my $query_hash = normalize($pg_msg->{query});

	if ($normalized->{$query_hash}->{count} == 1) {
		print $OUT_NORM "PREPARE xxx(...) AS $normalized->{$query_hash}->{query}\n\n";
		print $OUT_RAW "$pg_msg->{query}\n\n" if defined $OUT_RAW;
	}
}

## handle command Q
# @param $pg_msg hash with pg message properties
sub Query {
	my $pg_msg = shift;

	my $query_hash = normalize($pg_msg->{query});

	if ($normalized->{$query_hash}->{count} == 1) {
		print $OUT_NORM "$normalized->{$query_hash}->{query}\n\n";
		print $OUT_RAW "$pg_msg->{query}\n\n" if defined $OUT_RAW;
	}
}

sub END {
	my $self = shift;

# we could do something funnier like this trivial report...
# 	print "$normalized->{$_}->{count} :\n$normalized->{$_}->{query}\n\n"
# 		foreach (keys %{ $normalized });

	debug(1, "-- normalize: Number of normalized queries found: ". scalar(keys %{ $normalized }) ."\n");
}

1;
