package pgShark::Utils;
use strict;
use warnings;

use Exporter;
our $VERSION = 0.1;
our @ISA = ('Exporter');
our @EXPORT = qw/debug set_debug/;

my $debug_lvl = 0;

sub set_debug {
	my $lvl = shift;
	$debug_lvl = $lvl;

	debug(1, "debug level set to $debug_lvl.\n");
}

sub debug {
	my $lvl = shift;
	my $format = shift;
	printf(STDERR $format, @_) if $debug_lvl >= $lvl;
}

1
