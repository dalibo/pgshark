#!/usr/bin/perl
##
# This program is open source, licensed under the simplified BSD license.  For license terms, see the LICENSE file.
##

use strict;
use warnings;

#use Net::TcpDumpLog;
use Net::Pcap qw(:functions);
use Net::Pcap::Reassemble;
use NetPacket::Ethernet qw(:types);
use NetPacket::IP qw(:protos);
use NetPacket::TCP;
use Data::Hexdumper;
use Data::Dumper;
use Getopt::Long;
use Pod::Usage;
use pgShark::Utils;
use pgShark::Core;

my $pckt = {};
my $pckt_num = 0;
my $sessions = {};
my $pcap;
# simple number of query processed
my $num_queries = 0;

sub usage {
	my $msg = shift;
	print "$msg\n" if defined $msg and $msg ne '';
	pod2usage(-exitval => 1);
}

sub longusage {
	pod2usage(-verbose => 2, -exitval => 1);
}

# get options
my %args = (
	'debug' => 0,
	'help' => 0,
	'interface' => '',
	'output' => '',
	'host' => '127.0.0.1',
	'port' => 5432,
	'read' => '',
);

Getopt::Long::Configure('bundling');
GetOptions(\%args, qw{
	debug|d+
	help
	interface|i=s
	output|o=s
	host|p=s
	port|p=s
	read|r=s
}) or usage();

longusage() if ($args{'help'});

usage("Argument --output is mandatory.\n") if $args{'output'} eq '';

usage("Arguments --interface and --read are incompatible.\nEither listen from the networkor open a pcap file.\n")
	if $args{'interface'} ne '' and $args{'read'} ne '';

$args{'output'} = ucfirst lc $args{'output'};

# check if given plugin name exist (avoid loading potential dangerous external unknown files)
usage("This output plugin does not exist.\n") if ( not (
	   ($args{'output'} eq 'Sql')
	or ($args{'output'} eq 'Normalize')
	or ($args{'output'} eq 'Debug')
	or ($args{'output'} eq 'Fouine')
));

# set debug level given in options
set_debug($args{'debug'});

debug (1, "Options:\n%s\n", Dumper(\%args));

# load the plugin package
require "./pgShark/$args{'output'}.pm";
$args{'output'}->import;

my $shark = pgShark::Core->new({
	'procs' => getCallbacks(),
	'host' => $args{'host'},
	'port' => $args{'port'}
});

## opening the pcap handler
# open a live capture on given interface
if ($args{'interface'} ne '') {
	my $err = '';

	if ($shark->live($args{'interface'}, \$err) > 0) {
		debug (0, "Can not open interface '%s':\n", $args{'interface'});
		die ($err);
	}
	debug(1, "Listening from network on interace '%s'.\n", $args{'interface'});
}
# we have no interface to listen on,
# either open given pcap file to read from or start reading from stdin
else {
	my $err = '';
	# read from stdin if no pcap file given
	$args{'read'} = '-' if $args{'read'} eq '';

	if ($shark->open($args{'read'}, \$err) > 0) {
		debug (0, "Can not read from file '%s':\n", $args{'read'});
		die ($err);
	}

	if ($args{'read'} eq '-') {
		debug(1, "Reading Pcap data from stdin.\n");
	}
	else {
		debug(1, "Reading from Pcap file '%s'.\n", $args{'read'});
	}
}

$shark->setFilter(getFilter($args{'host'}, $args{'port'}));

my $ret = $shark->process_all();

$shark->close();

=head1 pgshark.pl

pgshark.pl - Messing with PostgreSQL network traffic

=head1 SYNOPSIS

=over 2

=item pgshark.pl --help

=item pgshark.pl [--debug] [--read file] {--output plugin_name}

Where B<plugin_name> could be I<sql> or I<normalize> or I<debug> or I<fouine>.

=back

=head1 DESCRIPTION

This program study PostgreSQL traffic captured from the network and is able to make various things with it. The network
dump could be live or from a pcap file (usingtcpdump as instance).

B<pgshark> comes with various output plugins able to do various things with these network dumps.

=over 2

=item B<-d>, B<--debug>

Print debug informations to the standart error. The more you repeat this option, the more B<pgshark> will be verbose.
There is 3 level of debug presently.

=item B<--help>

Show this help message and exit.

=item B<-h>, B<--host> <ip address>

Gives the IP address of the PostgreSQL server. By default, set to 127.0.0.1.

=item B<--i>, B<--interface> <interface name>

Capture PostgreSQL traffic directly from the given network interface. Conflict with B<--read>.
By default, B<pgshark> will read from stdin if neither B<--read> or B<--interface> are given.

=item B<-o>, B<--output> <plugin name>

Select the dump processing output plugin. This parameter value is case-insensitive
(eg. SQL, Sql and sql will all select the SQL plugin output).
See section L</PLUGINS>.

=item B<-p>, B<--port> <port>

Gives the port the PostgreSQL backend is listening on. Be default, set to 5432

=item B<-r>, B<--read> <path to file>

Read PostgreSQL traffic from given pcap file. Conflict with B<--interface>.
By default, B<pgshark> will read from stdin if neither B<--read> or B<--interface> are given.

=back

=head1 PLUGINS

=over 2

=item B<sql>

The B<sql> plugin write captured queries on stdout. Because of limitation of SQL language it doesn't support unnamed
prepared statement, so it actually name them.

Presently, this plugin doesn't support cursors.

=item B<normalize>

The B<normalize> plugin will try to normalize queries and prepared queries and output them to stdoud. It aims to give you a list
of unique queries, however the number of time they has been send by clients and whatever their parameters were.

=item B<debug>

The B<debug> plugin will output the PostgreSQL messages in human readable format. Usefull to analyze what is in a network
dump before using pgshark on some other duties.

=item B<fouine>

The B<fouine> plugin will output a report with most popular queries, slowest cumulatives ones, slowest queries ever,
classification of queries by types, etc.

=back

=head1 EXAMPLES

=over 2

=item C<cat some_capture.pcap* | pgshark.pl --output SQL>

Output all queries found in files C<some_capture.pcap*> in SQL to the standart output.

=item C<pgshark.pl --output SQL -r some_capture.pcap001>

Output all queries found in file C<some_capture.pcap001> in SQL to the standart output.

=item C<pgshark.pl --output normalize -i eth0>

Capture PostgreSQL traffic from interface eth0 and output normalized queries to the standart output.

=back

=head1 AUTHORS

Jehan-Guillaume (ioguix) de Rorthais, jgdr at dalibo dot com.

Dalibo's team.

http://www.dalibo.org

=head1 SEE ALSO

The pgShark wiki on github : https://github.com/dalibo/pgshark/wiki

=head1 LICENSING

This program is open source, licensed under the simplified BSD license. For license terms, see the LICENSE provided
with the sources.

=cut
