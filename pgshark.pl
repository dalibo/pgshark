#!/usr/bin/perl
##
# This program is open source, licensed under the simplified BSD license.  For license terms, see the LICENSE file.
##

use strict;
use warnings;

#use Net::TcpDumpLog;
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
	'2' => 0,
	'3' => 0
);

Getopt::Long::Configure('bundling');
GetOptions(\%args, qw{
	debug|d+
	help
	interface|i=s
	output|o=s
	host|h=s
	port|p=s
	read|r=s
	2+
	3+
}) or usage();

longusage() if ($args{'help'});

usage("Argument --output is mandatory.\n") if $args{'output'} eq '';
usage("Options -2 and -3 are mutal exclusives.\n") if $args{'2'} and $args{'3'};

usage("Arguments --interface and --read are incompatible.\nEither listen from the networkor open a pcap file.\n")
	if $args{'interface'} ne '' and $args{'read'} ne '';

$args{'output'} = ucfirst lc $args{'output'};

if ($args{'2'}) {
	$args{'protocol'} = 2;
}
else {
	$args{'protocol'} = 3;
}

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
	'port' => $args{'port'},
	'protocol' => $args{'protocol'}
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

=item pgshark.pl [--debug] [-2|-3] [--read file] {--output plugin_name} [-- [plugin options...]]

Where B<plugin_name> could be I<sql> or I<normalize> or I<debug> or I<fouine>.

=back

=head1 DESCRIPTION

This program studies PostgreSQL traffic captured from the network and is able to make various things with it. The network
dump could be live or from a pcap file (using tcpdump for instance).

B<pgshark> comes with various output plugins able to do various things with these network dumps.

=over 2

=item B<-d>, B<--debug>

Print debug informations to the standart error. The more you repeat this option, the more verbose B<pgshark> will be.
There are 3 levels of debug presently.

=item B<--help>

Show this help message and exit.

=item B<-2>

Dissect the pcap flow using PostgreSQL v2.0 protocol.

=item B<-3>

Dissect the pcap flow using PostgreSQL v3.0 protocol. This is the default.

=item B<-h>, B<--host> <ip address>

Gives the IP address of the PostgreSQL server. By default, set to 127.0.0.1.

=item B<-i>, B<--interface> <interface name>

Capture PostgreSQL traffic directly from the given network interface. Conflict with B<--read>.
By default, B<pgshark> will read from stdin if neither B<--read> or B<--interface> are given.

=item B<-o>, B<--output> <plugin name>

Select the dump processing output plugin. This parameter value is case-insensitive
(eg. SQL, Sql and sql will all select the SQL plugin output).
See section L</PLUGINS>.

=item B<-p>, B<--port> <port>

Specifies the port the PostgreSQL backend is listening on. By default, set to 5432

=item B<-r>, B<--read> <path to file>

Read PostgreSQL traffic from given pcap file. Conflict with B<--interface>.
By default, B<pgshark> will read from stdin if neither B<--read> or B<--interface> are given.

=back

=head1 PLUGINS

=head2 B<debug>

The B<debug> plugin will output the PostgreSQL messages in human readable format. Useful to analyze what is in a network
dump before using pgshark on some other duties.

=head2 B<sql>

The B<sql> plugin writes captured queries on stdout. Because of the SQL language doesn't support unnamed prepared
statement, this plugin actually try to names them. Presently, this plugin doesn't support cursors nor COPY messages.

=over 2

=item B<--line_prefix> <prefix string>

This is a printf-style string that is output at the beginning of each line. % characters begin "escape sequences" that
are replaced with status information as outlined below. Unrecognized escapes are ignored.
Other characters are copied straight to the log line. Some escapes might not be available depending on the context.

=over 3

=item B<%a>
Application name

=item B<%d>
Database name

=item B<%H>
Source host

=item B<%h>
Destination host

=item B<%k>
Hash key of the session (src ip and src port concatenated)

=item B<%R>
Source host and port

=item B<%r>
Destination host and port

=item B<%T>
Raw timestamp

=item B<%t>
Human readable timestamp

=item B<%u>
User name

=back

=back

=head2 B<normalize>

The B<normalize> plugin will try to normalize queries and prepared queries and output them to stdout. Its purpose is to give you a list
of unique queries, whatever the number of time they have been sent by clients and whatever their parameters were.

=head2 B<fouine>

The B<fouine> plugin will output a report with most popular queries, slowest cumulated ones, slowest queries ever,
classification of queries by type, etc.

=head1 EXAMPLES

=over 2

=item Output all queries found in files C<some_capture.pcap*> as SQL to the standart output:

C<cat some_capture.pcap* | pgshark.pl --output SQL>

=item Output all queries found in file C<some_capture.pcap001> as SQL to the standart output.

C<pgshark.pl --output SQL -r some_capture.pcap001>

=item Capture PostgreSQL traffic from interface eth0 and output normalized queries to the standart output.

C<pgshark.pl --output normalize -i eth0>

=item The following example shows how to work with a server that is B<NOT> listening on localhost and the default 5432 port. (1)
dump from C<eth0> every packets from/to the port 5490. C<-s 0> is requiered on some older version of tcpdump to dump
the whole packets. (2) use the SQL plugin with its C<--line_prefix> option. Here C<--host> and C<--port> are
B<important> to notify pgshark who is the PostgreSQL server in the network dump and its working port.

=over 3

=item C<tcpdump -i eth0 -w /tmp/tcp_5490.pcap -s 0 'tcp and port 5490'> (1)

=item C<pgshark.pl --port 5490 --host 192.168.42.5 --output SQL -r /tmp/tcp_5490.pcap -- --line_prefix "%t user=%u,database=%d: "> (2)

=back

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
