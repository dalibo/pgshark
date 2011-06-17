##
# This program is open source, licensed under the simplified BSD license.  For license terms, see the LICENSE file.
##
package Sql;

use strict;
use warnings;
use pgShark::Utils;
use Net::Pcap qw(:functions);
use Data::Dumper;
use Getopt::Long;
use POSIX;

use Exporter;
our $VERSION = 0.1;
our @ISA = ('Exporter');
our @EXPORT = qw/getCallbacks getFilter Bind Close Execute Parse Query StartupMessage Terminate/;
our @EXPORT_OK = qw/getCallbacks getFilter Bind Close Execute Parse Query StartupMessage Terminate/;

## TODO
#  * support cursors ?
#  * add support for COPY
#  * add support of an optional parameterizable line prefix

my %args = (
	'line_prefix' => ''
);

Getopt::Long::Configure('bundling');
GetOptions(\%args, qw{
	line_prefix=s
});

my $prefix = '';
my @prefix_keys;

if ($args{'line_prefix'} ne '') {
	$prefix = $args{'line_prefix'};
	push @prefix_keys, '%a' if ($prefix =~ /%a/);
	push @prefix_keys, '%d' if ($prefix =~ /%d/);
	push @prefix_keys, '%H' if ($prefix =~ /%H/);
	push @prefix_keys, '%h' if ($prefix =~ /%h/);
	push @prefix_keys, '%k' if ($prefix =~ /%k/);
	push @prefix_keys, '%R' if ($prefix =~ /%R/);
	push @prefix_keys, '%r' if ($prefix =~ /%r/);
	push @prefix_keys, '%T' if ($prefix =~ /%T/);
	push @prefix_keys, '%t' if ($prefix =~ /%t/);
	push @prefix_keys, '%u' if ($prefix =~ /%u/);
}

sub getCallbacks {
	return {
		'Bind' => \&Bind,
		'Close' => \&Close,
		'Execute' => \&Execute,
		'Parse' => \&Parse,
		'Query' => \&Query,
		'StartupMessage' => \&StartupMessage,
		'Terminate' => \&Terminate
	};
}

sub getFilter {
	my $host = shift;
	my $port = shift;
	return "(tcp and dst port $port) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
}

# Hash for sessions properties
# $sess = {
#   $session hash$ => {
#     'user' => username,
#     'database' => database
# }}
my %sess;

# Hash of prepared stmt
# $prepd = {
#   $session hash$ => {
#     $prepared name$ => {
#       'query' => SQL query
#       'portals' => {
#         $portal name$ = @params
#       }
#   }
# }
my $prepd = {};

# Hash of portals
# either cursors or binded prepd stmt
# $portals = {
#   $session hash$ => {
#     $portal name$ => the name of the associated prepd stmt
#   }
# }
my $portals = {};

##
# behave like printf, but takes $pg_msg as second argument,
# compute the line_prefix if any and prefix the output with it
# @param $frmt
# @param $pg_msg
# @params vars, ...
sub printf_prefix {
	my $output = shift;
	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{'sess_hash'};
	my $prefix_output = $prefix;

	unless ($prefix eq '') {
		foreach (@prefix_keys) {
			if (/%a/) {
				if (defined $sess{$sess_hash}{'application_name'}) {
					$prefix_output =~ s/%a/$sess{$sess_hash}{'application_name'}/ge;
				}
				else {
					$prefix_output =~ s/%a/?/g;
				}
			}
			elsif (/%d/) {
				if (defined $sess{$sess_hash}{'database'}) {
					$prefix_output =~ s/%d/$sess{$sess_hash}{'database'}/ge;
				}
				else {
					$prefix_output =~ s/%d/?/g;
				}
			}
			elsif (/%k/) {
				$prefix_output =~ s/%k/$sess_hash/ge;
			}
			elsif (/%H/) {
				my $src_ip = dec2dot($pg_msg->{'tcpip'}->{'src_ip'});
				$prefix_output =~ s/%H/$src_ip/ge;
			}
			elsif (/%h/) {
				my $dest_ip = dec2dot($pg_msg->{'tcpip'}->{'dest_ip'});
				$prefix_output =~ s/%h/$dest_ip/ge;
			}
			elsif (/%R/) {
				my $src_ip = dec2dot($pg_msg->{'tcpip'}->{'src_ip'});
				$prefix_output =~ s/%R/"$src_ip:$pg_msg->{'tcpip'}->{'src_port'}"/ge;
			}
			elsif (/%r/) {
				my $dest_ip = dec2dot($pg_msg->{'tcpip'}->{'dest_ip'});
				$prefix_output =~ s/%r/"$dest_ip:$pg_msg->{'tcpip'}->{'dest_port'}"/ge;
			}
			elsif (/%T/) {
				$prefix_output =~ s/%T/$pg_msg->{'timestamp'}/ge;
			}
			elsif (/%t/) {
				$prefix_output =~ s/%t/strftime('%Y-%m-%d %H:%M:%S', localtime $pg_msg->{'timestamp'})/ge;
			}
			elsif (/%u/) {
				if (defined $sess{$sess_hash}{'user'}) {
					$prefix_output =~ s/%u/$sess{$sess_hash}{'user'}/ge;
				}
				else {
					$prefix_output =~ s/%u/?/g;
				}
			}
		}
		print $prefix_output;
	}

	printf "$output", @_;
}

sub deallocate {
	my $pg_msg = shift;
	printf_prefix "DEALLOCATE %s;\n", $pg_msg, shift;
}

# We cannot use unnamed prepd stmt in SQL.
# As we cannot have more than one unnamed prepd stmt
# per session, we create a name for them based
# on their session properties
sub prep_name {
	my ($name, $hash) = @_;
	return ($name eq '') ? "anon$hash" : $name;
}

## handle command B
# @param $pg_msg hash with pg message properties
sub Bind {
	my $pg_msg = shift;
	my @params;
	my $sess_hash = $pg_msg->{'sess_hash'};

	debug(2, "SQL: call process_bind\n");

	my $prepname = prep_name($pg_msg->{'name'}, $sess_hash);
	my $portalname = prep_name($pg_msg->{'portal'}, $sess_hash);

	if (defined($prepd->{$sess_hash}->{$prepname})) {

		# We need to wait until the first BIND to know the number of params before actually issue a PREPARE
		# query. If understood correctly from the doc, even prepd stmt without args must be binded,
		# so this piece of code will be executed for all prepd stmt.
		# If never binded, there's no portals, so execute the PREPARE stmt as it wasn't prepd yet
		if (not scalar(keys %{$prepd->{$sess_hash}->{$prepname}->{'portals'} })) {

			printf_prefix "PREPARE %s ", $pg_msg, $prepname;

			# print parameters: we use "unknown" as we can not know
			# args types
			if ($pg_msg->{'num_params'}) {
				printf '(%s) ', substr('unknown,'x$pg_msg->{'num_params'},0,-1);
			}

			printf "AS %s;\n", $prepd->{$sess_hash}->{$prepname}->{'query'};
		}
	}
	else {
		# we might be trying to bind to a prepd stmt parsed before the network dump started
		# we should probably send some debug message about it...
		return;
	}

	## TODO
	# mess with text/binary format !
	# cf. @params_formats and http://www.postgresql.org/docs/9.0/interactive/protocol-message-formats.html
	# @ Bind (F) :
	# [...]
	# Int16
	#
	# The number of parameter format codes that follow (denoted C below). This can be zero to indicate that there are
	# no parameters or that the parameters all use the default format (text); or one, in which case the
	# specified format code is applied to all parameters; or it can equal the actual number of parameters.
	#
	# Int16[C]
	#
	# The parameter format codes. Each must presently be zero (text) or one (binary).

	## escape params
	# copy the params array instead of direct using the reference

	foreach my $param (@{$pg_msg->{'params'}}) {
		if (defined $param) {
			$param =~ s/'/''/g;
			push @params, "'$param'";
		}
		else {
			push @params, 'NULL';
		}
	}

	$portals->{$sess_hash}->{$portalname} = $prepname;
	$prepd->{$sess_hash}->{$prepname}->{'portals'}->{$portalname} = [ @params ];
}

## handle command C
# @param $pg_msg hash with pg message properties
sub Close {
	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{'sess_hash'};

	debug(2, "SQL: call process_close\n");

	my $prepname = prep_name($pg_msg->{'name'}, $sess_hash);

	# we ignore closing portals as it doesn't make sense in SQL
	if ($pg_msg->{'kind'} eq 'S') {
		deallocate($pg_msg, $prepname);
		foreach my $portal (keys %{ $prepd->{$sess_hash}->{$prepname}->{'portals'} }) {
			delete $portals->{$sess_hash}->{$portal};
		}
		delete $prepd->{$sess_hash}->{$prepname};
	}
}

## handle command E
# @param $pg_msg hash with pg message properties
#
# Here, we can saftly ignore nb_rows as there's no way to use
# portals in SQL but with the simple query protocol
sub Execute {
	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{'sess_hash'};

	debug(2, "SQL: call process_execute\n");

	my $portalname = prep_name($pg_msg->{'name'}, $sess_hash);

	if (defined ($portals->{$sess_hash}->{$portalname})) {
		my $prepname = $portals->{$sess_hash}->{$portalname};
		printf_prefix "EXECUTE %s", $pg_msg, $prepname;
		printf "(%s)", join (',', @{ $prepd->{$sess_hash}->{$prepname}->{'portals'}->{$portalname} })
			if (scalar(@{ $prepd->{$sess_hash}->{$prepname}->{'portals'}->{$portalname} }));
		printf ";\n";
	}
	else {
		# we might be trying to execute a prepd stmt parsed before the network dump
		# we should probably send some debug message about it...
		return;
	}
}

## handle P command
# @param $pg_msg hash with pg message properties
sub Parse {
	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{'sess_hash'};

	debug(2, "SQL: call process_parse (name, query) = ('$pg_msg->{'name'}', $pg_msg->{'query'})\n");

	my $prepname = prep_name($pg_msg->{'name'}, $sess_hash);

	# we can only have one anonymous prepd stmt per session, deallocate previous anonym xact
	# note: trying to parse using an existing name shoudl rise an error. We doesn't test
	# this case here as if the session did it, it received an error as well.
	if (($pg_msg->{'name'} eq '') and (defined $portals->{$sess_hash}->{$prepname})) {
		deallocate($pg_msg, $prepname);
		foreach my $portal (keys %{ $prepd->{$sess_hash}->{$prepname}->{'portals'} }) {
			delete $portals->{$sess_hash}->{$portal};
		}
		delete $prepd->{$sess_hash}->{$prepname};
	}

	# save the prepd stmt for this session
	$prepd->{$sess_hash}->{$prepname}->{'query'} = $pg_msg->{'query'};
}

## handle command Q
# @param $pg_msg hash with pg message properties
sub Query {
	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{'sess_hash'};

	debug(2, "SQL: call process_query\n");

	printf_prefix "%s;\n", $pg_msg, $pg_msg->{'query'};
}

## handle command StartupMessage (F)
# @param $pg_msg hash with pg message properties
sub StartupMessage {
	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{'sess_hash'};

	$sess{$sess_hash}{'user'} = $pg_msg->{'params'}->{'user'};
	$sess{$sess_hash}{'database'} = $pg_msg->{'params'}->{'database'};
	$sess{$sess_hash}{'application_name'} = $pg_msg->{'params'}->{'application_name'}
		if defined $pg_msg->{'params'}->{'application_name'};
}

## handle command X
# @param $pg_msg hash with pg message properties
sub Terminate {
	# release all prepd stmt

	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{'sess_hash'};

	debug(2, "SQL: call process_disconnect\n");

	delete $prepd->{$sess_hash};
}

1;
