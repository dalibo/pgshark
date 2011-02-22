use strict;
use warnings;
use pgShark::Utils;

## TODO
#  * Portal support (cursors)
#    we will have to convert portal to plain SQL queries (as we do with prepd stmt)

use Exporter;
our $VERSION = 0.1;
our @ISA = ('Exporter');
our @EXPORT = qw/process_parse process_bind process_execute process_close process_query process_disconnect/;

BEGIN {
	debug(1, "sql: Plugin loaded.\n");
}

## hash handling prepd stmt for all sessions
# $prepd = {
# 	session hash => {
# 		prepd stmt name => query,
# 		prepd stmt name => query,
# 		...
# 	}
# }
my $prepd = {};

# handle C command (close) 
sub deallocate {
	printf "DEALLOCATE %s;\n", shift;
}

# We cannot use unnamed prepd stmt in SQL.
# As we cannot have more than one unnamed prepd stmt 
# per session, we create a name for them based
# on their session properties
sub prep_name {
	my ($name, $hash) = @_;
	return ($name eq '') ? "anon$hash" : $name;
}

## handle P command (parse)
# @param $pg_msg hash with pg message properties
sub process_parse {
	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{sess_hash};
	
	my $prepname = prep_name($pg_msg->{name}, $sess_hash);
	
	# we can only have one anonymous prepd stmt per session, deallocate previous anonym xact
	if (($pg_msg->{name} eq '') and (defined $prepd->{$sess_hash}->{$prepname})) {
		deallocate($prepname) if $prepd->{$sess_hash}->{$prepname}->{is_parsed};
		undef $prepd->{$sess_hash};
	}

	# save the prepd stmt for this session
	$prepd->{$sess_hash}->{$prepname} = {
		query => $pg_msg->{query},
		# we don't know exactly how many params we'll have when parsing
		# so we delay the PREPARE query to the first BIND
		is_parsed => 0,
	}
}


## handle command B (bind)
# @param $pg_msg hash with pg message properties
sub process_bind {
	my $pg_msg = shift;
	my @params;
	my $sess_hash = $pg_msg->{sess_hash};

	my $prepname = prep_name($pg_msg->{name}, $sess_hash);
	
	if (defined($prepd->{$sess_hash}->{$prepname})) {

		# execute the PREPARE stmt if it wasn't prepd yet
		if (not $prepd->{$sess_hash}->{$prepname}->{is_parsed}) {

			printf "PREPARE %s ", $prepname;

			# print parameters: we use unknown as we can not know 
			# args types in SQL mode.
			if ($pg_msg->{num_params}) {
				printf '(%s) ', substr('unknown,'x$pg_msg->{num_params},0,-1);
			}
			
			printf "AS %s;\n", $prepd->{$sess_hash}->{$prepname}->{query};
			$prepd->{$sess_hash}->{$prepname}->{is_parsed} = 1;
		}
	}
	else {
		# we might be trying to bind to a prepd stmt parsed before the tcpdump
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
	
	foreach my $param (@{$pg_msg->{params}}) {
		if (defined $param) {
			$param =~ s/'/''/g;
			push @params, "'$param'";
		}
		else {
			push @params, 'NULL';
		}
	}
	$prepd->{$sess_hash}->{$prepname}->{params} = [ @params ] ;

}

## handle command E (execute)
# @param $pg_msg hash with pg message properties
#
# Here, we can saftly ignore nb_rows as there's no way to use 
# portals in SQL but with the simple query protocol
sub process_execute {
	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{sess_hash};
	
	my $prepname = prep_name($pg_msg->{name}, $sess_hash);
	
	if (defined ($prepd->{$sess_hash}->{$prepname})) {		
		printf "EXECUTE %s", $prepname;
		printf "(%s)", join (',', @{ $prepd->{$sess_hash}->{$prepname}->{params} })
			if (scalar(@{ $prepd->{$sess_hash}->{$prepname}->{params} }));
		printf ";\n";
	}
	else {
		# we might be trying to bind to a prepd stmt parsed before the tcpdump
		# we should probably send some debug message about it...
		return;
	}
}

## handle command C (close)
# @param $pg_msg hash with pg message properties
#
# Here, we can saftly ignore nb_rows as there's no way to use 
# portals in SQL but with the simple query protocol 
sub process_close {
	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{sess_hash};
	
	my $prepname = prep_name($pg_msg->{name}, $sess_hash);

	if ($pg_msg->{type} eq 'S') {
		deallocate($prepname);
	}
}

## handle command Q (query)
# @param $pg_msg hash with pg message properties
sub process_query {
	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{sess_hash};
	
	printf "%s;\n", $pg_msg->{query};
}

## handle command X (terminate)
# @param $pg_msg hash with pg message properties
sub process_disconnect {
	# release all prepd stmt
	
	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{sess_hash};
	
	delete $prepd->{$sess_hash};
}

1;
