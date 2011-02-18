package SQL;
use strict;
use warnings;

## TODO
#  * Portal support (cursors)
#    we will have to convert portal to plain SQL queries (as we do with prepd stmt)

use Exporter;
our $VERSION = 0.1;
our @ISA = ('Exporter');
our @EXPORT = qw/process_parse process_bind process_execute process_close process_query process_disconnect/;

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
# @param $sessions hash of all current clients sessions 
# @param $sess_hash hash of the current processed session
sub process_parse {
	my ($sessions, $sess_hash) = @_;
	my $msg = substr($sessions->{$sess_hash}->{data}, 5, $sessions->{$sess_hash}->{pg_len} - 4);
	
	my ($name, $query, $num_params, @params_types) = unpack('Z*Z*nN*', $msg);
	
	my $prepname = prep_name($name, $sess_hash);
	
	# we can only have one anonymous prepd stmt per session, deallocate previous anonym xact
	if (($name eq '') and (defined $prepd->{$sess_hash}->{$prepname})) {
		deallocate($prepname) if $prepd->{$sess_hash}->{$prepname}->{is_parsed};
		undef $prepd->{$sess_hash};
	}

	# save the prepd stmt for this session
	$prepd->{$sess_hash}->{$prepname} = {
		query => $query,
		# we don't know exactly how many params we'll have when parsing
		# so we delay the PREPARE query to the first BIND
		is_parsed => 0,
	}
}


## handle command B (bind)
# @param $sessions hash of all current clients sessions 
# @param $sess_hash hash of the current processed session
# message:
#   name=String
#   portal=String 
#   nb_formats=int16 
#   formats[]=int16[nb_formats] 
#   nb_params=int16 
#   params[]=(len=int32,value=char[len])[nb_params]
sub process_bind {
	my ($sessions, $sess_hash) = @_;
	my ($portal, $name, $num_formats, $num_params, @params_formats, @params);

	my $msg = substr($sessions->{$sess_hash}->{data}, 5, $sessions->{$sess_hash}->{pg_len} - 4);
	
	($portal, $name, $num_formats) = unpack('Z* Z* n', $msg);

	# we add 1 bytes for both portal and name that are null-terminated
	# + 2 bytes of int16 for $num_formats
	$msg = substr($msg, length($portal)+1 + length($name)+1 +2);

	# catch formats and the $num_params as well
	@params_formats = unpack("n$num_formats n", $msg);
	$msg = substr($msg, ($num_formats+1) * 2);

	$num_params = pop @params_formats;
	
	for (my $i=0; $i < $num_params; $i++) {
		# unpack hasn't 32bit signed network template, so we use l>
		my ($len) = unpack('l>', $msg);
		
		# if len < 0; the value is NULL
		if ($len > 0) {
			my $val = unpack("x4 a$len", $msg);
			# escape quotes
			$val =~ s/'/''/g;
			push @params, "'$val'";
			$msg = substr($msg, 4 + $len);
		}
		elsif ($len == 0) {
			push @params, "''";
			$msg = substr($msg, 4);
		}
		else { # value is NULL
			push @params, 'NULL';
			$msg = substr($msg, 4);
		}
		
	}
	
	my $prepname = prep_name($name, $sess_hash);
	
	if (defined($prepd->{$sess_hash}->{$prepname})) {

		# execute the PREPARE stmt if it wasn't prepd yet
		if (not $prepd->{$sess_hash}->{$prepname}->{is_parsed}) {

			printf "PREPARE %s ", $prepname;

			# print parameters: we use unknown as we can not know 
			# args types in SQL mode.
			if ($num_params) {
				printf '(%s) ', substr('unknown,'x$num_params,0,-1);
			}
			
			printf "AS %s;\n", $prepd->{$sess_hash}->{$prepname}->{query};
			$prepd->{$sess_hash}->{$prepname}->{is_parsed} = 1;
		}
	}
	else {
		# we might be trying to bind to a query parsed before the tcpdump
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
	$prepd->{$sess_hash}->{$prepname}->{vals} = [@params] ;
}

## handle command E (execute)
# @param $sessions hash of all current clients sessions 
# @param $sess_hash hash of the current processed session
#
# Here, we can saftly ignore nb_rows as there's no way to use 
# portals in SQL but with the simple query protocol
#
# message:
#   name=String
#   nb_rows=int32
sub process_execute {
	my ($sessions, $sess_hash) = @_;
	my ($name,$nb_rows);

	my $msg = substr($sessions->{$sess_hash}->{data}, 5, $sessions->{$sess_hash}->{pg_len} - 4);
	
	($name,$nb_rows) = unpack('Z*N', $msg);
	my $prepname = prep_name($name, $sess_hash);
	
	printf "EXECUTE %s", $prepname;
	printf "(%s)", join (',', @{ $prepd->{$sess_hash}->{$prepname}->{vals} }) if defined $prepd->{$sess_hash}->{$prepname}->{vals};
	printf ";\n";
}

## handle command C (close)
# @param $sessions hash of all current clients sessions 
# @param $sess_hash hash of the current processed session
#
# Here, we can saftly ignore nb_rows as there's no way to use 
# portals in SQL but with the simple query protocol
#
# message:
#   type=char
#   name=String
sub process_close {
	my ($sessions, $sess_hash) = @_;
	my $msg = substr($sessions->{$sess_hash}->{data}, 5, $sessions->{$sess_hash}->{pg_len} - 4);
	
	my ($type, $name) = unpack('AZ*', $msg);
	
	my $prepname = prep_name($name, $sess_hash);

	if ($type eq 'S') {
		deallocate($prepname);
	}
}

## handle command Q (query)
# @param $sessions hash of all current clients sessions 
# @param $sess_hash hash of the current processed session
# message:
#    query=String
sub process_query {
	my ($sessions, $sess_hash) = @_;
	
	# we remove the last char:
	# query are null terminated in pgsql proto and pg_len includes it
	my $query = substr($sessions->{$sess_hash}->{data}, 5, -1);
	
	printf "%s;\n", $query;
}

## handle command X (terminate)
# @param $sessions hash of all current clients sessions 
# @param $sess_hash hash of the current processed session
sub process_disconnect {
	# release all prepd stmt
	
	my ($sessions, $sess_hash) = @_;
	
	delete $prepd->{$sess_hash};
}

1;
