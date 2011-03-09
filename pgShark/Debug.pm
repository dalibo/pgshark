package Debug;

use strict;
use warnings;
use pgShark::Utils;
use Net::Pcap qw(:functions);

## TODO
#  * ...

sub new {
	my $class = shift;
	my $args = shift;
	my $pcap = shift;

	my $self = {
	};

	debug(1, "Debug: Plugin loaded.\n");

	return bless($self, $class);
}

# prints formated trace with mandatored fields
sub output {
	my $self = shift;
	my $pg_msg = shift;
	my $format = shift;
	printf("Packet: t=%s, session=%s\n", $pg_msg->{'timestamp'}, $pg_msg->{'sess_hash'});
	printf("PGSQL: type=%s, len=%d\n", $pg_msg->{'type'}, $pg_msg->{'len'});
	printf("$format", @_);
}

# handle F(C) command (close)
# @param $pg_msg hash with pg message properties
sub deallocate {
	my $self = shift;
	my $pg_msg = shift;

	$self->output($pg_msg, "DEALLOCATE type=%s, name=%s\n\n", $pg_msg->{'type'}, $pg_msg->{'name'});
}

## handle P command (parse)
# @param $pg_msg hash with pg message properties
sub process_parse {
	my $self = shift;
	my $pg_msg = shift;

	$self->output($pg_msg, "PARSE name=%s, query=%s, num_params=%d, params_type=%s\n\n",
		$pg_msg->{'name'}, $pg_msg->{'query'}, $pg_msg->{'num_params'}, join(',', $pg_msg->{'params_types'})
	);
}

## handle command F(B) (bind)
# @param $pg_msg hash with pg message properties
sub process_bind {
	my $self = shift;
	my $pg_msg = shift;

	$self->output($pg_msg, "BIND portal=%s, name=%s, num_formats=%d, formats=%s, num_params=%d, params=%s\n\n",
		$pg_msg->{'portal'}, $pg_msg->{'name'}, $pg_msg->{'num_formats'}, join(',', $pg_msg->{'params_types'}),
		$pg_msg->{'num_params'}, join(',', $pg_msg->{'params'})
	);
}

## handle command F(E) (execute)
# @param $pg_msg hash with pg message properties
sub process_execute {
	my $self = shift;
	my $pg_msg = shift;

	$self->output($pg_msg, "EXECUTE name=%s, nb_rows=%d\n\n", $pg_msg->{'name'}, $pg_msg->{'nb_rows'});
}

## handle command F(C) (close)
# @param $pg_msg hash with pg message properties
sub process_close {
	my $self = shift;
	my $pg_msg = shift;

	$self->output($pg_msg, "CLOSE type=%s, name=%s\n\n", $pg_msg->{'type'}, $pg_msg->{'name'});
}

## handle command F(Q) (query)
# @param $pg_msg hash with pg message properties
sub process_query {
	my $self = shift;
	my $pg_msg = shift;

	$self->output($pg_msg, "QUERY query=%s\n\n", $pg_msg->{'query'});
}

## handle command F(X) (terminate)
# @param $pg_msg hash with pg message properties
sub process_disconnect {
	my $self = shift;
	my $pg_msg = shift;

	$self->output($pg_msg, "DISCONNECT\n\n");
}

## handle command F(S) (sync)
# @param $pg_msg hash with pg message properties
sub process_sync {
	my $self = shift;
	my $pg_msg = shift;

	$self->output($pg_msg, "SYNC\n\n");
}

## handle command B(X) (command complete)
# @param $pg_msg hash with pg message properties
sub process_command_complete {
	my $self = shift;
	my $pg_msg = shift;

	$self->output($pg_msg, "COMMAND COMPLETE command=%s\n\n", $pg_msg->{'command'});
}

## handle command B(Z) (ready for query)
# @param $pg_msg hash with pg message properties
sub process_ready {
	my $self = shift;
	my $pg_msg = shift;

	if ($pg_msg->{'status'} eq 'I') {
		$self->output($pg_msg, "READY FOR QUERY type=<IDLE>\n\n");
	}
	elsif ($pg_msg->{'status'} eq 'T') {
		$self->output($pg_msg, "READY FOR QUERY type=<IDLE> in transaction\n\n");
	}
	elsif ($pg_msg->{'status'} eq 'E') {
		$self->output($pg_msg, "READY FOR QUERY type=<IDLE> in transaction (aborted)\n\n");
	}
}

sub DESTROY {
	my $self = shift;
#	debug(1, "Xxx: output something usefull here ?\n");
}

1;
