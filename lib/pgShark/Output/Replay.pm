##
# This program is open source, licensed under the simplified BSD license.  For license terms, see the LICENSE file.
##
package pgShark::Output::Replay;

use strict;
use warnings;
use pgShark qw(parse_v3);
use pgShark::Utils;
use Net::Pcap qw(:functions);
use Data::Dumper;
use Getopt::Long;
use IO::Socket;
use IO::Select;

use Exporter;
our $VERSION = 0.1;
our @ISA = ('Exporter');

our @EXPORT = qw/getCallbacks getFilter/;
our @EXPORT_OK = qw/getCallbacks getFilter/;

use constant READMAX => 2048;
use constant FROM_BACKEND => 1;

## TODO
# ...

my %args = (
	'rhost' => '/tmp',
	'rport' => 5432,
	'ruser' => 'postgres',
	'timeout' => 5,
);

Getopt::Long::Configure('bundling');
GetOptions(\%args, qw{
	rhost|rh=s
	rport|rp=s
	ruser|ru=s
	timeout|t=s
});

$args{'rhost'} = '/tmp' if $args{'rhost'} eq '';

debug (1, "Replay options:\n%s\n", Dumper(\%args));

my %sessions;
my $selects = new IO::Select();

sub getCallbacks {
	return {
		'AuthenticationOk' => \&openSocket,
		# 'AuthenticationKerberosV5' => \&Ignore,
		# 'AuthenticationCleartextPassword' => \&Ignore,
		# 'AuthenticationMD5Password' => \&Ignore,
		# 'AuthenticationSCMCredential' => \&Ignore,
		# 'AuthenticationGSS' => \&Ignore,
		# 'AuthenticationSSPI' => \&Ignore,
		# 'AuthenticationGSSContinue' => \&Ignore,
		# 'BackendKeyData' => \&Ignore,
		'Bind' => \&Replay,
		# 'BindComplete' => \&ReadFromBackend,
		'CancelRequest' => \&Replay,
		'Close' => \&Replay,
		# 'CloseComplete' => \&ReadFromBackend,
		# 'CommandComplete' => \&ReadFromBackend,
		'CopyData' => \&ReplayCopy,
		'CopyDone' => \&ReplayCopy,
		'CopyFail' => \&Replay,
		# 'CopyInResponse' => \&ReadFromBackend,
		# 'CopyOutResponse' => \&ReadFromBackend,
		# 'DataRow' => \&ReadFromBackend,
		'Describe' => \&Replay,
		# 'EmptyQueryResponse' => \&ReadFromBackend,
		# 'ErrorResponse' => \&ReadFromBackend,
		'Execute' => \&Replay,
		'Flush' => \&Replay,
		'FunctionCall' => \&Replay,
		# 'FunctionCallResponse' => sub {},
		# 'NoData' => \&ReadFromBackend,
		# 'NoticeResponse' => \&ReadFromBackend,
		# 'NotificationResponse' => \&ReadFromBackend,
		# 'ParameterDescription' => \&ReadFromBackend,
		# 'ParameterStatus' => \&ReadFromBackend,
		'Parse' => \&Replay,
		# 'ParseComplete' => undef,
		# 'PasswordMessage' => undef,
		# 'PortalSuspended' => undef,
		'Query' => \&Replay,
		# 'ReadyForQuery' => undef,
		# 'RowDescription' => undef,
		# 'SSLAnswer' => undef,
		# 'SSLRequest' => undef,
		'StartupMessage' => \&StartupMessage,
		'Sync' => \&Replay,
		'Terminate' => \&Terminate
	};
}

sub getFilter {
	my $host = shift;
	my $port = shift;
	return "(tcp and port $port) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
}

##
# 
# @returns 0 when ready, 1 when nothing happened
##
sub readFromBackend {
	my $sess_hash = shift;
	my $session = $sessions{$sess_hash};
	my $sock = $session->{'sock'};
	my $timeout = $args{'timeout'};
	my $count = READMAX;
	my $buff = '';
	my @ready;

	debug(1, "readFromBackend: on session %s.\n", $sess_hash);

	# TODO: better timeout handling
	TIMELOOP:while ($timeout) {
		@ready = $selects->can_read(1);

		foreach my $fh (@ready) {
			# our socket is ready to be readed
			last TIMELOOP if($fh == $sock);
		}
		debug(1, "readFromBackend: socket not ready (%d).\n", $timeout);
		sleep 1;
		$timeout--;
	}

	return 1 unless $timeout > 0;

	while($count == READMAX) {
		$count = sysread($sock, $buff, READMAX);
		if (defined $count) {
			debug(1, "  %d bytes readed.\n", $count);
			$session->{'data'} .= $buff;
		}
		# TODO must handle error on $count not defined
	}

	return 0;
}

##
# return next message
##
sub nextMessage {
	my $sess_hash = shift;
	my $session = $sessions{$sess_hash};
	my $buff = '';
	my $count = 0;
	my $pg_msg = {
		'type' => ''
	};

	$count = pgShark::parse_v3($pg_msg, FROM_BACKEND, $session->{'data'})
		unless $session->{'data'} eq '';

	return undef if $count == -1;

	if ($count == 0) {
		return undef if readFromBackend($sess_hash) == 1;

		$count = pgShark::parse_v3($pg_msg, FROM_BACKEND, $session->{'data'});
	}

	$session->{'data'} = substr($session->{'data'}, $count);
	debug(1, "nextMessage: Seen a %s as answer to %s.\n", $pg_msg->{'type'}, $sess_hash);

	return $pg_msg;
}

sub pg_connect {
	my $sess_hash = shift;
	my $sock = $sessions{$sess_hash}{'sock'};
	my $pg_msg;

	debug(1, "pg_connect: session %s\n", $sess_hash);

	## authentication
	my $msg = "user\0$args{'ruser'}\0database\0$sessions{$sess_hash}{'database'}\0\0";
	# TODO support protocol 2 ?
	$msg = pack("NNZ*Z*Z*Z*Z*", 8 + length($msg), 196608, "user", $args{'ruser'}, 
		"database", $sessions{$sess_hash}{'database'}, ""
	);
	$sock->send($msg);

	$pg_msg = nextMessage($sess_hash);

	return 1 if not defined $pg_msg
		or $pg_msg->{'type'} ne 'AuthenticationOk';

	do {
		$pg_msg = nextMessage($sess_hash);
	} while $pg_msg->{'type'} ne 'ReadyForQuery';

	return 0;
}

## handle command StartupMessage (F)
# @param $pg_msg hash with pg message properties
sub StartupMessage {
	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{'sess_hash'};

	debug(1, "StartupMessage: session %s.\n", $sess_hash);
	
	$sessions{$sess_hash}{'database'} = $pg_msg->{'params'}->{'database'};
}

## handle command B(R)
# @param $pg_msg hash with pg message properties
sub openSocket {
	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{'sess_hash'};

	debug (1, "openSocket: session %s\n", $sess_hash);

	# if we don't have information about the session opening, ignore it
	return unless defined $sessions{$sess_hash};

	if (substr($args{'rhost'}, 0, 1) eq '/') {
		my $sock_path = "$args{'rhost'}/.s.PGSQL.$args{'rport'}";

		debug (1, "  opening unix socket : «%s»\n", $sock_path);
		$sessions{$sess_hash}{'sock'} = IO::Socket::UNIX->new (
			'Type' => SOCK_STREAM,
			'Peer' => $sock_path
		);
	}
	else {
		debug (1, "  opening inet socket : «%s»\n", "tcp://$args{'rhost'}:$args{'rport'}");
		$sessions{$sess_hash}{'sock'} = IO::Socket::INET->new (
			'PeerAddr' => $args{'rhost'},
			'PeerPort' => $args{'rport'},
			'Proto' => 'tcp',
			'Blocking' => 0
		);
	}

	if (not $sessions{$sess_hash}{'sock'}) {
		debug(1, "  could not open socket for session %s. %s\n", $sess_hash, $!);
		delete $sessions{$sess_hash};
		return;
	}
	
	debug(1, "  socket for session %s.\n", $sess_hash);

	$selects->add($sessions{$sess_hash}{'sock'});

	$sessions{$sess_hash}{'data'} = '';
	
	if (pg_connect($sess_hash)) {
		debug(1, "  could not open pgsql session for $sess_hash.\n");
		delete $sessions{$sess_hash};
		return;
	}
	
	debug(1, "  pgsql session $sess_hash opened.\n");
}

## replay any kind of message
# @param $pg_msg hash with pg message properties
sub Replay {
	my $pg_msg = shift;
	my $pg_ans = shift;
	my $sess_hash = $pg_msg->{'sess_hash'};

	return unless defined $sessions{$sess_hash};

	debug(1, "Replay: replaying a '%s' for session $sess_hash.\n", $pg_msg->{'type'});

	my $sock = $sessions{$sess_hash}{'sock'};

	print $sock $pg_msg->{'data'};
	$sock->flush;

	do {
		$pg_ans = nextMessage($sess_hash);
	} while defined $pg_ans and $pg_ans->{'type'} ne 'ReadyForQuery';
}

## special callback to filter message availables for F OR B 
sub ReplayCopy {
	my $pg_msg = shift;
	
	return if $pg_msg->{'from_backend'};

	Replay($pg_msg);
}

## handle command F(X)
# @param $pg_msg hash with pg message properties
sub Terminate {
	my $pg_msg = shift;
	my $sess_hash = $pg_msg->{'sess_hash'};

	return unless defined $sessions{$sess_hash};

	my $sock = $sessions{$sess_hash}{'sock'};

	debug(1, "Terminate: session %s.\n", $sess_hash);

	print $sock $pg_msg->{'data'};
	$selects->remove($sock);
	$sock->close();
	delete $sessions{$sess_hash};
}

1;
