# This program is open source, licensed under the simplified BSD license.  For
# license terms, see the LICENSE file.

#TODO
#  * catch INT/KILL signals to interrupt live capture
#  * optionally allow use of Net::Pcap::Reassemble, see sub process_all
#  * handling TCP seq counter overflow
#  * detect server ?

=head1 pgShark

pgShark - pgShark is a Perl module able to mess with PostgreSQL network traffic

=head1 SYNOPSIS

A simple exemple to count the number of connections and disconnections on
localhost, live version:

	use pgShark;
	
	my ($cnx, $dcnx) = (0, 0);
	my $dev = 'lo';
	my $err;
	
	$shark = pgShark->new({
		'procs' => {
			'AuthenticationOk' => sub {$cnx++},
			'Terminate' => sub {$dcnx++},
		},
		'host' => '127.0.0.1',
		'port' => 5432
	});
	
	die "Can not open interface $dev:\n$err" if $shark->live($dev, \$err);
	
	# on live capture, a ctrl-c interrupt the loop
	$shark->process_all();
	
	$shark->close();
	
	printf "Number of connections/disconnections: %u/%u\n", $cnx, $dcnx;

=head1 DESCRIPTION

This Perl module is able to study PostgreSQL traffic captured from a network
interface and call various functions for each messages of the protocol. The
network dump could be live or from a pcap file (using tcpdump as instance).

pgShark comes with various sample scripts able to do various things with these
network dumps. See help page of each of them for more informations.

=cut

package pgShark;

use strict;
use warnings;
use Net::Pcap qw(:functions);
use pgShark::Utils;
use POSIX ':signal_h';
use Math::BigInt;
use Exporter;
use Pod::Usage;
our $VERSION   = 0.1;
our @ISA       = ('Exporter');
our @EXPORT    = qw/parse_v2 parse_v3 PCAP_FILTER_TEMPLATE/;
our @EXPORT_OK = qw/parse_v2 parse_v3 PCAP_FILTER_TEMPLATE/;

# see tcpdump(8) section 'EXAMPLES'
use constant PCAP_FILTER_TEMPLATE =>

    # catch TCP traffic with given port
    '(tcp and port %s) and ( '

    # ignore packet with no data...
    . '(((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0) '

    # ...but the one with FIN or RST flags
    . 'or (tcp[tcpflags] & (tcp-fin|tcp-rst) != 0) ' . ')';

# "static" unique id over all created object
my $id = 0;

# "static" hash holding the pcap file descs of all objects.
my %pcaps;

# Catch SIGINT to stop immediatly pcap_loop amongs all pgShark objects.
sigaction SIGINT, new POSIX::SigAction(
    sub {
        foreach my $i ( keys %pcaps ) {
            pcap_breakloop( $pcaps{$i} );
        }
    },
    undef,
    &POSIX::SA_RESETHAND & &POSIX::SA_RESTART
) or die "Error setting SIGINT handler: $!\n";

=head1 METHODS

=over

=item *
B<new (\%settings)>

B<Static method>.

Creates a new pgShark object and returns it. It takes a hash as parameter with
the following settings:

	{
		'host' => IP address of the server
		'port' => Port of the PostgreSQL server
		'protocol' => the protocol version, ie. 2 or 3
		'procs' => {
			# Hash of callbacks for each messages.
			'message name' => \&callback
			...
		}
	}

pgShark is not able to detect in a network dump which IP address is the server
and on which port it is listening. Defaults are PostgreSQL's ones, ie.
127.0.0.1:5432. Make sure to always set the proper host/port or pgShark will
not be able to decode your PostgreSQL traffic.

If not defined, the protocol version by default is 3.

The 'procs' hash associate a callback to each messages of the PostgreSQL
protocol you are interested in. See the following link about available message
names and definitions:

  http://www.postgresql.org/docs/current/static/protocol-message-formats.html

Some more messages type has been added to catch those that are not defined
explicitly in the protocol.

In protocol v3: CancelRequest, SSLRequest, SSLAnswer and StartupMessage
In protocol v2: CancelRequest, SSLRequest, SSLAnswer, StartupMessage,
PasswordPacket, CopyDataRows

See section PROTOCOL for details about messages.

=cut

sub new {
    my $class = shift;
    my %args  = %{ shift() };

    $id++;

    my $self = {
        'host' => defined $args{'host'} ? $args{'host'} : '127.0.0.1',
        'id' => $id,
        'pckt_count' => 0,
        'port'       => defined $args{'port'} ? $args{'port'} : '5432',
        'msg_count'  => 0,
        'protocol'   => defined $args{'protocol'} ? $args{'protocol'} : '3',
        'sessions'   => {}
    };

    # Converts the dot'ed IPADDR of the host to decimal
    # to dirct compare with address given from libpcap
    my ( $na, $nb, $nc, $nd ) = split /\./, $self->{'host'};
    $self->{'host'} = ( $na << 24 ) + ( $nb << 16 ) + ( $nc << 8 ) + ($nd);

    # register callbacks for given pgsql messages
    foreach my $func ( keys %{ $args{'procs'} } ) {
        $self->{$func} = $args{'procs'}->{$func};
    }

    if ( $self->{'protocol'} eq '2' ) {
        $self->{'parser'} = \&parse_v2;
    }
    else {
        $self->{'parser'} = \&parse_v3;
    }

    set_debug( $args{'debug'} ) if defined( $args{'debug'} );

    debug( 1, "A shark is borned.\n" );

    return bless( $self, $class );
}

#_setFilter
# Set the pcap filter to apply to the pcap stream. See pcap-filter(7)
sub _setFilter {
    my $self     = shift;
    my $c_filter = undef;
    my $filter   = sprintf( PCAP_FILTER_TEMPLATE, $self->{'port'} );

    debug( 2, "set filter to: %s\n", $filter );

    return 1 unless defined $pcaps{ $self->{'id'} } and $filter;

    pcap_compile( $pcaps{ $self->{'id'} }, \$c_filter, $filter, 0, 0 );
    pcap_setfilter( $pcaps{ $self->{'id'} }, $c_filter );

    return 0;
}

=item *
B<live ($interface, \$err)>

Open a live capture on given interface from first parameter. The second
parameter is a reference to a string. It will be filled with the error message
if the method fails.

Returns 0 on success, 1 on failure

=cut

sub live {
    my $self      = shift;
    my $interface = shift;
    my $err       = shift;

    return 1
        unless $pcaps{ $self->{'id'} }
            = pcap_open_live( $interface, 65535, 0, 0, \$err );

    $self->_setFilter();

    return 0;
}

=item *
B<open ($file, \$err)>

Open a given pcap file from first parameter. The second parameter is a
reference to a string. It will be filled with the error message if the method
fails.

Returns 0 on success, 1 on failure.

=cut

sub open {
    my $self = shift;
    my $file = shift;
    my $err  = shift;

    return 1
        unless $pcaps{ $self->{'id'} } = pcap_open_offline( $file, \$err );

    $self->_setFilter();

    return 0;
}

=item *
B<close ()>

Close the pcap handle previously opened with this object using either
pgShark::live() or pgShark::open() methods.

=cut

sub close {
    my $self = shift;

    pcap_close( $pcaps{ $self->{'id'} } ) if exists $pcaps{ $self->{'id'} };

    debug( 2, "pcap stream closed.\n" );

    delete $pcaps{ $self->{'id'} };
}

=item *
B<process_all ()>

Loop over all available packets from the previously opened pcap handle.

=cut

sub process_all {
    my $self = shift;

  # Net::Pcap::Reassemble::loop($self->{'pcap'}, -1, \&process_packet, $self)
  # 	if $self->{'pcap'};

    ## slightly better perfs without Net::Pcap::Reassemble
    pcap_loop( $pcaps{ $self->{'id'} }, -1, \&process_packet, $self )
        if exists $pcaps{ $self->{'id'} };
}

##
# process_packet
#
# Main callback called to dissect a network packet called from "pcap_loop" in sub
# process_all.
#
# It dissects the given network packet looking for PostgreSQL data. If some pgsql
# payload is found in TCP data, it dissects the buffer calling
# "self->pgsql_dissect()".
#
# Code to dissect IP and TCP fields was inspired from perl NetPacket library and
# optimzed to speed up the parsing, fetching only usefull information. Moreover,
# one pgShark's rule is to rely on very few non-core libraries.
#
# TCP dialogs are tracked in a hash table. Each dialog is referenced by a key
# composed by the IP and port of the remote client. A dialog is an array with
# backend data in first position and frontend ones in second.
#
# Data payloads are reconstructed based on TCP seq/ack sequences.
sub process_packet {
    my ( $self, $pckt_hdr, $pckt ) = @_;
    my ( $sess_hash, $curr_sess, $from_backend, $is_fin );

    $self->{'pckt_count'}++;

    my ( $eth_type, $data ) = unpack( 'x12na*', $pckt );

    # ignore non-IP packets
    return unless defined $data and defined $eth_type and $eth_type == 0x0800;

    # decode the IP payload
    my ( $ip_hlen, $ip_len, $ip_proto, $src_ip, $dest_ip );
    ( $ip_hlen, $ip_len, $ip_proto, $src_ip, $dest_ip, $data )
        = unpack( 'CxnxxxxxCxxNNa*', $data );

    # ignore non-TCP packets
    unless ( $ip_proto == 6 ) {
        debug( 4, "IP: not TCP\n" );
        return;
    }

    $ip_hlen = $ip_hlen & 0x0f;
    $ip_hlen = 5 if $ip_hlen < 5;    # precaution against bad header

    $data = substr( $data, ( $ip_hlen - 5 ) * 4, $ip_len - 4 * $ip_hlen );

    # decode the TCP payload
    my ( $src_port, $dest_port, $seqnum, $acknum, $tcp_hlen, $tcp_len );
    ( $src_port, $dest_port, $seqnum, $acknum, $tcp_hlen, $data )
        = unpack( "nnNNnx6a*", $data );

    # Extract flags
    # Flags closing connexion (FIN/RST)
    $is_fin = ( $tcp_hlen & 0x0005 );
    $tcp_hlen = ( ( ( $tcp_hlen & 0xf000 ) >> 12 ) - 5 ) * 4;
    $tcp_hlen = 0 if $tcp_hlen < 0;    # Check for bad hlen

    $data = substr( $data, $tcp_hlen );

    debug( 4, "packet: #=%d len=%s, caplen=%s\n",
        $self->{'pckt_count'}, $pckt_hdr->{'len'}, $pckt_hdr->{'caplen'} );

    $tcp_len = length($data);

    # ignore tcp without data or that are not a FIN
    unless ( $tcp_len or $is_fin ) {
        debug( 4, "TCP: no data\n" );
        return;
    }

    debug( 4,
        "IP:TCP %s:%d->%s:%d, seqnum: %d, acknum: %d, len: %d, FIN: %b\n",
        $src_ip, $src_port, $dest_ip, $dest_port, $seqnum, $acknum, $tcp_len,
        $is_fin );

   # pgShark must track every sessions to be able to dissect their data
   # without mixing them. Sessions related data are kept in
   # "$self->{'sessions'}", each session is identified with its hash, composed
   # by its IP and origin port. We could add server ip and port to this hash,
   # but we are suppose to work with only one server.
    if ( $src_ip eq $self->{'host'} and $src_port == $self->{'port'} ) {
        $from_backend = 1;
        $sess_hash    = $dest_ip . $dest_port;
    }
    else {
        $from_backend = 0;
        $sess_hash    = $src_ip . $src_port;
    }

    if ($is_fin) {
        delete $self->{'sessions'}->{$sess_hash};
        debug( 4,
            "TCP session finished (FIN or RST). Pgsql session dropped.\n" );
        return;
    }

    if ( not defined( $self->{'sessions'}->{$sess_hash} ) ) {
        debug( 3, "PGSQL: creating a new session %s\n", $sess_hash );
        $self->{'sessions'}->{$sess_hash} = [
            {    # not from backend
                'data'     => '',    # raw tcp data
                'next_seq' => -1,
                'segs'     => [],    # segments buffer
            },
            {                        # from backend
                'data'     => '',    # raw tcp data
                'next_seq' => -1,
                'segs'     => [],    # segments buffer
            }
        ];
    }

    if ( $self->{'sessions'}->{$sess_hash} eq 'SSL' ) {
        debug( 3, "PGSQL: session %s encrypted, ignore.\n", $sess_hash );
        return;
    }

    $curr_sess = $self->{'sessions'}->{$sess_hash}->[$from_backend];

    $curr_sess->{'next_seq'} = $seqnum;

    push @{ $curr_sess->{'segs'} },
        (
        {   'seq'  => $seqnum,
            'len'  => $tcp_len,
            'data' => $data
        }
        );

    debug( 5, "TCP/IP: %s-%d: segment in the buff: %d\n",
        $sess_hash, $from_backend, scalar @{ $curr_sess->{'segs'} } );

    # we loop over existing tcp segments trying to find the best one to
    # reconstruct the data
    my $i = 0;
    foreach my $segment ( @{ $curr_sess->{'segs'} } ) {

        # normal
        if ( $curr_sess->{'next_seq'} == $segment->{'seq'} ) {

            debug( 5, "TCP/IP: %s-%d: perfect sequence\n",
                $sess_hash, $from_backend );

            # add data to the current session's buffer
            $curr_sess->{'data'} .= $segment->{'data'};
            $curr_sess->{'next_seq'}
                = $curr_sess->{'next_seq'} + $segment->{'len'};

            splice @{ $curr_sess->{'segs'} }, $i, 1;
        }

        # tcp's data begins in past but finish in future
        elsif (
            ( $curr_sess->{'next_seq'} >= $segment->{'seq'} )
            and ( $curr_sess->{'next_seq'}
                < $segment->{'seq'} + $segment->{'len'} )
            )
        {
            debug(
                5,
                "TCP/IP: %s-%d: segment start in the past but complete data\n",
                $sess_hash,
                $from_backend
            );
            my $offset = $curr_sess->{'next_seq'} - $segment->{'seq'};

            # add data to the current session's buffer
            $curr_sess->{'data'} .= substr( $segment->{'data'}, $offset );
            $curr_sess->{'next_seq'}
                = $curr_sess->{'next_seq'} + $segment->{'len'} - $offset;

            splice @{ $curr_sess->{'segs'} }, $i, 1;
        }

        # tcp segment already done, drop it
        elsif ( $curr_sess->{'next_seq'}
            >= $segment->{'seq'} + $segment->{'len'} )
        {
            debug( 5, "TCP/IP: %s-%d: segment in the past.\n",
                $sess_hash, $from_backend );
            splice @{ $curr_sess->{'segs'} }, $i, 1;
        }

        # tcp's in the future, we keep it in the segment buffer
        else {
            debug(
                5,
                "TCP/IP: %s-%d:  tcp's in the future, next_seq: %d, seq: %d-%d.\n",
                $sess_hash,
                $from_backend,
                $curr_sess->{'next_seq'},
                $segment->{'seq'},
                $segment->{'seq'} + $segment->{'len'}
            );
        }
        $i++;
    }

    # message informations hash
    my $pg_msg = {

        # tcp/ip properties
        'tcpip' => {
            'src_ip'    => $src_ip,
            'dest_ip'   => $dest_ip,
            'src_port'  => $src_port,
            'dest_port' => $dest_port
        },

        # the session this message belongs to
        'sess_hash' => $sess_hash,

        # is the message coming from backend ?
        'from_backend' => $from_backend,

        # timestamps of the message
        'timestamp' => "$pckt_hdr->{'tv_sec'}."
            . sprintf( '%06d', $pckt_hdr->{'tv_usec'} ),
        ## the following entries will be feeded bellow
        # 'type' => message type. Either one-char type or full message for
        #			special ones
        # 'data' =>  the message data (without the type and int32 length)
        ## other fields specifics to each messages are added bellow
    };

    # if dissecting the buffer fails, reset the data for this half-part of a
    # session
    if ( $self->pgsql_dissect($pg_msg) != 0 ) {
        $self->{'sessions'}->{$sess_hash}->[$from_backend] = {
            'data'     => '',    # raw tcp data
            'next_seq' => -1,
            'segs'     => [],    # segments buffer
        };
    }
}

##
# pgsql_dissect
#
# A PostgreSQL TCP monolog can have more than one message.
#
# Loop on data from a session monologue (tcp payload from backend or frontend)
# to parse each pgsql messages in it. The loop stop when the monologue has no
# more data or when it's not parsable.
#
# Each iteration of the loop parse one message from the bigining of the monolog
# buffer. Parsing is done from one of the parse_vX functions depending on the
# protocol version.
#
# Once the parsing is done, the appropriate callback is called and the message
# removed from the monolog buffer.
#
# When the TCP monolog buffer is empty, parsing was successful, or message is
# fragmented, returns 0. Any other value means that an error occured.
#
# @param pg_msg_orig	The hash's skeleton to use to construct a pgsql hash
# 						message.
# 						It already contains tcp and other global infos.
sub pgsql_dissect {
    my $self         = shift;
    my $pg_msg_orig  = shift;
    my $sess_hash    = $pg_msg_orig->{'sess_hash'};
    my $from_backend = $pg_msg_orig->{'from_backend'};

    my $curr_sess = $self->{'sessions'}->{$sess_hash}->[$from_backend];

    my $data_len = length $curr_sess->{'data'};

    do {

        # copy base message properties hash for this new message
        my $pg_msg = {%$pg_msg_orig};

        my $msg_len = $self->{'parser'}
            ->( $pg_msg, $from_backend, $curr_sess->{'data'}, $curr_sess );

        # we don't have enough data for the current message (0)
        # or an error occured (<0)
        return $msg_len if $msg_len < 1;

        debug(
            3,
            "PGSQL: pckt=%d, timestamp=%s, session=%s type=%s, msg_len=%d, data_len=%d\n",
            $self->{'pckt_count'},
            $pg_msg->{'timestamp'},
            $sess_hash,
            $pg_msg->{'type'},
            $msg_len,
            $data_len
        );

        # extract the message data from the buffer
        $pg_msg->{'data'} = substr( $curr_sess->{'data'}, 0, $msg_len );

        # call the callback for the message type if defined.
        $self->{ $pg_msg->{'type'} }->($pg_msg)
            if defined $self->{ $pg_msg->{'type'} };

        # remove processed data from the buffer
        $curr_sess->{'data'} = substr( $curr_sess->{'data'}, $msg_len );
        $data_len -= $msg_len;

        # if the message was Terminate, destroy the session
        if ( $pg_msg->{'type'} eq 'Terminate' ) {
            debug(
                3,
                "PGSQL: destroying session %s (remaining buffer was %d byte long).\n",
                $sess_hash,
                $data_len
            );
            delete $self->{'sessions'}->{$sess_hash};
            $curr_sess = undef;
            return 0;
        }

        if (    $pg_msg->{'type'} eq 'SSLAnswer'
            and $pg_msg->{'ssl_answer'} eq 'S' )
        {
            debug( 3,
                "PGSQL: session %s will be encrypted so we ignore it.\n",
                $sess_hash );
            delete $self->{'sessions'}->{$sess_hash};
            $curr_sess = undef;
            $self->{'sessions'}->{$sess_hash} = 'SSL';
            return 0;
        }

        $self->{'msg_count'}++;
    } while ( $data_len > 0 );

    return 0;
}

=item *
B<parse_v3 (\%pg_msg, $from_backend, $data)>

B<Static method>.

Parse and dissect a buffer, looking for a valid pgsql v3 message, and set the
given hashref as first parameter with the message properties. Properties set in
the given hashref depend on the message type. See the method code comments for
more information about them.

The second parameter tells the method who sent the given data so it is able to
parse them properly: the backend (1) or the frontend (0).

The data to parsed are given in the third parameter.

This method is static, so it can be used outside of the class for any other
purpose.

CAUTION: This function MUST returns the total length of the parsed message so
it can be removed from the TCP monolog buffer. 0 means lack of data to
process the current message. On error, returns -1

=cut

sub parse_v3 {
    my $pg_msg       = shift;
    my $from_backend = shift;
    my $raw_data     = shift;
    my $data_len     = length $raw_data;
    my $len;
    my $msg_len;

    if (   ( not $from_backend and $raw_data =~ /^[BCfDEHFPpQSXdc].{4}/s )
        or ( $from_backend and $raw_data =~ /^[RK23CGHDIEVnNAtS1sZTdc].{4}/s )
        )
    {

        # the message has a type byte
        ( $pg_msg->{'type'}, $msg_len ) = unpack( 'AN', $raw_data );

        if ( $data_len < $msg_len + 1 ) {    # we add the type byte
                # we don't have the full message, waiting for more bits
            debug(
                3,
                "NOTICE: message fragmented (data available: %d, total message length: %d), waiting for more bits.\n",
                $data_len,
                $msg_len + 1
            );
            return 0;
        }
    }
    elsif ( $from_backend and $raw_data =~ /^(N|S)$/ ) {

        # SSL answer
        $pg_msg->{'type'} = 'SSLAnswer';
    }
    elsif ( not $from_backend and $raw_data =~ /^.{8}/s ) {
        my $code;
        ( $msg_len, $code ) = unpack( 'NN', $raw_data );
        if ( $code == 80877102 ) {
            $pg_msg->{'type'} = 'CancelRequest';
        }
        elsif ( $code == 80877103 ) {
            $pg_msg->{'type'} = 'SSLRequest';
        }
        elsif ( $code == 196608 ) {
            $pg_msg->{'type'} = 'StartupMessage';

            # my $min = $code%65536; # == 0
            # my $maj = $code/65536; # == 3
        }
    }
    elsif ( $from_backend and $data_len < 5 ) {
        debug(
            3,
            "NOTICE: buffer full of junk or empty (data available: %d)...waiting for more bits.\n",
            $data_len
        );
        my $d = $raw_data;
        $d =~ tr/\x00-\x1F\x7F-\xFF/./;
        debug( 3, "HINT: data are: «%s»\n", $d );
        return 0;
    }

    if ( not defined $pg_msg->{'type'} ) {
        if ( get_debug_lvl() > 2 ) {
            $raw_data =~ tr/\x00-\x1F\x7F-\xFF/./;
            debug(
                3,
                "WARNING: dropped alien packet I was unable to mess with at timestamp %s:\n'%s'\n",
                $pg_msg->{'timestamp'},
                $raw_data
            );
        }
        return -1;
    }

    # message: B(R) "Authentication*"
    if ( $from_backend and $pg_msg->{'type'} eq 'R' ) {
        ( $len, $pg_msg->{'code'} ) = unpack( 'xNN', $raw_data );

        # AuthenticationOk
        #   code=int32
        if ( $pg_msg->{'code'} == 0 ) {
            $pg_msg->{'type'} = 'AuthenticationOk';
            return 9;
        }

        # AuthenticationKerberosV5
        #   code=int32
        elsif ( $pg_msg->{'code'} == 2 ) {
            $pg_msg->{'type'} = 'AuthenticationKerberosV5';
            return 9;
        }

        # AuthenticationCleartextPassword
        #   code=int32
        elsif ( $pg_msg->{'code'} == 3 ) {
            $pg_msg->{'type'} = 'AuthenticationCleartextPassword';
            return 9;
        }

        # AuthenticationMD5Password
        #   code=int32
        #   salt=Char[4]
        elsif ( $pg_msg->{'code'} == 5 ) {
            $pg_msg->{'salt'} = substr( $raw_data, 9, 4 );
            $pg_msg->{'type'} = 'AuthenticationMD5Password';
            return 13;
        }

        # AuthenticationSCMCredential
        #   code=int32
        elsif ( $pg_msg->{'code'} == 6 ) {
            $pg_msg->{'type'} = 'AuthenticationSCMCredential';
            return 9;
        }

        # AuthenticationGSS
        #   code=int32
        elsif ( $pg_msg->{'code'} == 7 ) {
            $pg_msg->{'type'} = 'AuthenticationGSS';
            return 9;
        }

        # AuthenticationSSPI
        #   code=int32
        elsif ( $pg_msg->{'code'} == 9 ) {
            $pg_msg->{'type'} = 'AuthenticationSSPI';
            return 9;
        }

        # GSSAPI or SSPI authentication data
        #   code=int32
        #   auth_data=String
        elsif ( $pg_msg->{'code'} == 8 ) {
            $pg_msg->{'auth_data'} = substr( $raw_data, 9, $len - 8 );
            $pg_msg->{'type'} = 'AuthenticationGSSContinue';
            return $len + 1;
        }

        # FIXME Add a catch all ?
    }

    # message: B(K) "BackendKeyData"
    #   pid=int32
    #   key=int32
    elsif ( $from_backend and $pg_msg->{'type'} eq 'K' ) {
        ( $pg_msg->{'pid'}, $pg_msg->{'key'} ) = unpack( 'x5NN', $raw_data );
        $pg_msg->{'type'} = 'BackendKeyData';
        return 13;
    }

    # message: F(B) "Bind"
    #   portal=String
    #   name=String
    #   num_formats=int16
    #   formats[]=int16[nb_formats]
    #   num_params=int16
    #   params[]=(len=int32,value=char[len])[nb_params]
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'B' ) {
        my @params_formats;
        my @params;
        my $msg;

        # TODO refactor this mess

        (   $len, $pg_msg->{'portal'}, $pg_msg->{'name'},
            $pg_msg->{'num_formats'}
        ) = unpack( 'xNZ*Z*n', $raw_data );

        # we add 1 bytes for both portal and name that are null-terminated
        # + 2 bytes of int16 for $num_formats
        $msg = substr( $raw_data,
                  5 
                + length( $pg_msg->{'portal'} ) + 1
                + length( $pg_msg->{'name'} )
                + 1
                + 2 );

        # catch formats and the $num_params as well
        @params_formats = unpack( "n$pg_msg->{'num_formats'} n", $msg );
        $pg_msg->{'num_params'}   = pop @params_formats;
        $pg_msg->{'params_types'} = [@params_formats];

        $msg = substr( $msg, ( $pg_msg->{'num_formats'} + 1 ) * 2 );

        # TODO add some safety tests about available data in $msg ?
        for ( my $i = 0; $i < $pg_msg->{'num_params'}; $i++ ) {

            # unpack hasn't 32bit signed network template, so we use l>
            my ($len) = unpack( 'l>', $msg );

            # if len < 0; the value is NULL
            if ( $len > 0 ) {
                push @params, substr( $msg, 4, $len );
                $msg = substr( $msg, 4 + $len );
            }
            elsif ( $len == 0 ) {
                push @params, '';
                $msg = substr( $msg, 4 );
            }
            else {    # value is NULL
                push @params, undef;
                $msg = substr( $msg, 4 );
            }
        }

        $pg_msg->{'params'} = [@params];

        $pg_msg->{'type'} = 'Bind';
        return $len + 1;
    }

    # message: B(2) "BindComplete"
    elsif ( $from_backend and $pg_msg->{'type'} eq '2' ) {
        $pg_msg->{'type'} = 'BindComplete';
        return 5;
    }

    # message: CancelRequest (F)
    #   pid=int32
    #   key=int32
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'CancelRequest' ) {
        ( $pg_msg->{'pid'}, $pg_msg->{'key'} ) = unpack( 'x8NN', $raw_data );
        $pg_msg->{'type'} = 'CancelRequest';
        return 16;
    }

    # message: F(C) "Close"
    #   kind=char
    #   name=String
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'C' ) {
        ( $len, $pg_msg->{'kind'}, $pg_msg->{'name'} )
            = unpack( 'xNAZ*', $raw_data );
        $pg_msg->{'type'} = 'Close';
        return $len + 1;
    }

    # message: B(3) "CloseComplete"
    elsif ( $from_backend and $pg_msg->{'type'} eq '3' ) {
        $pg_msg->{'type'} = 'CloseComplete';
        return 5;
    }

    # message: B(C) "CommandComplete"
    #   type=char
    #   name=String
    elsif ( $from_backend and $pg_msg->{'type'} eq 'C' ) {
        ( $len, $pg_msg->{'command'} ) = unpack( 'xNZ*', $raw_data );
        $pg_msg->{'type'} = 'CommandComplete';
        return $len + 1;
    }

    # message: B(d) or F(d) "CopyData"
    #   row=Byte[n]
    elsif ( $pg_msg->{'type'} eq 'd' ) {
        $len = unpack( 'xN', $raw_data );
        $pg_msg->{'type'} = 'CopyData';
        $pg_msg->{'row'} = substr( $raw_data, 5, $len - 4 );
        return $len + 1;
    }

    # message: B(c) or F(c) "CopyDone"
    #   data=Byte[n]
    elsif ( $pg_msg->{'type'} eq 'c' ) {
        $pg_msg->{'type'} = 'CopyDone';
        return 5;
    }

    # message: F(f) "CopyFail"
    #   error=String
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'f' ) {
        ( $len, $pg_msg->{'error'} ) = unpack( 'xNZ*', $raw_data );
        $pg_msg->{'type'} = 'CopyFail';
        return $len + 1;
    }

    # message: B(G) "CopyInResponse"
    #   copy_format=int8
    #   num_fields=int16
    #   fields_formats[]=int16[num_fields]
    elsif ( $from_backend and $pg_msg->{'type'} eq 'G' ) {
        my @fields_formats;

        ( $len, $pg_msg->{'copy_format'}, @fields_formats )
            = unpack( 'xNCn/n', $raw_data );
        $pg_msg->{'num_fields'}     = scalar(@fields_formats);
        $pg_msg->{'fields_formats'} = [@fields_formats];

        $pg_msg->{'type'} = 'CopyInResponse';
        return $len + 1;
    }

    # message: B(H) "CopyOutResponse"
    #   copy_format=int8
    #   num_fields=int16
    #   fields_formats[]=int16[num_fields]
    elsif ( $from_backend and $pg_msg->{'type'} eq 'H' ) {
        my @fields_formats;

        ( $len, $pg_msg->{'copy_format'}, @fields_formats )
            = unpack( 'xNCn/n', $raw_data );
        $pg_msg->{'num_fields'}     = scalar(@fields_formats);
        $pg_msg->{'fields_formats'} = [@fields_formats];

        $pg_msg->{'type'} = 'CopyOutResponse';
        return $len + 1;
    }

    # message: B(D) "DataRow"
    #   num_values=int16
    #   (
    #   value_len=int32
    #   value=Byte[value_len]
    #		(TODO give the format given in previous message B(T) ?)
    #   )[num_values]
    elsif ( $from_backend and $pg_msg->{'type'} eq 'D' ) {
        my @values;
        my $msg;
        my $i = 0;

        ( $len, $pg_msg->{'num_values'} ) = unpack( 'xNn', $raw_data );

        $msg = substr( $raw_data, 7, $len - 6 );

        while ( $i < $pg_msg->{'num_values'} ) {
            my $val_len = unpack( 'l>', $msg );
            my $val = undef;
            if ( $val_len != -1 ) {
                $val = substr( $msg, 4, $val_len );
                $msg = substr( $msg, 4 + $val_len );
            }
            else {
                $val = undef;
                $msg = substr( $msg, 4 );
            }

            push @values, [ $val_len, $val ];

            $i++;
        }

        $pg_msg->{'values'} = [@values];

        $pg_msg->{'type'} = 'DataRow';
        return $len + 1;
    }

    # message: F(D) "Describe"
    #   kind=char
    #   name=String
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'D' ) {
        ( $len, $pg_msg->{'kind'}, $pg_msg->{'name'} )
            = unpack( 'xNAZ*', $raw_data );
        $pg_msg->{'type'} = 'Describe';
        return $len + 1;
    }

    # message: B(I) "EmptyQueryResponse"
    elsif ( $from_backend and $pg_msg->{'type'} eq 'I' ) {
        $pg_msg->{'type'} = 'EmptyQueryResponse';
        return 5;
    }

    # message: B(E) "ErrorResponse"
    #   (code=char
    #   value=String){1,}\x00
    elsif ( $from_backend and $pg_msg->{'type'} eq 'E' ) {
        my $fields = {};
        my $msg;

        $len = unpack( 'xN', $raw_data );
        $msg = substr( $raw_data, 5, $len - 4 );

        while ( $msg ne '' ) {
            my ( $code, $value ) = unpack( 'AZ*', $msg );
            last if ( $code eq '' );
            $fields->{$code} = $value;
            $msg = substr( $msg, 2 + length($value) );
        }

        $pg_msg->{'fields'} = $fields;

        $pg_msg->{'type'} = 'ErrorResponse';
        return $len + 1;
    }

    # message: F(E) "Execute"
    #   name=String
    #   nb_rows=int32
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'E' ) {
        ( $len, $pg_msg->{'name'}, $pg_msg->{'nb_rows'} )
            = unpack( 'xNZ*N', $raw_data );
        $pg_msg->{'type'} = 'Execute';
        return $len + 1;
    }

    # message: F(H) "Flush"
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'H' ) {
        $pg_msg->{'type'} = 'Flush';
        return 5;
    }

    # message: F(F) "FunctionCall"
    #   func_oid=Int32
    #   num_args_formats=Int16
    #   args_formats[]=int16[nb_formats]
    #   num_args=Int16
    #   args[]=(len=int32,value=Byte[len])[nb_args]
    #   result_format=Int16
    # TODO: NOT TESTED yet
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'F' ) {
        my @args_formats;
        my @args;
        my $msg;

        ( $len, $pg_msg->{'func_oid'}, @args_formats )
            = unpack( 'xNNn/n n', $raw_data );
        $pg_msg->{'num_args'}         = pop @args_formats;
        $pg_msg->{'num_args_formats'} = scalar(@args_formats);
        $pg_msg->{'args_formats'}     = [@args_formats];

        $msg = substr( $raw_data, 5 + 8 + $pg_msg->{'num_args_formats'} * 2 );

        for ( my $i = 0; $i < $pg_msg->{'num_args'}; $i++ ) {

            # unpack hasn't 32bit signed network template, so we use l>
            my ($len) = unpack( 'l>', $msg );

            # if len < 0; the value is NULL
            if ( $len > 0 ) {
                push @args, substr( $msg, 4, $len );
                $msg = substr( $msg, 4 + $len );
            }
            elsif ( $len == 0 ) {
                push @args, '';
                $msg = substr( $msg, 4 );
            }
            else {    # value is NULL
                push @args, undef;
                $msg = substr( $msg, 4 );
            }
        }

        $pg_msg->{'params'} = [@args];

        $pg_msg->{'result_format'} = unpack( 'n', $msg );

        $pg_msg->{'type'} = 'FunctionCall';
        return $len + 1;
    }

    # message: B(V) "FunctionCallResponse"
    #   len=Int32
    #   value=Byte[len]
    # TODO: NOT TESTED yet
    elsif ( $from_backend and $pg_msg->{'type'} eq 'V' ) {
        ( $len, $pg_msg->{'len'} ) = unpack( 'xNl>', $raw_data );

        # if len < 0; the value is NULL
        if ( $pg_msg->{'len'} > 0 ) {
            $pg_msg->{'value'} = substr( $raw_data, 4, $pg_msg->{'len'} );
        }
        elsif ( $pg_msg->{'len'} == 0 ) {
            $pg_msg->{'value'} = '';
        }
        else {    # value is NULL
            $pg_msg->{'value'} = undef;
        }

        $pg_msg->{'type'} = 'FunctionCallResponse';
        return $len + 1;
    }

    # message: B(n) "NoData"
    elsif ( $from_backend and $pg_msg->{'type'} eq 'n' ) {
        $pg_msg->{'type'} = 'NoData';
        return 5;
    }

    # message: B(N) "NoticeResponse"
    #   (code=char
    #   value=String){1,}\x00
    elsif ( $from_backend and $pg_msg->{'type'} eq 'N' ) {
        my $fields = {};
        my $msg;

        $len = unpack( 'xN', $raw_data );
        $msg = substr( $raw_data, 5, $len - 4 );

        while ( $msg ne '' ) {
            my ( $code, $value ) = unpack( 'AZ*', $msg );
            last if ( $code eq '' );
            $fields->{$code} = $value;
            $msg = substr( $msg, 2 + length($value) );
        }

        $pg_msg->{'fields'} = $fields;

        $pg_msg->{'type'} = 'NoticeResponse';
        return $len + 1;
    }

    # message: B(A) "NotificationResponse"
    #   pid=int32
    #   channel=String
    #   payload=String
    elsif ( $from_backend and $pg_msg->{'type'} eq 'A' ) {
        ( $len, $pg_msg->{'pid'}, $pg_msg->{'channel'}, $pg_msg->{'payload'} )
            = unpack( 'xNNZ*Z*', $raw_data );
        $pg_msg->{'type'} = 'NotificationResponse';
        return $len + 1;
    }

    # message: B(t) "ParameterDescription"
    #   num_params=int16
    #   params_types[]=int32[nb_formats]
    elsif ( $from_backend and $pg_msg->{'type'} eq 't' ) {
        my @params_types;

        ( $len, @params_types ) = unpack( 'xNn/N', $raw_data );
        $pg_msg->{'num_params'}   = scalar(@params_types);
        $pg_msg->{'params_types'} = [@params_types];

        $pg_msg->{'type'} = 'ParameterDescription';
        return $len + 1;
    }

    # message: B(S) "ParameterStatus"
    #   name=String
    #   value=String
    elsif ( $from_backend and $pg_msg->{'type'} eq 'S' ) {
        ( $len, $pg_msg->{'name'}, $pg_msg->{'value'} )
            = unpack( 'xNZ*Z*', $raw_data );

        $pg_msg->{'type'} = 'ParameterStatus';
        return $len + 1;
    }

    # message: F(P) "Parse"
    #   name=String
    #   query=String
    #   num_params=int16
    #   params_types[]=int32[nb_formats]
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'P' ) {
        my @params_types;
        ( $len, $pg_msg->{'name'}, $pg_msg->{'query'}, @params_types )
            = unpack( 'xNZ*Z*n/N', $raw_data );
        $pg_msg->{'num_params'}   = scalar(@params_types);
        $pg_msg->{'params_types'} = [@params_types];

        $pg_msg->{'type'} = 'Parse';
        return $len + 1;
    }

    # message: B(1) "ParseComplete"
    elsif ( $from_backend and $pg_msg->{'type'} eq '1' ) {
        $pg_msg->{'type'} = 'ParseComplete';
        return 5;
    }

    # message: F(p) "PasswordMessage"
    #    password=String
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'p' ) {
        ( $len, $pg_msg->{'password'} ) = unpack( 'xNZ*', $raw_data );
        $pg_msg->{'type'} = 'PasswordMessage';
        return $len + 1;
    }

    # message: B(s) "PortalSuspended"
    elsif ( $from_backend and $pg_msg->{'type'} eq 's' ) {
        $pg_msg->{'type'} = 'PortalSuspended';
        return 5;
    }

    # message: F(Q) "Query"
    #    query=String
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'Q' ) {
        ( $len, $pg_msg->{'query'} ) = unpack( 'xNZ*', $raw_data );
        $pg_msg->{'type'} = 'Query';
        return $len + 1;
    }

    # message: B(Z) "ReadyForQuery"
    #   status=Char
    elsif ( $from_backend and $pg_msg->{'type'} eq 'Z' ) {
        $pg_msg->{'status'} = substr( $raw_data, 5, 1 );
        $pg_msg->{'type'} = 'ReadyForQuery';
        return 6;
    }

    # message: B(T) "RowDescription"
    #   num_fields=int16
    #   (
    #     field=String
    #     relid=int32 (0 if not associated to a table)
    #     attnum=int16 (0 if not associated to a table)
    #     type=int32
    #     type_len=int16 (-1 if variable, see pg_type.typlen)
    #     type_mod=int32 (see pg_attribute.atttypmod)
    #     format=int16 (0:text or 1:binary)
    #   )[num_fields]
    elsif ( $from_backend and $pg_msg->{'type'} eq 'T' ) {
        my @fields;
        my $i = 0;
        my $msg;

        ( $len, $pg_msg->{'num_fields'} ) = unpack( 'xNn', $raw_data );
        $msg = substr( $raw_data, 7 );

        while ( $i < $pg_msg->{'num_fields'} ) {
            my @field = unpack( 'Z*NnNnNn', $msg );
            push @fields, [@field];
            $msg = substr( $msg, 19 + length( $field[0] ) );

            $i++;
        }

        $pg_msg->{'fields'} = [@fields];

        $pg_msg->{'type'} = 'RowDescription';
        return $len + 1;
    }

    # message: SSLAnswer (B)
    elsif ( $from_backend and $pg_msg->{'type'} eq 'SSLAnswer' ) {
        $pg_msg->{'ssl_answer'} = substr( $raw_data, 0, 1 );
        $pg_msg->{'type'} = 'SSLAnswer';

        return 1;
    }

    # message: SSLRequest (F)
    #   status=Char
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'SSLRequest' ) {
        $pg_msg->{'type'} = 'SSLRequest';
        return 8;
    }

    # message: StartupMessage (F)
    #   status=Char
    #   (param=String
    #   value=String){1,}\x00
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'StartupMessage' ) {
        my $msg;
        my $params = {};

        $len = unpack( 'N', $raw_data );

        $pg_msg->{'version'} = 3;

        $msg = substr( $raw_data, 8 );    # ignore the version fields

        while ( $msg ne '' ) {
            my ( $param, $value ) = unpack( 'Z*Z*', $msg );
            last if ( $param eq '' );
            $params->{$param} = $value;
            $msg = substr( $msg, 2 + length($param) + length($value) );
        }

        $pg_msg->{'params'} = $params;

        $pg_msg->{'type'} = 'StartupMessage';
        return $len;
    }

    # message: F(S) "Sync"
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'S' ) {
        $pg_msg->{'type'} = 'Sync';
        return 5;
    }

    # message: F(X) "Terminate"
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'X' ) {
        $pg_msg->{'type'} = 'Terminate';
        return 5;
    }

    # Default catchall
    else {
        debug(
            3,
            "PGSQL: not implemented message type: %s(%s)\n",
            ( $from_backend ? 'B' : 'F' ),
            $pg_msg->{'type'}
        );

        # FIXME: might be a bug to return undef
        return undef;
    }

    # return $pg_msg;
    return 1;
}

=item *
B<parse_v2 (\%pg_msg, $from_backend, $data, \%state)>

B<Static method>.

Parse and dissect a buffer, looking for a valid pgsql v2 message, and set the
given hashref as first parameter with the message properties. Properties set in
the given hashref depend on the message type. See the method code comments for
more information about them.

The second parameter tells the method who sent the given data so it is able to
parse them properly: the backend (1) or the frontend (0).

The data to parsed are given in the third parameter.

Unlike the protocole version 3, version 2 is stateful. Because of this, this
is the responsability of the caller to keep track of the state of each
sessions by giving a hashref as fourth parameter. This hashref
**MUST** concern the ONLY current session (Frontend/Backend couple) data are
parsed for. This fourth parameter does not exists in the protocol v3 version of
this method as v3 is a stateless protocol.

This method is static, so it can be used outside of the class for any other
purpose.

The method tries to keep some compatibility with messages type returned from the
v3 parser. Here is how messages are mapped between v2 and v3:

  "AsciiRow"               => "DataRow"
  "BinaryRow"              => "DataRow"
  "CompletedResponse"      => "CommandComplete"
  "CopyDataRows"           => "CopyData"
  "FunctionResultResponse" => "FunctionCallResponse"
  "FunctionVoidResponse"   => "FunctionCallResponse"
  "StartupPacket"          => "StartupMessage"

CAUTION: message "CursorResponse" is protocol v2 only !

CAUTION: This function MUST returns the total length of the parsed message so
it can be removed from the TCP monolog buffer. 0 means lack of data to
process the current message. On error, returns -1

Caution: this parser hadn't been tested enough to be considered stable. We need
some pcap file to make some tests !


=cut

sub parse_v2 {
    my $pg_msg       = shift;
    my $from_backend = shift;
    my $raw_data     = shift;
    my $curr_sess    = shift;
    my $data_len     = length $raw_data;
    my $len;
    my $msg_len;

    if ( $from_backend and $raw_data =~ /^(N|S)$/ ) {

        # SSL answer
        $pg_msg->{'type'} = 'SSLAnswer';
    }
    elsif (( not $from_backend and $raw_data =~ /^[FQX]/ )
        or ( $from_backend and $raw_data =~ /^[DRKBCGHPIEVNAZT]/ ) )
    {

        # the message has a type byte
        $pg_msg->{'type'} = substr( $raw_data, 0, 1 );
    }
    elsif ( not $from_backend and $raw_data =~ /^.{8}/s ) {
        my $code;
        ( $msg_len, $code ) = unpack( 'NN', $raw_data );

        if ( $code == 80877102 ) {
            $pg_msg->{'type'} = 'CancelRequest';
        }
        elsif ( $code == 80877103 ) {
            $pg_msg->{'type'} = 'SSLRequest';
        }
        elsif ( $code == 131072 ) {
            $pg_msg->{'type'} = 'StartupMessage';

            # my $min = $code%65536; # == 0
            # my $maj = $code/65536; # == 2
        }
        elsif ( defined $curr_sess->{'ask_passwd'} ) {
            $pg_msg->{'type'} = 'PasswordPacket';
            delete $curr_sess->{'ask_passwd'};
        }
        elsif ( defined $curr_sess->{'copy_mode'} ) {
            $pg_msg->{'type'} = 'CopyDataRows';
        }
    }

    if ( not defined $pg_msg->{'type'} ) {
        if ( get_debug_lvl() > 2 ) {
            $raw_data =~ tr/\x00-\x1F\x7F-\xFF/./;
            debug(
                3,
                "WARNING: dropped alien packet (from_backend: %d) I was unable to mess with at timestamp %s:\n'%s'\n",
                $from_backend,
                $pg_msg->{'timestamp'},
                $raw_data
            );
        }
        return -1;
    }

    # message: B(D) "AsciiRow" or B(B) "BinaryRow"
    # we try to be compatible with proto v3 here
    if ( $from_backend and $pg_msg->{'type'} =~ /[DB]/ ) {
        my $num_bytes = 1 + int( $curr_sess->{'num_fields'} / 8 );
        my $num_bits  = 8 * $num_bytes;
        my @values;
        my @field_notnull;
        my $msg;

        my $msg_len = 1 + $num_bytes;

        $pg_msg->{'num_values'} = $curr_sess->{'num_fields'};

       # DataRow message are really prone to be splitted between multi network
       # packets
        return 0 if $data_len < $msg_len;

        @field_notnull = split( //, unpack( "xB$num_bits", $raw_data ) );

        # check if we have enough data in the buffer
        for ( my $i = 0; $i < $pg_msg->{'num_values'}; $i++ ) {
            if ( $field_notnull[$i] eq '1' ) {
                if ( $msg_len + 4 <= $data_len ) {
                    my $val_len = unpack( "x${msg_len}N", $raw_data );
                    $msg_len += $val_len;
                    return 0 if $msg_len > $data_len;
                }
                else { return 0; }
            }
        }

        $msg = substr( $raw_data, 1 + $num_bytes );

        for ( my $i = 0; $i < $pg_msg->{'num_values'}; $i++ ) {

            # printf STDERR "  i: %d", $i;
            my $val_len = -1;
            my $val     = undef;

            if ( $field_notnull[$i] eq '1' ) {
                $val_len = unpack( 'N', $msg );
                $val = substr( $msg, 4, $val_len - 4 );
                $msg = substr( $msg, $val_len );
            }

            push @values, [ $val_len, $val ];
        }

        $pg_msg->{'values'} = [@values];

        # TODO we should take care of binary -vs- text format at some point...
        $pg_msg->{'type'} = 'DataRow';

        return $msg_len;
    }

    # message: B(R) "Authentication*"
    elsif ( $from_backend and $pg_msg->{'type'} eq 'R' ) {
        ( $pg_msg->{'code'} ) = unpack( 'xN', $raw_data );

        # AuthenticationOk
        if ( $pg_msg->{'code'} == 0 ) {
            $pg_msg->{'type'} = 'AuthenticationOk';
            return 5;
        }

        # AuthenticationKerberosV4
        elsif ( $pg_msg->{'code'} == 1 ) {
            $pg_msg->{'type'} = 'AuthenticationKerberosV4';
            return 5;
        }

        # AuthenticationKerberosV5
        elsif ( $pg_msg->{'code'} == 2 ) {
            $pg_msg->{'type'} = 'AuthenticationKerberosV5';
            return 5;
        }

        # AuthenticationCleartextPassword
        elsif ( $pg_msg->{'code'} == 3 ) {
            $pg_msg->{'type'}          = 'AuthenticationCleartextPassword';
            $curr_sess->{'ask_passwd'} = 1;
            return 5;
        }

        # AuthenticationCryptPassword
        elsif ( $pg_msg->{'code'} == 4 ) {
            $pg_msg->{'salt'}          = substr( $raw_data, 5, 2 );
            $pg_msg->{'type'}          = 'AuthenticationCryptPassword';
            $curr_sess->{'ask_passwd'} = 1;
            return 7;
        }

        # AuthenticationMD5Password
        elsif ( $pg_msg->{'code'} == 5 ) {
            $pg_msg->{'salt'}          = substr( $raw_data, 5, 4 );
            $pg_msg->{'type'}          = 'AuthenticationMD5Password';
            $curr_sess->{'ask_passwd'} = 1;
            return 9;
        }

        # AuthenticationSCMCredential
        elsif ( $pg_msg->{'code'} == 6 ) {
            $pg_msg->{'type'} = 'AuthenticationSCMCredential';
            return 5;
        }

        # FIXME Add a catch all ?
    }

    # message: B(K) "BackendKeyData"
    elsif ( $from_backend and $pg_msg->{'type'} eq 'K' ) {
        ( $pg_msg->{'pid'}, $pg_msg->{'key'} ) = unpack( 'xNN', $raw_data );
        $pg_msg->{'type'} = 'BackendKeyData';
        return 9;
    }

    # message: CancelRequest (F)
    # TODO: NOT TESTED yet
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'CancelRequest' ) {
        ( $pg_msg->{'pid'}, $pg_msg->{'key'} ) = unpack( 'x8NN', $raw_data );
        $pg_msg->{'type'} = 'CancelRequest';
        return 16;
    }

    # message: B(C) "CompletedResponse"
    #   type=char
    #   name=String
    elsif ( $from_backend and $pg_msg->{'type'} eq 'C' ) {
        my $msg_len;

        $pg_msg->{'command'} = unpack( 'xZ*', $raw_data );
        $pg_msg->{'type'} = 'CommandComplete';

        # add type + null terminated String
        $msg_len = length( $pg_msg->{'command'} ) + 2;

        return 0 if $msg_len > $data_len;
        return $msg_len;
    }

    # message: B or F "CopyDataRows"
    #   row=Byte[n]
    # TODO: NOT TESTED yet
    elsif ( $pg_msg->{'type'} eq 'CopyDataRows' ) {
        my $end = index( $raw_data, "\n" );

        # we don't have the full row (fragmentation)
        return 0 if ( $end == -1 );

        $pg_msg->{'row'} = substr( $raw_data, 0, $end + 1 );
        $pg_msg->{'type'} = 'CopyData';

        if ( $pg_msg->{'row'} eq "\\.\n" ) {
            delete $curr_sess->{'copy_mode'};
        }

        return length( $pg_msg->{'row'} );
    }

    # message: B(G) "CopyInResponse"
    # TODO: NOT TESTED yet
    elsif ( $from_backend and $pg_msg->{'type'} eq 'G' ) {
        $curr_sess->{'copy_mode'} = 1;
        $pg_msg->{'type'}         = 'CopyInResponse';
        return 1;
    }

    # message: B(H) "CopyOutResponse"
    # TODO: NOT TESTED yet
    elsif ( $from_backend and $pg_msg->{'type'} eq 'H' ) {
        $curr_sess->{'copy_mode'} = 1;
        $pg_msg->{'type'}         = 'CopyOutResponse';
        return 1;
    }

    # message: B(P) "CursorResponse"
    elsif ( $from_backend and $pg_msg->{'type'} eq 'P' ) {
        my $msg_len;

        $pg_msg->{'name'} = unpack( 'xZ*', $raw_data );
        $pg_msg->{'type'} = 'CursorResponse';

        # add type + null terminated String
        $msg_len = length( $pg_msg->{'name'} ) + 2;

        return 0 if $msg_len > $data_len;
        return $msg_len;
    }

    # message: B(I) "EmptyQueryResponse"
    elsif ( $from_backend and $pg_msg->{'type'} eq 'I' ) {
        $pg_msg->{'type'} = 'EmptyQueryResponse';
        return
            2;  # EmptyQueryResponse has an empty string (1-byte) as parameter
    }

    # message: B(E) "ErrorResponse"
    # We try to be compatible with v3 here
    #   M => String
    # TODO: NOT TESTED yet
    elsif ( $from_backend and $pg_msg->{'type'} eq 'E' ) {
        my $msg_len;

        $pg_msg->{'fields'} = { 'M' => unpack( 'xZ*', $raw_data ) };

        $pg_msg->{'type'} = 'ErrorResponse';

        # add type + null terminated String
        $msg_len = length( $pg_msg->{'fields'}->{'M'} ) + 2;

        return 0 if $msg_len > $data_len;
        return $msg_len;
    }

    # message: F(F) "FunctionCall"
    #   func_oid=Int32
    #   num_args=Int32
    #   args[]=(len=int32,value=Byte[len])[nb_args]
    # TODO: NOT TESTED yet
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'F' ) {
        my @args;
        my $msg;
        my $msg_len = 0;

        # fragmentation...
        return 0 if ( $data_len < 10 );

        # FunctionCall has an empty string (one-byte "\0") as second
        # "parameter"...
        ( $pg_msg->{'func_oid'}, $pg_msg->{'num_args'} )
            = unpack( 'xxNN', $raw_data );

        # compute the message size and check for fragmentation
        $msg_len = 10;
        for ( my $i = 0; $i < $pg_msg->{'num_args'}; $i++ ) {
            if ( $msg_len + 4 <= $data_len ) {
                my $val_len = unpack( "x${msg_len}N", $raw_data );
                $msg_len += $val_len;
                return 0 unless ( $msg_len <= $data_len );
            }
            else { return 0; }
        }

        $msg = substr( $raw_data, 10 );

        for ( my $i = 0; $i < $pg_msg->{'num_args'}; $i++ ) {
            my $len = unpack( 'N', $msg );

            push @args, substr( $msg, 4, $len );
            $msg = substr( $msg, $len + 4 );
        }

        $pg_msg->{'params'} = [@args];

        $pg_msg->{'type'} = 'FunctionCall';
        return $msg_len;
    }

    # message: B(V) "FunctionResultResponse" and "FunctionVoidResponse"
    # aka "FunctionCallResponse" in v3
    #   len=Int32
    #   value=Byte[len]
    # TODO: NOT TESTED yet
    elsif ( $from_backend and $pg_msg->{'type'} eq 'V' ) {
        my $status = unpack( 'xA', $raw_data );
        my $msg_len;
        $pg_msg->{'type'} = 'FunctionCallResponse';

        if ( $status eq '0' ) {
            $pg_msg->{'len'}   = 0;
            $pg_msg->{'value'} = undef;
            return 2;
        }

        $pg_msg->{'len'} = unpack( 'xxN', $raw_data );
        $pg_msg->{'value'} = substr( $raw_data, 6, $pg_msg->{'len'} );

        $msg_len = $pg_msg->{'len'} + 6;

        return 0 if $msg_len > $data_len;
        return $msg_len;
    }

    # message: B(N) "NoticeResponse"
    # We try to be compatible with v3 here
    #   M => String
    # TODO: NOT TESTED yet
    elsif ( $from_backend and $pg_msg->{'type'} eq 'N' ) {
        my $msg_len;

        $pg_msg->{'fields'} = { 'M' => unpack( 'xZ*', $raw_data ) };

        $pg_msg->{'type'} = 'NoticeResponse';

        # add type + null terminated String
        $msg_len = length( $pg_msg->{'fields'}->{'M'} ) + 2;

        return 0 if $msg_len > $data_len;
        return $msg_len;
    }

    # message: B(A) "NotificationResponse"
    # We try to be compatible with v3 here
    #   pid=int32
    #   channel=String
    #   payload=undef (NOT in protocol v2!)
    # TODO: NOT TESTED yet
    elsif ( $from_backend and $pg_msg->{'type'} eq 'A' ) {
        my $msg_len;

        ( $pg_msg->{'pid'}, $pg_msg->{'channel'} )
            = unpack( 'xNZ*', $raw_data );
        $pg_msg->{'payload'} = undef;
        $pg_msg->{'type'}    = 'NotificationResponse';

        # add type + pid + null terminated String
        $msg_len = length( $pg_msg->{'channel'} ) + 6;

        return 0 if $msg_len > $data_len;
        return $msg_len;
    }

    # message: F "PasswordMessage"
    #    password=String
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'PasswordMessage' ) {
        my $msg_len;

        ( $msg_len, $pg_msg->{'password'} ) = unpack( 'NZ*', $raw_data );
        $pg_msg->{'type'} = 'PasswordMessage';

        return 0 if $msg_len > $data_len;
        return $msg_len;
    }

    # message: F(Q) "Query"
    #    query=String
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'Q' ) {
        my $msg_len;

        ( $pg_msg->{'query'} ) = unpack( 'xZ*', $raw_data );
        $pg_msg->{'type'} = 'Query';

        # add type + null terminated String
        $msg_len = length( $pg_msg->{'query'} ) + 2;

        return 0 if $msg_len > $data_len;
        return $msg_len;
    }

    # message: B(Z) "ReadyForQuery"
    # We try to be compatible with proto v3 here
    #   status=undef (NOT definied in v2 !)
    elsif ( $from_backend and $pg_msg->{'type'} eq 'Z' ) {
        $pg_msg->{'status'} = undef;
        $pg_msg->{'type'}   = 'ReadyForQuery';
        return 1;
    }

    # message: B(T) "RowDescription"
    # We try to be compatible with v3 here
    #   num_fields=int16
    #   (
    #     field=String
    #     relid=undef (NOT in proto v2)
    #     attnum=undef (NOT in proto v2)
    #     type=int32
    #     type_len=int16 (-1 if variable, see pg_type.typlen)
    #     type_mod=int32 (see pg_attribute.atttypmod)
    #     format=undef (NOT in proto v2)
    #   )[num_fields]
    elsif ( $from_backend and $pg_msg->{'type'} eq 'T' ) {
        my @fields;
        my $i = 0;
        my $msg;
        my $msg_len;

        # TODO we should probably check for segmentation in here...

        ( $pg_msg->{'num_fields'} ) = unpack( 'xn', $raw_data );
        $msg = substr( $raw_data, 3 );

        $msg_len = 3;

        while ( $i < $pg_msg->{'num_fields'} ) {
            my ( $name, $type, $type_len, $type_mod )
                = unpack( 'Z*NnN', $msg );
            my @field
                = ( $name, undef, undef, $type, $type_len, $type_mod, undef );
            my $len = 11 + length( $field[0] );
            push @fields, [@field];
            $msg = substr( $msg, $len );
            $msg_len += $len;
            $i++;
        }

        $pg_msg->{'fields'} = [@fields];

        # save the number of fields for messages AsciiRow and BinaryRow
        $curr_sess->{'num_fields'} = $pg_msg->{'num_fields'};

        $pg_msg->{'type'} = 'RowDescription';
        return $msg_len;
    }

    # message: SSLAnswer (B)
    elsif ( $from_backend and $pg_msg->{'type'} eq 'SSLAnswer' ) {
        $pg_msg->{'ssl_answer'} = substr( $raw_data, 0, 1 );
        $pg_msg->{'type'} = 'SSLAnswer';
        return 1;
    }

    # message: SSLRequest (F)
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'SSLRequest' ) {
        $pg_msg->{'type'} = 'SSLRequest';
        return 8;
    }

    # message: StartupPacket (F)
    # We try to be compatible with v3 here
    #   version=2
    #   params = (param => String)
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'StartupMessage' ) {
        my $msg;
        my $params = {};

        $pg_msg->{'version'} = 2;

        $pg_msg->{'params'}->{'database'} = substr( $raw_data, 8,  64 );
        $pg_msg->{'params'}->{'user'}     = substr( $raw_data, 72, 64 );

        $pg_msg->{'params'} = $params;

        $pg_msg->{'type'} = 'StartupMessage';
        return 296;
    }

    # message: F(X) "Terminate"
    elsif ( not $from_backend and $pg_msg->{'type'} eq 'X' ) {
        $pg_msg->{'type'} = 'Terminate';
        return 1;
    }

    # we matched nothing known
    debug(
        3,
        "PGSQL: not implemented message type: %s(%s)\n",
        ( $from_backend ? 'B' : 'F' ),
        $pg_msg->{'type'}
    );

    return -1;
}

DESTROY {
    my $self = shift;

    if ( exists $pcaps{ $self->{'id'} } ) {
        $self->close();
    }

    debug( 1, "Total number of messages processed: %d\n",
        $self->{'msg_count'} );
}

1

__END__

=back

=head1 BINARIES

=over

=item *
B<pgs-debug>

Outputs the PostgreSQL messages in human readable format. Useful to analyze
what is in a network dump before using pgshark on some other duties.

=item *
B<pgs-normalize>

The C<pgs-normalize> script tries to normalize queries and prepared statements
and output them to stdout. Its purpose is to give you a list of unique queries,
whatever the number of time they have been sent by clients and whatever their
parameters were.

=item *
C<pgs-record> filters network traffic and dump PostgreSQL related activity to a
pcap file. The pcap file can then be processed with all available pgShark
tools.

C<pgs-record> rely on perl Net::Pcap module. However, unlike Net::Pcap,
C<tcpdump> is able to set a bigger capture buffer using recent libpcap. Default
buffer size is often too small to be able to dump all tcp datagram quickly
enough. Because of this buffer size (1MB), on high loaded systems, you might
loose packets. Therefor, by default, C<pgs-record> will try to act as a wrapper
around c<tcpdump> if it is available on the system and set the buffer to C<32M>.

Capturing high throughput traffic, make sure your CPU, disks and memory are
good enough to deal with the amount of data.  You might want to set the capture
buffer to 256MB or more and redirect directly to a file for future use.

=item *
B<pgs-replay>

<pgs-replay> send the PostgreSQL messages to a given PostgreSQL cluster. The
network dump could be live or from a pcap file (using tcpdump for instance).

This script only supports protocol v3, making it compatilible with versions 7.4
to 9.2 of PostgreSQL.

This script currently does not support any kind of authentication on the remote
PostgreSQL cluster where messages are send. Make sure it can connect using
ident, peer or trust.

=item *
B<pgs-sql>

Writes captured queries on stdout. Because of the SQL language doesn't support
unnamed prepared statement, this script actually try to names them. Presently,
this script doesn't support cursors nor COPY messages.

=item *
B<pgs-stats>

This script analyse the pcap traffics and outputs various statistics about
what was found in PostgreSQL protocol.

The report contains most popular queries, slowest cumulated ones, slowest
queries ever, classification of queries by type, sessions time, number of
connexion, errors, notices, etc.

The network dump could be live or from a pcap file (using tcpdump for instance).

=back

=head1 LICENSING

This program is open source, licensed under the simplified BSD license. For
license terms, see the LICENSE provided with the sources.

=head1 AUTHORS

Authors:

  * Jehan-Guillaume de Rorthais
  * Nicolas Thauvin

Copyright: (C) 2012-2013 Jehan-Guillaume de Rorthais - All rights reserved.

Dalibo's team. http://www.dalibo.org
  
=cut
