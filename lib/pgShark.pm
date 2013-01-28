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
our $VERSION   = 0.2;
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

One messages type has been added to both protocols: SSLAnswer.

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
        'sessions'   => {},
        'can_detect_sr' => 0
    };

    # Converts the dot'ed IPADDR of the host to decimal
    # to dirct compare with address given from libpcap
    my ( $na, $nb, $nc, $nd ) = split /\./, $self->{'host'};
    $self->{'host'} = ( $na << 24 ) + ( $nb << 16 ) + ( $nc << 8 ) + ($nd);

    # register callbacks for given pgsql messages
    foreach my $func ( keys %{ $args{'procs'} } ) {
        $self->{$func} = $args{'procs'}->{$func};
    }

    $self->{'can_detect_sr'} = 1 if defined ($self->{'CopyBothResponse'})
        or (defined ($self->{'CopyData'}) and defined ($self->{'CopyDone'}));

    if ( $self->{'protocol'} eq '2' ) {
        eval 'use pgShark::protocol_2';
        die 'Could not load module pgShark::protocol_2!' if $@;
    }
    else {
        eval 'use pgShark::protocol_3';
        die 'Could not load module pgShark::protocol_3!' if $@;
    }

    set_debug( $args{'debug'} ) if defined( $args{'debug'} );

    debug( 1, "A %s shark is borned.\n", $VERSION );

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
  #     if $self->{'pcap'};

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
    my ( $sess_hash, $monolog, $from, $is_fin );

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
        $from = 'B';
        $sess_hash    = $dest_ip . $dest_port;
    }
    else {
        $from = 'F';
        $sess_hash    = $src_ip . $src_port;
    }

    if ($is_fin) {
        delete $self->{'sessions'}{$sess_hash};
        debug( 4,
            "TCP session finished (FIN or RST). Pgsql session dropped.\n" );
        return;
    }

    if ( not defined( $self->{'sessions'}->{$sess_hash} ) ) {
        debug( 3, "PGSQL: creating a new session %s\n", $sess_hash );
        $self->{'sessions'}{$sess_hash} = {
            'F' => { # frontend
                'data'     => '',    # raw tcp data
                'next_seq' => -1,
                'segs'     => [],    # segments buffer
            },
            'B' => { # backend
                'data'     => '',    # raw tcp data
                'next_seq' => -1,
                'segs'     => [],    # segments buffer
            }
        };
    }

    if ( $self->{'sessions'}{$sess_hash} eq 'SSL' ) {
        debug( 3, "PGSQL: session %s encrypted, ignore.\n", $sess_hash );
        return;
    }

    $monolog = $self->{'sessions'}{$sess_hash}{$from};

    $monolog->{'next_seq'} = $seqnum;

    push @{ $monolog->{'segs'} },
        (
        {   'seq'  => $seqnum,
            'len'  => $tcp_len,
            'data' => $data
        }
        );

    debug( 5, "TCP/IP: %s-%s: segment in the buff: %d\n",
        $sess_hash, $from, scalar @{ $monolog->{'segs'} } );

    # we loop over existing tcp segments trying to find the best one to
    # reconstruct the data
    my $i = 0;
    foreach my $segment ( @{ $monolog->{'segs'} } ) {

        # normal
        if ( $monolog->{'next_seq'} == $segment->{'seq'} ) {

            debug( 5, "TCP/IP: %s-%s: perfect sequence\n",
                $sess_hash, $from );

            # add data to the current session's buffer
            $monolog->{'data'} .= $segment->{'data'};
            $monolog->{'next_seq'}
                = $monolog->{'next_seq'} + $segment->{'len'};

            splice @{ $monolog->{'segs'} }, $i, 1;
        }

        # tcp's data begins in past but finish in future
        elsif (
            ( $monolog->{'next_seq'} >= $segment->{'seq'} )
            and ( $monolog->{'next_seq'}
                < $segment->{'seq'} + $segment->{'len'} )
            )
        {
            debug(
                5,
                "TCP/IP: %s-%s: segment start in the past but complete data\n",
                $sess_hash,
                $from
            );
            my $offset = $monolog->{'next_seq'} - $segment->{'seq'};

            # add data to the current session's buffer
            $monolog->{'data'} .= substr( $segment->{'data'}, $offset );
            $monolog->{'next_seq'}
                = $monolog->{'next_seq'} + $segment->{'len'} - $offset;

            splice @{ $monolog->{'segs'} }, $i, 1;
        }

        # tcp segment already done, drop it
        elsif ( $monolog->{'next_seq'}
            >= $segment->{'seq'} + $segment->{'len'} )
        {
            debug( 5, "TCP/IP: %s-%s: segment in the past.\n",
                $sess_hash, $from );
            splice @{ $monolog->{'segs'} }, $i, 1;
        }

        # tcp's in the future, we keep it in the segment buffer
        else {
            debug(
                5,
                "TCP/IP: %s-%s:  tcp's in the future, next_seq: %d, seq: %d-%d.\n",
                $sess_hash,
                $from,
                $monolog->{'next_seq'},
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
        'from' => $from,

        # timestamps of the message
        'timestamp' => "$pckt_hdr->{'tv_sec'}."
            . sprintf( '%06d', $pckt_hdr->{'tv_usec'} ),
        ## the following entries will be feeded bellow
        # 'type' => message type. Either one-char type or full message for
        #           special ones
        # 'data' =>  the message data (without the type and int32 length)
        ## other fields specifics to each messages are added bellow
    };

    # if dissecting the buffer fails, reset the data for this half-part of a
    # session
    if ( $self->pgsql_dissect($pg_msg) != 0 ) {
        $self->{'sessions'}{$sess_hash}{$from} = {
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
# @param pg_msg_orig    The hash's skeleton to use to construct a pgsql hash
#                       message.
#                       It already contains tcp and other global infos.
sub pgsql_dissect {
    my $self         = shift;
    my $pg_msg_orig  = shift;
    my $sess_hash    = $pg_msg_orig->{'sess_hash'};
    my $from         = $pg_msg_orig->{'from'};

    my $sess = $self->{'sessions'}{$sess_hash};
    my $monolog = $self->{'sessions'}{$sess_hash}{$from};

    my $data_len = length $monolog->{'data'};

    do {

        # copy base message properties hash for this new message
        my $pg_msg = {%$pg_msg_orig};
        my $msg_len;
        my $type
            = $from eq 'B'
            ? get_msg_type_backend( $monolog->{'data'}, $sess )
            : get_msg_type_frontend( $monolog->{'data'}, $sess );

        if ( not defined $type ) {
            debug(
                3,
                "NOTICE: buffer full of junk or empty (data available: %d)...waiting for more bits.\n",
                $data_len
            );
            debug( 6, "DEBUG: last packet was: %s\n", $monolog->{'data'} );
            return 0;
        }

        if ( $type eq '' ) {
            debug(
                3,
                "WARNING: dropped alien packet at timestamp %s!\n",
                $pg_msg->{'timestamp'}
            );
            debug( 6, "DEBUG: alien packet was: %s\n", $monolog->{'data'} );
            return -1;
        }

        if ( defined $self->{$type} ) {
            $pg_msg->{'type'} = $type;

            $msg_len
                = &{ get_msg_parser( $type ) }( $pg_msg, $monolog->{'data'},
                $sess );

            # Simple streaming replication auto-detect. If both sides are
            # talking over a CopyData stream before the Copy mode is done,
            # then we are in replication mode !
            if ($self->{'can_detect_sr'} and not $sess->{'replication'}) {
                debug(1, "LOG: trying to detect streaming replication for session %s\n"
                    , $sess_hash
                ) unless defined $sess->{'copy_from'};

                if ($type eq 'CopyDone') {
                    delete $sess->{'copy_from'};
                }
                elsif ($type eq 'CopyData'
                    and not defined $sess->{'copy_from'})
                {
                    $sess->{'copy_from'} = $from;
                }
                elsif ($type eq 'CopyData') {
                    unless ($sess->{'copy_from'} eq $from) {
                        $sess->{'replication'} = 1;

                        debug(1, "LOG: streaming replication detected for session %s!\n"
                            , $sess_hash
                        );

                        # recompute type and parsing
                        $type = $from eq 'B'
                            ? get_msg_type_backend( $monolog->{'data'}, $sess )
                            : get_msg_type_frontend( $monolog->{'data'}, $sess );
                        $msg_len = &{ get_msg_parser( $type ) }
                            ( $pg_msg, $monolog->{'data'}, $sess );
                    }
                }
            }

            # we don't have enough data for the current message (0)
            # or an error occured (<0)
            return $msg_len if $msg_len < 1;

            # extract the message data from the buffer
            $pg_msg->{'data'} = substr( $monolog->{'data'}, 0, $msg_len );

            # callback for this message type
            &{ $self->{$type} }( $pg_msg );
        }
        else {
            $msg_len = get_msg_len( $type, $monolog->{'data'}, $sess );
        }

        # we don't have enough data for the current message (0)
        # or an error occured (<0)
        return $msg_len if $msg_len < 1;

        # here, we processed some data

        $self->{'msg_count'}++;

        debug(
            3,
            "PGSQL: pckt=%d, timestamp=%s, session=%s type=%s, msg_len=%d, data_len=%d\n",
            $self->{'pckt_count'},
            $pg_msg->{'timestamp'},
            $sess_hash,
            $type,
            $msg_len,
            $data_len
        );

        # if the message was Terminate, destroy the session
        if ( $type eq 'Terminate' ) {
            debug(
                3,
                "PGSQL: destroying session %s (remaining buffer was %d byte long).\n",
                $sess_hash,
                $data_len
            );

            delete $self->{'sessions'}{$sess_hash};
            $monolog = undef;
            return 0;
        }

        if ( $type eq 'SSLAnswer' and $monolog->{'data'} =~ /^Y/ ) {
            debug( 3,
                "PGSQL: session %s will be encrypted so we ignore it.\n",
                $sess_hash );
            delete $self->{'sessions'}{$sess_hash};
            $monolog = undef;
            $self->{'sessions'}{$sess_hash} = 'SSL';
            return 0;
        }

        # remove processed data from the buffer
        $monolog->{'data'} = substr( $monolog->{'data'}, $msg_len );
        $data_len -= $msg_len;

    } while ( $data_len > 0 );

    return 0;
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

For details, see the output of parameter C<--help> for each of them.

=over

=item *
B<pgs-badger>

This script analyse the pcap traffics and outputs various statistics about
what was found in PostgreSQL protocol.

The report contains most popular queries, slowest cumulated ones, slowest
queries ever, classification of queries by type, sessions time, number of
connexion, errors, notices, etc.

The network dump could be live or from a pcap file (using tcpdump for instance).

In a futur version this script is supposed to talk with pgbadger directly !

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
B<pgs-record>

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
B<pgs-stat>

Outputs various informations about PostgreSQL activity on the network on a
given sampling period.

=back

=head1 SEE ALSO

This module rely on two modules to parse message of protocols v2 and v3:
B<pgShark::protocol_2> and B<pgShark::protocol_3>.

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
