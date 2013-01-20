# This program is open source, licensed under the simplified BSD license.  For
# license terms, see the LICENSE file.

package pgShark::protocol_2;

use strict;
use warnings;

use Exporter;
use Pod::Usage;

our $VERSION   = 0.2;
our @ISA       = ('Exporter');
our @EXPORT    = qw/pgsql_parser/;
our @EXPORT_OK = qw/pgsql_parser/;

=item *
B<pgsql_parser (\%pg_msg, $from_backend, $data, \%state)>

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

sub pgsql_parser {
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
        # if ( get_debug_lvl() > 2 ) {
        #     $raw_data =~ tr/\x00-\x1F\x7F-\xFF/./;
        #     debug(
        #         3,
        #         "WARNING: dropped alien packet (from_backend: %d) I was unable to mess with at timestamp %s:\n'%s'\n",
        #         $from_backend,
        #         $pg_msg->{'timestamp'},
        #         $raw_data
        #     );
        # }
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
    # debug(
    #     3,
    #     "PGSQL: not implemented message type: %s(%s)\n",
    #     ( $from_backend ? 'B' : 'F' ),
    #     $pg_msg->{'type'}
    # );

    return -1;
}

1