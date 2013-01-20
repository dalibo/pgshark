# This program is open source, licensed under the simplified BSD license.  For
# license terms, see the LICENSE file.

package pgShark::protocol_3;

use strict;
use warnings;

use Exporter;
use Pod::Usage;

our $VERSION   = 0.2;
our @ISA       = ('Exporter');
our @EXPORT    = qw/pgsql_parser/;
our @EXPORT_OK = qw/pgsql_parser/;

=item *
B<pgsql_parser (\%pg_msg, $from_backend, $data)>

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

sub pgsql_parser {
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
            # debug(
            #     3,
            #     "NOTICE: message fragmented (data available: %d, total message length: %d), waiting for more bits.\n",
            #     $data_len,
            #     $msg_len + 1
            # );
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
        # debug(
        #     3,
        #     "NOTICE: buffer full of junk or empty (data available: %d)...waiting for more bits.\n",
        #     $data_len
        # );
        my $d = $raw_data;
        $d =~ tr/\x00-\x1F\x7F-\xFF/./;
        # debug( 3, "HINT: data are: «%s»\n", $d );
        return 0;
    }

    if ( not defined $pg_msg->{'type'} ) {
        # if ( get_debug_lvl() > 2 ) {
        #     $raw_data =~ tr/\x00-\x1F\x7F-\xFF/./;
        #     debug(
        #         3,
        #         "WARNING: dropped alien packet I was unable to mess with at timestamp %s:\n'%s'\n",
        #         $pg_msg->{'timestamp'},
        #         $raw_data
        #     );
        # }
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

        # AuthenticationCryptPassword
        #   code=int32
        #   sal=Char[2]
        elsif ( $pg_msg->{'code'} == 4) {
            $pg_msg->{'salt'} = substr( $raw_data, 9, 2 );
            $pg_msg->{'type'} = 'AuthenticationCryptPassword';
            return 11;
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

1