# This program is open source, licensed under the simplified BSD license.  For
# license terms, see the LICENSE file.

package pgShark::protocol_3;

use strict;
use warnings;

use Exporter;
use Pod::Usage;

our $VERSION = 0.2;
our @ISA     = ('Exporter');
our @EXPORT  = qw/pgsql_parser_backend pgsql_parser_frontend
    get_msg_type_frontend get_msg_type_backend get_msg_parser/;
our @EXPORT_OK = qw/pgsql_parser_backend pgsql_parser_frontend
    get_msg_type_frontend get_msg_type_backend get_msg_parser/;

my %frontend_msg_type = (
    'B' => 'Bind',

    # CancelRequest has no code
    'C' => 'Close',
    'd' => 'CopyData',
    'c' => 'CopyDone',
    'f' => 'CopyFail',
    'D' => 'Describe',
    'E' => 'Execute',
    'H' => 'Flush',
    'F' => 'FunctionCall',
    'P' => 'Parse',
    'p' => 'PasswordMessage',
    'Q' => 'Query',

    # SSLRequest has no code
    # StartupMessage has no code
    'S' => 'Sync',
    'X' => 'Terminate'
);

my %backend_msg_type = (
    'R' => 'Authentication',
    'K' => 'BackendKeyData',
    '2' => 'BindComplete',
    '3' => 'CloseComplete',
    'C' => 'CommandComplete',
    'W' => 'CopyBothResponse',
    'd' => 'CopyData',
    'c' => 'CopyDone',
    'G' => 'CopyInResponse',
    'H' => 'CopyOutResponse',
    'P' => 'CursorResponse',
    'D' => 'DataRow',
    'I' => 'EmptyQueryResponse',
    'E' => 'ErrorResponse',
    'V' => 'FunctionCallResponse',
    'n' => 'NoData',
    'N' => 'NoticeResponse',
    'A' => 'NotificationResponse',
    't' => 'ParameterDescription',
    'S' => 'ParameterStatus',
    '1' => 'ParseComplete',
    's' => 'PortalSuspended',
    'Z' => 'ReadyForQuery',
    'T' => 'RowDescription'
);

my %authentication_codes = (
    0 => 'AuthenticationOk',
    1 => 'AuthenticationKerberosV4',
    2 => 'AuthenticationKerberosV5',
    3 => 'AuthenticationCleartextPassword',
    4 => 'AuthenticationCryptPassword',
    5 => 'AuthenticationMD5Password',
    6 => 'AuthenticationSCMCredential',
    7 => 'AuthenticationGSS',
    9 => 'AuthenticationSSPI',
    8 => 'AuthenticationGSSContinue'
);

my %parsers = (
    'AuthenticationOk'                => \&AuthenticationOk,
    'AuthenticationKerberosV4'        => \&AuthenticationKerberosV4,
    'AuthenticationKerberosV5'        => \&AuthenticationKerberosV5,
    'AuthenticationCleartextPassword' => \&AuthenticationCleartextPassword,
    'AuthenticationCryptPassword'     => \&AuthenticationCryptPassword,
    'AuthenticationMD5Password'       => \&AuthenticationMD5Password,
    'AuthenticationSCMCredential'     => \&AuthenticationSCMCredential,
    'AuthenticationGSS'               => \&AuthenticationGSS,
    'AuthenticationSSPI'              => \&AuthenticationSSPI,
    'AuthenticationGSSContinue'       => \&AuthenticationGSSContinue,
    'BackendKeyData'                  => \&BackendKeyData,
    'Bind'                            => \&Bind,
    'BindComplete'                    => \&BindComplete,
    'CancelRequest'                   => \&CancelRequest,
    'Close'                           => \&Close,
    'CloseComplete'                   => \&CloseComplete,
    'CommandComplete'                 => \&CommandComplete,
    'CopyBothResponse'                => \&CopyBothResponse,
    'CopyData'                        => \&CopyData,
    'CopyDone'                        => \&CopyDone,
    'CopyFail'                        => \&CopyFail,
    'CopyInResponse'                  => \&CopyInResponse,
    'CopyOutResponse'                 => \&CopyOutResponse,
    'DataRow'                         => \&DataRow,
    'Describe'                        => \&Describe,
    'EmptyQueryResponse'              => \&EmptyQueryResponse,
    'ErrorResponse'                   => \&ErrorResponse,
    'Execute'                         => \&Execute,
    'Flush'                           => \&Flush,
    'FunctionCall'                    => \&FunctionCall,
    'FunctionCallResponse'            => \&FunctionCallResponse,
    'NoData'                          => \&NoData,
    'NoticeResponse'                  => \&NoticeResponse,
    'NotificationResponse'            => \&NotificationResponse,
    'ParameterDescription'            => \&ParameterDescription,
    'ParameterStatus'                 => \&ParameterStatus,
    'Parse'                           => \&Parse,
    'ParseComplete'                   => \&ParseComplete,
    'PasswordMessage'                 => \&PasswordMessage,
    'PortalSuspended'                 => \&PortalSuspended,
    'Query'                           => \&Query,
    'ReadyForQuery'                   => \&ReadyForQuery,
    'RowDescription'                  => \&RowDescription,
    'SSLAnswer'                       => \&SSLAnswer,
    'SSLRequest'                      => \&SSLRequest,
    'StartupMessage'                  => \&StartupMessage,
    'Sync'                            => \&Sync,
    'Terminate'                       => \&Terminate
);

my $backend_type_re  = qr/^([K23CGHWDIEVnNAtS1sZTdc]).{4}/s;
my $frontend_type_re = qr/^[BCfDEHFPpQSXdc].{4}/s;
my $sslanswer_re     = qr/^[NY]$/;

sub get_msg_parser($) {
    return $parsers{ $_[0] };
}

sub get_msg_len($$) {
    my $type     = shift;
    my $raw_data = shift;

    # TODO: replace with a hash ?

    return 16 if $type eq 'CancelRequest';
    return 13 if $type eq 'BackendKeyData';
    return 13 if $type eq 'AuthenticationMD5Password';
    return 11 if $type eq 'AuthenticationCryptPassword';
    return 9
        if $type eq 'AuthenticationOk'
            or $type eq 'AuthenticationKerberosV4'
            or $type eq 'AuthenticationKerberosV5'
            or $type eq 'AuthenticationCleartextPassword'
            or $type eq 'AuthenticationSCMCredential'
            or $type eq 'AuthenticationGSS'
            or $type eq 'AuthenticationSSPI';
    return 8 if $type eq 'SSLRequest';
    return 6 if $type eq 'ReadyForQuery';
    return 5
        if $type eq 'BindComplete'
            or $type eq 'CloseComplete'
            or $type eq 'CopyDone'
            or $type eq 'Flush'
            or $type eq 'EmptyQueryResponse'
            or $type eq 'NoData'
            or $type eq 'ParseComplete'
            or $type eq 'PortalSuspended'
            or $type eq 'Sync'
            or $type eq 'Terminate';

    return 1 if $type eq 'SSLAnswer';

    return $type eq 'StartupMessage'
        ? unpack( 'N',  $raw_data )
        : unpack( 'xN', $raw_data ) + 1;
}

sub get_msg_type_backend($) {
    my $raw_data = shift;

    return 'SSLAnswer' if $raw_data =~ $sslanswer_re;

    return $backend_msg_type{$1}
        if $raw_data =~ $backend_type_re;

    # message: B(R) "Authentication*"
    if ( $raw_data =~ /^R.{8}/s ) {
        my $code = unpack( 'x5N', $raw_data );

        return $authentication_codes{$code};
    }

    # not enough data (usually because of fragmented data)
    return undef if length $raw_data < 5;

    # not known !
    return '';
}

sub get_msg_type_frontend($) {
    my $raw_data = shift;

    # the message has a type byte
    return $frontend_msg_type{ substr( $raw_data, 0, 1 ) }
        if $raw_data =~ $frontend_type_re;

    if ( $raw_data =~ /^.{8}/s ) {
        my $code = unpack( 'xxxxN', $raw_data );

        return 'CancelRequest'  if $code == 80877102;
        return 'SSLRequest'     if $code == 80877103;
        return 'StartupMessage' if $code == 196608;

        # my $min = $code%65536; # == 0
        # my $maj = $code/65536; # == 3
    }

    # not known !
    return '';
}

# AuthenticationOk
#   code=int32
sub AuthenticationOk($$) {
    $_[0]{'code'} = 0;
    return 9;
}

# AuthenticationKerberosV4
#   code=int32
sub AuthenticationKerberosV4($$) {
    $_[0]{'code'} = 1;
    return 9;
}

# AuthenticationKerberosV5
#   code=int32
sub AuthenticationKerberosV5($$) {
    $_[0]{'code'} = 2;
    return 9;
}

# AuthenticationCleartextPassword
#   code=int32
sub AuthenticationCleartextPassword($$) {
    $_[0]{'code'} = 3;
    return 9;
}

# AuthenticationCryptPassword
#   code=int32
#   sal=Char[2]
sub AuthenticationCryptPassword($$) {
    $_[0]{'code'} = 4;
    $_[0]{'salt'} = substr( $_[1], 9, 2 );
    return 11;
}

# AuthenticationMD5Password
#   code=int32
#   salt=Char[4]
sub AuthenticationMD5Password($$) {
    $_[0]{'code'} = 5;
    $_[0]{'salt'} = substr( $_[1], 9, 4 );
    return 13;
}

# AuthenticationSCMCredential
#   code=int32
sub AuthenticationSCMCredential($$) {
    $_[0]{'code'} = 6;
    return 9;
}

# AuthenticationGSS
#   code=int32
sub AuthenticationGSS($$) {
    $_[0]{'code'} = 7;
    return 9;
}

# AuthenticationSSPI
#   code=int32
sub AuthenticationSSPI($$) {
    $_[0]{'code'} = 9;
    return 9;
}

# GSSAPI or SSPI authentication data
#   code=int32
#   auth_data=String
sub AuthenticationGSSContinue($$) {
    my $len = unpack( 'xN', $_[1] );

    return 0 if $len + 1 > length $_[1];

    $_[0]{'code'} = 8;
    $_[0]{'auth_data'} = substr( $_[1], 9, $len - 8 );
    return $len + 1;
}

# message: B(K) "BackendKeyData"
#   pid=int32
#   key=int32
sub BackendKeyData($$) {
    return 0 if length $_[1] < 13;

    ( $_[0]{'pid'}, $_[0]{'key'} ) = unpack( 'x5NN', $_[1] );

    return 13;
}

# message: F(B) "Bind"
#   portal=String
#   name=String
#   num_formats=int16
#   formats[]=int16[nb_formats]
#   num_params=int16
#   params[]=(len=int32,value=char[len])[nb_params]
sub Bind($$) {
    my @params_formats;
    my @params;
    my $pg_msg   = $_[0];
    my $raw_data = $_[1];
    my $len      = unpack( 'xN', $raw_data );
    my $msg;

    return 0 if $len + 1 > length $raw_data;

    # TODO refactor this mess

    ( $pg_msg->{'portal'}, $pg_msg->{'name'}, $pg_msg->{'num_formats'} )
        = unpack( 'x5Z*Z*n', $raw_data );

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
        my $len = unpack( 'l>', $msg );

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

    return $len + 1;
}

sub BindComplete ($$) { return 5 }

# message: CancelRequest (F)
#   pid=int32
#   key=int32
sub CancelRequest($$) {
    ( $_[0]{'pid'}, $_[0]{'key'} ) = unpack( 'x8NN', $_[1] );
    return 16;
}

# message: F(C) "Close"
#   kind=char
#   name=String
sub Close($$) {
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'kind'}, $_[0]{'name'} ) = unpack( 'x5AZ*', $_[1] );

    return $len;
}

sub CloseComplete ($$) { return 5 }

# message: B(C) "CommandComplete"
#   type=char
#   name=String
sub CommandComplete($$) {
    my $len;
    ( $len, $_[0]{'command'} ) = unpack( 'xNZ*', $_[1] );

    $len++;

    return 0 if $len > length $_[1];

    return $len;
}

# message: B(d) or F(d) "CopyData"
#   row=Byte[n]
sub CopyData($$) {
    my $len = unpack( 'xN', $_[1] );

    return 0 if $len + 1 > length $_[1];

    $_[0]{'row'} = substr( $_[1], 5, $len - 4 );

    return $len + 1;
}

sub CopyDone($$) { return 5 }

# message: F(f) "CopyFail"
#   error=String
sub CopyFail($$) {
    my $len;

    ( $len, $_[0]{'error'} ) = unpack( 'xNZ*', $_[1] );

    $len++;

    return 0 if $len > length $_[1];

    return $len;
}

# message: B(G) "CopyInResponse"
#   copy_format=int8
#   num_fields=int16
#   fields_formats[]=int16[num_fields]
sub CopyInResponse($$) {
    my @fields_formats;

    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'copy_format'}, @fields_formats ) = unpack( 'x5Cn/n', $_[1] );
    $_[0]{'num_fields'}     = scalar(@fields_formats);
    $_[0]{'fields_formats'} = [@fields_formats];

    return $len;
}

# message: B(D) "DataRow"
#   num_values=int16
#   (
#   value_len=int32
#   value=Byte[value_len]
#       (TODO give the format given in previous message B(T) ?)
#   )[num_values]
sub DataRow($$) {
    my @values;
    my $msg;
    my $i = 0;
    my $len = unpack( 'xN', $_[1] );

    return 0 if $len + 1 > length $_[1];

    $_[0]{'num_values'} = unpack( 'x5n', $_[1] );

    $msg = substr( $_[1], 7, $len - 6 );

    while ( $i < $_[0]{'num_values'} ) {
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

    $_[0]{'values'} = [@values];

    return $len + 1;
}

# message: F(D) "Describe"
#   kind=char
#   name=String
sub Describe($$) {
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'kind'}, $_[0]{'name'} ) = unpack( 'x5AZ*', $_[1] );

    return $len;
}

# message: B(E) "ErrorResponse"
#   (code=char
#   value=String){1,}\x00
sub ErrorResponse($$) {
    my %fields;
    my $len = unpack( 'xN', $_[1] );

    return 0 if $len + 1 > length $_[1];

    my $msg = substr( $_[1], 5, $len - 4 );

    while ( $msg ne '' ) {
        my ( $code, $value ) = unpack( 'AZ*', $msg );
        last if ( $code eq '' );
        $fields{$code} = $value;
        $msg = substr( $msg, 2 + length($value) );
    }

    $_[0]{'fields'} = \%fields;

    return $len + 1;
}

sub EmptyQueryResponse($$) { return 5 }

# message: F(E) "Execute"
#   name=String
#   nb_rows=int32
sub Execute($$) {
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'name'}, $_[0]{'nb_rows'} ) = unpack( 'x5Z*N', $_[1] );

    return $len;
}

sub Flush($$) { return 5 }

# message: F(F) "FunctionCall"
#   func_oid=Int32
#   num_args_formats=Int16
#   args_formats[]=int16[nb_formats]
#   num_args=Int16
#   args[]=(len=int32,value=Byte[len])[nb_args]
#   result_format=Int16
# TODO: NOT TESTED yet
sub FunctionCall($$) {
    my @args_formats;
    my @args;
    my $msg;
    my $len = unpack( 'xN', $_[1] );

    return 0 if $len + 1 > length $_[1];

    ( $_[0]{'func_oid'}, @args_formats ) = unpack( 'x5Nn/n n', $_[1] );

    $_[0]{'num_args'}         = pop @args_formats;
    $_[0]{'num_args_formats'} = scalar(@args_formats);
    $_[0]{'args_formats'}     = [@args_formats];

    $msg = substr( $_[1], 5 + 8 + $_[0]{'num_args_formats'} * 2 );

    for ( my $i = 0; $i < $_[0]{'num_args'}; $i++ ) {

        # unpack hasn't 32bit signed network template, so we use l>
        my $len = unpack( 'l>', $msg );

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

    $_[0]{'params'} = [@args];
    $_[0]{'result_format'} = unpack( 'n', $msg );

    return $len + 1;
}

# message: B(V) "FunctionCallResponse"
#   len=Int32
#   value=Byte[len]
# TODO: NOT TESTED yet
sub FunctionCallResponse($$) {
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    $_[0]{'len'} = unpack( 'x5l>', $_[1] );

    # if len < 0; the value is NULL
    if ( $_[0]{'len'} > 0 ) {
        $_[0]{'value'} = substr( $_[1], 4, $_[0]{'len'} );
    }
    elsif ( $_[0]{'len'} == 0 ) {
        $_[0]{'value'} = '';
    }
    else {    # value is NULL
        $_[0]{'value'} = undef;
    }

    return $len;
}

sub NoData($$) { return 5 }

# message: B(A) "NotificationResponse"
#   pid=int32
#   channel=String
#   payload=String
sub NotificationResponse($$) {
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'pid'}, $_[0]{'channel'}, $_[0]{'payload'} )
        = unpack( 'x5NZ*Z*', $_[1] );

    return $len;
}

# message: B(t) "ParameterDescription"
#   num_params=int16
#   params_types[]=int32[nb_formats]
sub ParameterDescription($$) {
    my @params_types;
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    @params_types = unpack( 'x5n/N', $_[1] );
    $_[0]{'num_params'}   = scalar(@params_types);
    $_[0]{'params_types'} = [@params_types];

    return $len;
}

# message: B(S) "ParameterStatus"
#   name=String
#   value=String
sub ParameterStatus($$) {
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'name'}, $_[0]{'value'} ) = unpack( 'x5Z*Z*', $_[1] );

    return $len;
}

# message: F(P) "Parse"
#   name=String
#   query=String
#   num_params=int16
#   params_types[]=int32[nb_formats]
sub Parse($$) {
    my @params_types;
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'name'}, $_[0]{'query'}, @params_types )
        = unpack( 'x5Z*Z*n/N', $_[1] );

    $_[0]{'num_params'}   = scalar(@params_types);
    $_[0]{'params_types'} = [@params_types];

    return $len;
}

sub ParseComplete($$) { return 5 }

# message: F(p) "PasswordMessage"
#    password=String
sub PasswordMessage($$) {
    my $len;
    ( $len, $_[0]{'password'} ) = unpack( 'xNZ*', $_[1] );

    $len++;

    return 0 if $len > length $_[1];

    return $len;
}

sub PortalSuspended($$) { return 5 }

# message: F(Q) "Query"
#    query=String
sub Query($$) {
    my $len;
    ( $len, $_[0]{'query'} ) = unpack( 'xNZ*', $_[1] );

    $len++;

    return 0 if $len > length $_[1];

    return $len;
}

# message: B(Z) "ReadyForQuery"
#   status=Char
sub ReadyForQuery($$) {
    return 0 if length $_[1] < 6;

    $_[0]{'status'} = substr( $_[1], 5, 1 );

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
sub RowDescription($$) {
    my @fields;
    my $i = 0;
    my $msg;
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    $_[0]{'num_fields'} = unpack( 'x5n', $_[1] );

    $msg = substr( $_[1], 7 );

    while ( $i < $_[0]{'num_fields'} ) {
        my @field = unpack( 'Z*NnNnNn', $msg );
        push @fields, [@field];
        $msg = substr( $msg, 19 + length( $field[0] ) );

        $i++;
    }

    $_[0]{'fields'} = [@fields];

    return $len;
}

# message: SSLAnswer (B)
sub SSLAnswer($$) {
    $_[0]{'ssl_answer'} = substr( $_[1], 0, 1 );

    return 1;
}

sub SSLRequest($$) { return 8 }

# message: StartupMessage (F)
#   status=Char
#   (param=String
#   value=String){1,}\x00
sub StartupMessage($$) {
    my $msg;
    my $len = unpack( 'N', $_[1] );
    my %params;

    return 0 if $len > length $_[1];

    $_[0]{'version'} = 3;

    $msg = substr( $_[1], 8 );    # ignore the version fields

    while ( $msg ne '' ) {
        my ( $param, $value ) = unpack( 'Z*Z*', $msg );
        last if ( $param eq '' );
        $params{$param} = $value;
        $msg = substr( $msg, 2 + length($param) + length($value) );
    }

    $_[0]{'params'} = \%params;

    return $len;
}

sub Sync($$) { return 5 }

sub Terminate($$) { return 5 }

BEGIN {
    *CopyBothResponse = \&CopyInResponse;
    *CopyOutResponse  = \&CopyInResponse;
    *NoticeResponse   = \&ErrorResponse;
}

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

sub pgsql_parser_backend($$;$) {
    my $pg_msg   = shift;
    my $raw_data = shift;
    my $type     = get_msg_type_backend($raw_data);

    return 0 if not defined $type;

    $pg_msg->{'type'} = $type;

    # messages without payload
    return 5
        if $type eq 'BindComplete'
            or $type eq 'CloseComplete'
            or $type eq 'CopyDone'
            or $type eq 'EmptyQueryResponse'
            or $type eq 'NoData'
            or $type eq 'ParseComplete'
            or $type eq 'PortalSuspended';

    return &{ $parsers{$type} }( $pg_msg, $raw_data )
        if ( defined $parsers{$type} );

    # catchall / debug message ?

    return -1;
}

sub pgsql_parser_frontend($$;$) {
    my $pg_msg   = shift;
    my $raw_data = shift;
    my $type;

    $type = get_msg_type_frontend($raw_data);

    return 0 if not defined $type;

    $pg_msg->{'type'} = $type;

    # messages without payload
    return 5
        if $type eq 'CopyDone'
            or $type eq 'Flush',
            or $type eq 'Sync',
            or $type eq 'Terminate';

    return 8 if $type eq 'SSLRequest';

    return &{ $parsers{$type} }( $pg_msg, $raw_data )
        if ( defined $parsers{$type} );

    # catchall / debug message ?

    return -1;
}

1
