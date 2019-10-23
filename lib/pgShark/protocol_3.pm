# This program is open source, licensed under the simplified BSD license.  For
# license terms, see the LICENSE file.

=head1 pgShark::protocol_3

pgShark::protocol_3 - is the collection of functions able to deal with procol
v2 of PostgreSQL

=head1 DESCRIPTION

This Perl module is aimed to be used by module pgShark. However, its functions
can be useful for other purpose to deal or parse PostgreSQL message of
protocol v3.

Some messages properties depends to previous ones.  Because of this, in
most function, this is the responsability of the caller to keep track of the
state of each sessions by giving a hashref where states are kept. This hashref
**MUST** concern the ONLY current session (Frontend/Backend couple) data are
parsed for.

=head1 FUNCTIONS

=over

=cut

package pgShark::protocol_3;

use strict;
use warnings;

use Exporter;
use Pod::Usage;

our $VERSION = 0.2;
our @ISA     = ('Exporter');
our @EXPORT  = qw/pgsql_parser_backend pgsql_parser_frontend
    get_msg_type_frontend get_msg_type_backend get_msg_parser get_msg_len/;
our @EXPORT_OK = qw/pgsql_parser_backend pgsql_parser_frontend
    get_msg_type_frontend get_msg_type_backend get_msg_parser get_msg_len/;

my %frontend_msg_type = (
    'B' => 'Bind',
    # CancelRequest has no code
    'C' => 'Close',
    'd' => 'CopyData', # backend and frontend message
    'c' => 'CopyDone', # backend and frontend message
    'f' => 'CopyFail',
    'D' => 'Describe',
    'E' => 'Execute',
    'H' => 'Flush',
    'F' => 'FunctionCall',
    'P' => 'Parse',
    'p' => 'PasswordMessage', # or GSSResponse or SASLInitialResponse or SASLResponse
    'Q' => 'Query',
    # SSLRequest has no code
    # GSSENCRequest has no code
    # StartupMessage has no code
    'S' => 'Sync',
    'X' => 'Terminate'
);
# pre-compile to save time during parsing
# do not include 'd' which is checked if neither of bellow msg match during parsing
my $frontend_type_re = qr/^([BCcfDEHFPpQSX]).{4}/s;

my %backend_msg_type = (
    'R' => 'Authentication',
    'K' => 'BackendKeyData',
    '2' => 'BindComplete',
    '3' => 'CloseComplete',
    'C' => 'CommandComplete',
    'd' => 'CopyData', # backend and frontend message
    'c' => 'CopyDone', # backend and frontend message
    'G' => 'CopyInResponse',
    'H' => 'CopyOutResponse',
    'W' => 'CopyBothResponse',
    'D' => 'DataRow',
    'I' => 'EmptyQueryResponse',
    'E' => 'ErrorResponse',
    'V' => 'FunctionCallResponse',
    'v' => 'NegotiateProtocolVersion',
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
# pre-compile to save time during parsing
# do not include 'R' and 'd' which are checked if neither of bellow msg match during parsing
my $backend_type_re  = qr/^([ K23CcGHWDIEVvnNAtS1sZT]).{4}/s;

my %authentication_codes = (
    0 => 'AuthenticationOk',
    1 => 'AuthenticationKerberosV4',
    2 => 'AuthenticationKerberosV5',
    3 => 'AuthenticationCleartextPassword',
    4 => 'AuthenticationCryptPassword',
    5 => 'AuthenticationMD5Password',
    6 => 'AuthenticationSCMCredential',
    7 => 'AuthenticationGSS',
    8 => 'AuthenticationGSSContinue',
    9 => 'AuthenticationSSPI',
    10 => 'AuthenticationSASL',
    11 => 'AuthenticationSASLContinue',
    12 => 'AuthenticationSASLFinal'
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
    'AuthenticationSASL'              => \&AuthenticationSASL,
    'AuthenticationSASLContinue'      => \&AuthenticationSASLContinue,
    'AuthenticationSASLFinal'         => \&AuthenticationSASLFinal,
    'BackendKeyData'                  => \&BackendKeyData,
    'Begin'                           => \&Begin,
    'Bind'                            => \&Bind,
    'BindComplete'                    => \&BindComplete,
    'CancelRequest'                   => \&CancelRequest,
    'Close'                           => \&Close,
    'CloseComplete'                   => \&CloseComplete,
    'CommandComplete'                 => \&CommandComplete,
    'Commit'                          => \&Commit,
    'CopyBothResponse'                => \&CopyBothResponse,
    'CopyData'                        => \&CopyData,
    'CopyDone'                        => \&CopyDone,
    'CopyFail'                        => \&CopyFail,
    'CopyInResponse'                  => \&CopyInResponse,
    'CopyOutResponse'                 => \&CopyOutResponse,
    'DataRow'                         => \&DataRow,
    'Delete'                          => \&Delete,
    'Describe'                        => \&Describe,
    'EmptyQueryResponse'              => \&EmptyQueryResponse,
    'ErrorResponse'                   => \&ErrorResponse,
    'Execute'                         => \&Execute,
    'Flush'                           => \&Flush,
    'FunctionCall'                    => \&FunctionCall,
    'FunctionCallResponse'            => \&FunctionCallResponse,
    'GSSENCRequest'                   => \&GSSENCRequest,
    'GSSResponse'                     => \&GSSResponse,
    'HotStandbyFeedback'              => \&HotStandbyFeedback,
    'Insert'                          => \&Insert,
    'NegotiateProtocolVersion'        => \&NegotiateProtocolVersion,
    'NoData'                          => \&NoData,
    'NoticeResponse'                  => \&NoticeResponse,
    'NotificationResponse'            => \&NotificationResponse,
    'Origin'                          => \&Origin,
    'ParameterDescription'            => \&ParameterDescription,
    'ParameterStatus'                 => \&ParameterStatus,
    'Parse'                           => \&Parse,
    'ParseComplete'                   => \&ParseComplete,
    'PasswordMessage'                 => \&PasswordMessage,
    'PortalSuspended'                 => \&PortalSuspended,
    'PrimaryKeepalive'                => \&PrimaryKeepalive,
    'Query'                           => \&Query,
    'ReadyForQuery'                   => \&ReadyForQuery,
    'Relation'                        => \&Relation,
    'RowDescription'                  => \&RowDescription,
    'SASLInitialResponse'             => \&SASLInitialResponse,
    'SASLResponse'                    => \&SASLResponse,
    'SSLAnswer'                       => \&SSLAnswer,
    'SSLRequest'                      => \&SSLRequest,
    'StandbyStatusUpdate'             => \&StandbyStatusUpdate,
    'StartupMessage'                  => \&StartupMessage,
    'Sync'                            => \&Sync,
    'Terminate'                       => \&Terminate,
    'Truncate'                        => \&Truncate,
    'Type'                            => \&Type,
    'Update'                          => \&Update,
    'XLogData'                        => \&XLogData
);

my $sslanswer_re     = qr/^[NY]$/;

=item *
B<get_msg_parser ($data)>

Retruns a subref able to parse the message of type given as parameter one.

The parser sub takes three args:

    &{ $parser} (\%msg_props, $data, \%state)

First parameter is a hashref where the message properties will be set. The
second one is the data to parse the message from and the third one helps to keep
track of the session status.

=cut

sub get_msg_parser($) {
    return $parsers{ $_[0] };
}

=item *
B<get_msg_len ($type, $data, \%state)>

Returns the length of the message of given as second parameter according to the
type given as first parameter. Returns 0 when the message is not complete.

The third parameter is used to keep track of session state.

=cut

sub get_msg_len($$$) {
    my $type     = $_[0];
    my $raw_data = $_[1];
    my $len      = length $_[1];
    my $ret;

    # TODO: replace with a hash ?

    return ( 16 <= $len ? 16 : 0 ) if $type eq 'CancelRequest';
    return ( 13 <= $len ? 13 : 0 )
        if $type eq 'BackendKeyData'
            or $type eq 'AuthenticationMD5Password';
    return ( 11 <= $len ? 11 : 0 ) if $type eq 'AuthenticationCryptPassword';
    return ( 9 <= $len ? 9 : 0 )
        if $type eq 'AuthenticationOk'
            or $type eq 'AuthenticationKerberosV4'
            or $type eq 'AuthenticationKerberosV5'
            or $type eq 'AuthenticationCleartextPassword'
            or $type eq 'AuthenticationSCMCredential'
            or $type eq 'AuthenticationGSS'
            or $type eq 'AuthenticationSSPI';
    return ( 8 <= $len ? 8 : 0 ) if $type eq 'SSLRequest' or $type eq 'GSSENCRequest';
    return ( 6 <= $len ? 6 : 0 ) if $type eq 'ReadyForQuery';
    return ( 5 <= $len ? 5 : 0 )
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

    $ret
        = $type eq 'StartupMessage'
        ? unpack( 'N',  $raw_data )
        : unpack( 'xN', $raw_data ) + 1;

    return ( $ret <= $len ) ? $ret : 0;
}

=item *
B<get_msg_type_backend ($data, \%state)>

Returns the type of a message coming from the backend. Message is given as
first parameter.

The second parameter helps to keep track of the session state. As this function
is responsible to detect the type of messages, it has reponsability to set the
state of each session.

=cut

sub get_msg_type_backend($$) {
    my $raw_data = $_[0];
    my $state    = $_[1];

    return 'SSLAnswer' if $raw_data =~ $sslanswer_re;

    return $backend_msg_type{$1}
        if $raw_data =~ $backend_type_re;

    # message: B(R) "Authentication*"
    if ( $raw_data =~ /^R.{8}/s ) {
        my $code = unpack( 'x5N', $raw_data );

        return $authentication_codes{$code};
    }

    if ( $raw_data =~ /^d.{4}/ ) {
        return 'CopyData' unless defined $state->{'replication'};
        return undef if length $raw_data < 6;

        my $type = unpack( 'x5A', $raw_data );

        return 'PrimaryKeepalive' if $type eq 'k';
        if ( $type eq 'w'
        and  defined $state->{'replication'}
        and  defined $state->{'logical'} ) {
            my $type = unpack( 'x30A', $raw_data );
            return 'Begin'    if $type eq 'B';
            return 'Commit'   if $type eq 'C';
            return 'Origin'   if $type eq 'O';
            return 'Relation' if $type eq 'R';
            return 'Type'     if $type eq 'Y';
            return 'Insert'   if $type eq 'I';
            return 'Update'   if $type eq 'U';
            return 'Delete'   if $type eq 'D';
            return 'Truncate' if $type eq 'T';

            # fallback
            return 'XLogData';
        }
        else {
            return 'XLogData' if $type eq 'w';
        }

        # not known !
        return '';
    }

    # not enough data (usually because of fragmented data)
    return undef if length $raw_data < 5;

    # not known !
    return '';
}

=item *
B<get_msg_type_frontend ($data, \%state)>

Returns the type of a message coming from the frontend. Message is given as
first parameter.

The second parameter helps to keep track of the session state. As this function
is responsible to detect the type of messages, it has reponsability to set the
state of each session.

=cut

sub get_msg_type_frontend($$) {
    my $raw_data = $_[0];
    my $state    = $_[1];

    # the message has a type byte
    return $frontend_msg_type{$1}
        if $raw_data =~ $frontend_type_re;

    if ( $raw_data =~ /^d.{4}/ ) {
        return 'CopyData' unless defined $state->{'replication'};

        return undef if length $raw_data < 6;

        my $type = unpack( 'xxxxxA', $raw_data );

        return 'StandbyStatusUpdate' if $type eq 'r';
        return 'HotStandbyFeedback'  if $type eq 'h';

        # not known !
        return '';
    }

    if ( $raw_data =~ /^.{8}/s ) {
        my $code = unpack( 'xxxxN', $raw_data );

        return 'CancelRequest'  if $code == 80877102;
        return 'GSSENCRequest'  if $code == 80877104;
        return 'SSLRequest'     if $code == 80877103;
        return 'StartupMessage' if $code == 196608;

        # my $min = $code%65536; # == 0
        # my $maj = $code/65536; # == 3
    }

    # not enough data (usually because of fragmented data)
    return undef if length $raw_data < 5;

    # not known !
    return '';
}

=item *
B<pgsql_parser_backend (\%pg_msg, $data, \%state)>

Parse and dissect a buffer, looking for a valid pgsql v3 message coming from
the backend. Then it sets the given hashref as first parameter with the message
properties. Properties set in the given hashref depend on the message type. See
the function code comments for more information about them.

The data to parsed are given as second parameter.

The third parameter helps to keep track of the state of each
sessions by giving a hashref as third parameter.

CAUTION: This function MUST returns the total length of the parsed message so
it can be removed from the TCP monolog buffer. 0 means lack of data to
process the current message. On error, returns -1

=cut

sub pgsql_parser_backend($$$) {
    my $pg_msg   = $_[0];
    my $raw_data = $_[1];
    my $state    = $_[2];
    my $type     = get_msg_type_backend( $raw_data, $state );

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

=item *
B<pgsql_parser_frontend (\%pg_msg, $data, \%state)>

Parse and dissect a buffer, looking for a valid pgsql v3 message coming from a
frontend. It sets the given hashref as first parameter with the message
properties. Properties set in the given hashref depend on the message type. See
the function code comments for more information about them.

The data to parsed are given as second parameter.

The third parameter helps to keep track of the state of each
sessions by giving a hashref as third parameter.

CAUTION: This function MUST returns the total length of the parsed message so
it can be removed from the TCP monolog buffer. 0 means lack of data to
process the current message. On error, returns -1

=cut

sub pgsql_parser_frontend($$$) {
    my $pg_msg   = $_[0];
    my $raw_data = $_[1];
    my $state    = $_[2];
    my $type     = get_msg_type_frontend( $raw_data, $state );

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

# AuthenticationOk
#   code=int32
sub AuthenticationOk($$$) {
    $_[0]{'code'} = 0;
    return 9;
}

# AuthenticationKerberosV4
#   code=int32
sub AuthenticationKerberosV4($$$) {
    $_[0]{'code'} = 1;
    return 9;
}

# AuthenticationKerberosV5
#   code=int32
sub AuthenticationKerberosV5($$$) {
    $_[0]{'code'} = 2;
    return 9;
}

# AuthenticationCleartextPassword
#   code=int32
sub AuthenticationCleartextPassword($$$) {
    $_[0]{'code'} = 3;
    return 9;
}

# AuthenticationCryptPassword
#   code=int32
#   sal=Char[2]
sub AuthenticationCryptPassword($$$) {
    $_[0]{'code'} = 4;
    $_[0]{'salt'} = substr( $_[1], 9, 2 );
    return 11;
}

# AuthenticationMD5Password
#   code=int32
#   salt=Char[4]
sub AuthenticationMD5Password($$$) {
    $_[0]{'code'} = 5;
    $_[0]{'salt'} = substr( $_[1], 9, 4 );
    return 13;
}

# AuthenticationSASL
#   code=int32
#   name=String
sub AuthenticationSASL($$$) {
    my $len = unpack( 'xN', $_[1] );

    return 0 if $len + 1 > length $_[1];

    $_[0]{'code'} = 10;
    $_[0]{'name'} = substr( $_[1], 9, $len - 8 );

    return $len + 1;
}

# AuthenticationSASLContinue
#   code=int32
#   data=String
sub AuthenticationSASLContinue($$$) {
    my $len = unpack( 'xN', $_[1] );

    return 0 if $len + 1 > length $_[1];

    $_[0]{'code'} = 11;
    $_[0]{'data'} = substr( $_[1], 9, $len - 8 );

    return $len + 1;
}

# AuthenticationSASLFinal
#   code=int32
#   name=String
sub AuthenticationSASLFinal($$$) {
    my $len = unpack( 'xN', $_[1] );

    return 0 if $len + 1 > length $_[1];

    $_[0]{'code'} = 12;
    $_[0]{'data'} = substr( $_[1], 9, $len - 8 );

    return $len + 1;
}

# AuthenticationSCMCredential
#   code=int32
sub AuthenticationSCMCredential($$$) {
    $_[0]{'code'} = 6;
    return 9;
}

# AuthenticationGSS
#   code=int32
sub AuthenticationGSS($$$) {
    $_[0]{'code'} = 7;
    return 9;
}

# AuthenticationSSPI
#   code=int32
sub AuthenticationSSPI($$$) {
    $_[0]{'code'} = 9;
    return 9;
}

# GSSAPI or SSPI authentication data
#   code=int32
#   auth_data=String
sub AuthenticationGSSContinue($$$) {
    my $len = unpack( 'xN', $_[1] );

    return 0 if $len + 1 > length $_[1];

    $_[0]{'code'} = 8;
    $_[0]{'auth_data'} = substr( $_[1], 9, $len - 8 );
    return $len + 1;
}

# message: B(K) "BackendKeyData"
#   pid=int32
#   key=int32
sub BackendKeyData($$$) {
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
sub Bind($$$) {
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

sub BindComplete ($$$) { return 5 }

# message: CancelRequest (F)
#   pid=int32
#   key=int32
sub CancelRequest($$$) {
    ( $_[0]{'pid'}, $_[0]{'key'} ) = unpack( 'x8NN', $_[1] );
    return 16;
}

# message: F(C) "Close"
#   kind=char
#   name=String
sub Close($$$) {
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'kind'}, $_[0]{'name'} ) = unpack( 'x5AZ*', $_[1] );

    return $len;
}

sub CloseComplete ($$$) { return 5 }

# message: B(C) "CommandComplete"
#   type=char
#   name=String
sub CommandComplete($$$) {
    my $len;
    ( $len, $_[0]{'command'} ) = unpack( 'xNZ*', $_[1] );

    $len++;

    return 0 if $len > length $_[1];

    return $len;
}

# message: B(G) "CopyBothResponse"
#   wrapper around CopyInResponse which parse exact same properties but
# doesn't set the "replication" state.
sub CopyBothResponse($$$) {

    $_[2]{'replication'} = 1;

    return CopyInResponse(@_);
}

# message: B(d) or F(d) "CopyData"
#   row=Byte[n]
sub CopyData($$$) {
    my $len = unpack( 'xN', $_[1] );

    return 0 if $len + 1 > length $_[1];

    $_[0]{'row'} = substr( $_[1], 5, $len - 4 );

    return $len + 1;
}

sub CopyDone($$$) { return 5 }

# message: F(f) "CopyFail"
#   error=String
sub CopyFail($$$) {
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
sub CopyInResponse($$$) {
    my @fields_formats;

    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'copy_format'}, @fields_formats ) = unpack( 'x5Cn/n', $_[1] );

    # we can unpack in network order, make sure the format is 0 or 1
    $_[0]{'copy_format'}    = ( $_[0]{'copy_format'} != 0 );
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
sub DataRow($$$) {
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
sub Describe($$$) {
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'kind'}, $_[0]{'name'} ) = unpack( 'x5AZ*', $_[1] );

    return $len;
}

# message: B(E) "ErrorResponse"
#   (code=char
#   value=String){1,}\x00
sub ErrorResponse($$$) {
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

sub EmptyQueryResponse($$$) { return 5 }

# message: F(E) "Execute"
#   name=String
#   nb_rows=int32
sub Execute($$$) {
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'name'}, $_[0]{'nb_rows'} ) = unpack( 'x5Z*N', $_[1] );

    return $len;
}

sub Flush($$$) { return 5 }

# message: F(F) "FunctionCall"
#   func_oid=Int32
#   num_args_formats=Int16
#   args_formats[]=int16[nb_formats]
#   num_args=Int16
#   args[]=(len=int32,value=Byte[len])[nb_args]
#   result_format=Int16
# TODO: NOT TESTED yet
sub FunctionCall($$$) {
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
sub FunctionCallResponse($$$) {
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

# message: F "GSSENCRequest"
sub GSSENCRequest($$$) {
    return 8;
}

# message: F(p) "GSSResponse"
#   data: byte[n]
sub GSSResponse($$$) {
    my $len = unpack( 'xN', $_[1] );

    return 0 if $len + 1 > length $_[1];

    $_[0]{'data'} = substr( $_[1], 5, $len - 4 );

    return $len + 1;
}

# message: F(h)
#   ts=int64
#   xmin=int32
#   xmin_epoch=int32
#   catalog_xmin=int32
#   catalog_xmin_epoch=int32
sub HotStandbyFeedback($$$) {
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ($_[0]{'ts'}, $_[0]{'xmin'}, $_[0]{'xmin_epoch'}, $_[0]{'catalog_xmin'},
        $_[0]{'catalog_xmin_epoch'} ) = unpack( 'x6Q>NNNN', $_[1] );

    return $len;
}

# message: B(v) NegotiateProtocolVersion
#   minor=int32
#   unknowns=String[]
sub NegotiateProtocolVersion($$$) {
    my $len = unpack( 'xN', $_[1] ) + 1;
    my $unknowns;

    return 0 if $len > length $_[1];

    ( $_[0]{'minor'}, $unknowns ) = unpack( 'x5Nx4a*', $_[1] );
    $_[0]{'unknowns'} = [ split /\0/, $unknowns ];

    return $len;
}

sub NoData($$$) { return 5 }

# message: B(A) "NotificationResponse"
#   pid=int32
#   channel=String
#   payload=String
sub NotificationResponse($$$) {
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'pid'}, $_[0]{'channel'}, $_[0]{'payload'} )
        = unpack( 'x5NZ*Z*', $_[1] );

    return $len;
}

# message: B(t) "ParameterDescription"
#   num_params=int16
#   params_types[]=int32[nb_formats]
sub ParameterDescription($$$) {
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
sub ParameterStatus($$$) {
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
sub Parse($$$) {
    my @params_types;
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'name'}, $_[0]{'query'}, @params_types )
        = unpack( 'x5Z*Z*n/N', $_[1] );

    $_[0]{'num_params'}   = scalar(@params_types);
    $_[0]{'params_types'} = [@params_types];

    return $len;
}

sub ParseComplete($$$) { return 5 }

# message: F(p) "PasswordMessage"
#    password=String
sub PasswordMessage($$$) {
    my $len;
    ( $len, $_[0]{'password'} ) = unpack( 'xNZ*', $_[1] );

    $len++;

    return 0 if $len > length $_[1];

    return $len;
}

sub PortalSuspended($$$) { return 5 }

# message: B(k) "PrimaryKeepalive"
#  lsn=int64
#  ts=int64
#  ping=bool
sub PrimaryKeepalive($$$) {
    return 0 if length $_[1] < 23;

    ( $_[0]{'lsn'}, $_[0]{'ts'}, $_[0]{'ping'} ) = unpack( 'x6Q>Q>c', $_[1] );

    return 23;
}

# message: F(Q) "Query"
#    query=String
sub Query($$$) {
    my $len;
    ( $len, $_[0]{'query'} ) = unpack( 'xNZ*', $_[1] );

    $len++;

    return 0 if $len > length $_[1];

    return $len;
}

# message: B(Z) "ReadyForQuery"
#   status=Char
sub ReadyForQuery($$$) {
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
sub RowDescription($$$) {
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

# message: F(p) "SASLInitialResponse"
#   name: string
#   sz: int32
#   data: byte[n]
sub SASLInitialResponse($$$) {
    my $len = unpack( 'N', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'name'}, $_[0]{'sz'} ) = unpack( 'x5Z*N', $_[1] );

    if ( $_[0]{'sz'} == -1 ) {
        $_[0]{'data'} = '';
    }
    else {
        $_[0]{'data'} = substr( $_[1], $_[0]{'sz'} * -1 );
    }

    return $len;
}

# message: F(p) "SASLResponse"
#   data: byte[n]
sub SASLResponse($$$) {
    my $len = unpack( 'N', $_[1] ) + 1;

    return 0 if $len > length $_[1];
    $_[0]{'data'} = substr( $_[1], 5, $len - 5 );

    return $len;
}

# message: "SSLAnswer" (B)
sub SSLAnswer($$$) {
    $_[0]{'ssl_answer'} = substr( $_[1], 0, 1 );

    return 1;
}

# message: "SSLRequest" (F)
sub SSLRequest($$$) { return 8 }

# message: F(r) "StandbyStatusUpdate"
#   written: int64
#   flushed: int64
#   applied: int64
#   ts: int64
#   ping: bool
sub StandbyStatusUpdate($$$) {
    return 0 if 39 > length $_[1];

    ( $_[0]{'written'}, $_[0]{'flushed'}, $_[0]{'applied'}, $_[0]{'ts'}, $_[0]{'ping'} )
        = unpack( 'x6Q>Q>Q>Q>C', $_[1] );

    return 39;
}

# message: StartupMessage (F)
#   status=Char
#   (param=String
#   value=String){1,}\x00
sub StartupMessage($$$) {
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
        $_[2]{'replication'} = 1
            if $param eq 'replication' and $value =~ m{^(?:true|on|yes|1|database)$}i;
        $_[2]{'logical'} = 1 if $value eq 'database';
    }

    $_[0]{'params'} = \%params;

    return $len;
}

sub Sync($$$) { return 5 }

sub Terminate($$$) { return 5 }


# message: B(B) "Begin"
#   lsn=int64         # XLogData part
#   current_lsn=int64 # XLogData part
#   current_ts=int64  # XLogData part
#   xact_end_lsn=int64
#   xact_ts=int64
#   xid=int32
sub Begin($$$) {
    return 0 if 51 > length $_[1];

    ( $_[0]{'lsn'}, $_[0]{'current_lsn'}, $_[0]{'current_ts'},
      $_[0]{'xact_end_lsn'}, $_[0]{'xact_ts'}, $_[0]{'xid'} )
        = unpack( 'x5 xQ>Q>Q> xQ>Q>N', $_[1] );

    return 51;
}

# message: B(C) "Commit"
#   lsn=int64         # XLogData part
#   current_lsn=int64 # XLogData part
#   current_ts=int64  # XLogData part
#   flag=int8
#   xact_lsn=int64
#   xact_lsn_end=int64
#   xact_ts=int64
sub Commit($$$) {
    return 0 if 56 > length $_[1];

    ( $_[0]{'lsn'}, $_[0]{'current_lsn'}, $_[0]{'current_ts'},
      $_[0]{'flag'}, $_[0]{'xact_lsn'}, $_[0]{'xact_lsn_end'}, $_[0]{'xact_ts'} )
        = unpack( 'x5 xQ>Q>Q> xcQ>Q>Q>', $_[1] );

    return 56;
}

# message: B(O) "Origin"
#   lsn=int64         # XLogData part
#   current_lsn=int64 # XLogData part
#   current_ts=int64  # XLogData part
#   xact_lsn=int64
#   name=string
sub Origin($$$) {
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'lsn'}, $_[0]{'current_lsn'}, $_[0]{'current_ts'},
      $_[0]{'lsn'}, $_[0]{'name'} ) = unpack( 'x5 xQ>Q>Q> xQ>Z*', $_[1] );

    return $len;
}

# message: B(R) "Relation"
#   lsn=int64         # XLogData part
#   current_lsn=int64 # XLogData part
#   current_ts=int64  # XLogData part
#   relid=int32
#   nspname=string
#   relname=string
#   relident=int8
#   cols={int8, string, int32, int32}[]
sub Relation($$$) {
    my @cols;
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'lsn'}, $_[0]{'current_lsn'}, $_[0]{'current_ts'},
      $_[0]{'relid'}, $_[0]{'nspname'}, $_[0]{'relname'}, $_[0]{'relident'}, @cols )
        = unpack( 'x5 xQ>Q>Q> xNZ*Z*c n/(cZ*NN)', $_[1] );

    push @{ $_[0]{'cols'} }, [ splice(@cols, 0, 4) ] while @cols;

    return $len;
}

# message: B(Y) "Type"
#   lsn=int64         # XLogData part
#   current_lsn=int64 # XLogData part
#   current_ts=int64  # XLogData part
#   typid=int32
#   nspname=String
#   typname=String
sub Type($$$) {
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'lsn'}, $_[0]{'current_lsn'}, $_[0]{'current_ts'},
      $_[0]{'typid'}, $_[0]{'nspname'}, $_[0]{'typname'} )
        = unpack( 'x5 xQ>Q>Q> xNZ*Z*', $_[1] );

    return $len;
}

# message: B(I) Insert
#   lsn=int64         # XLogData part
#   current_lsn=int64 # XLogData part
#   current_ts=int64  # XLogData part
#   relid=int32
#   ident=byte
#   data={ int16, byte, byte[n] }
sub Insert($$$) {
    my $bin;
    my $ncols;
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'lsn'}, $_[0]{'current_lsn'}, $_[0]{'current_ts'},
      $_[0]{'relid'}, $_[0]{'ident'}, $bin )
        = unpack( 'x5 xQ>Q>Q> xNAa*', $_[1] );
        #= unpack( 'x5 xQ>Q>Q> xNAnAN/a', $_[1] );

    ( $ncols, $bin ) = unpack( 'na*', $bin );

    while ( $ncols ) {
        my $dat_kind;

        ( $dat_kind, $bin ) = unpack( 'Aa*', $bin );
        if ($dat_kind =~ /[nu]/) {
            push @{ $_[0]{'tup'}{$_[0]{'ident'}} }, [ $dat_kind ];
        }
        else {
            my ($sz, $data);
            ($data, $bin) = unpack( 'N/aa*', $bin );
            push @{ $_[0]{'tup'}{$_[0]{'ident'}} }, [ $dat_kind, $data ];
        }

        $ncols--;
    }

    return $len;
}

# message: B(I) Update
#   lsn=int64         # XLogData part
#   current_lsn=int64 # XLogData part
#   current_ts=int64  # XLogData part
#   relid=int32
#   tup={ byte => {byte[, byte[n]]}[] }[]
sub Update($$$) {
    my $bin;
    my $ncols;
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'lsn'}, $_[0]{'current_lsn'}, $_[0]{'current_ts'},
      $_[0]{'relid'}, $bin ) = unpack( 'x5 xQ>Q>Q> xNa*', $_[1] );

    {
        my ( $tup_kind, $ncols, @tup );

        ( $tup_kind, $ncols, $bin ) = unpack( 'Ana*', $bin );

        while ( $ncols ) {
            my $dat_kind;

            ( $dat_kind, $bin ) = unpack( 'Aa*', $bin );
            if ($dat_kind =~ /[nu]/) {
                push @tup, [ $dat_kind ];
            }
            else {
                my ($sz, $data);
                ($data, $bin) = unpack( 'N/aa*', $bin );
                push @tup, [ $dat_kind, $data ];
            }

            $ncols--;
        }

        $_[0]{'tup'}{$tup_kind} = \@tup;

        redo unless $tup_kind eq 'N';
    }

    return $len;
}

# message: B(D) Delete
#   lsn=int64         # XLogData part
#   current_lsn=int64 # XLogData part
#   current_ts=int64  # XLogData part
#   relid=int32
#   tup={ byte => {byte[, byte[n]]}[] }
sub Delete($$$) {
    my $bin;
    my $tup_kind;
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'lsn'}, $_[0]{'current_lsn'}, $_[0]{'current_ts'},
      $_[0]{'relid'}, $tup_kind, $bin )
        = unpack( 'x5 xQ>Q>Q> xNAa*', $_[1] );

    while ( length($bin) > 0 ) {
        my ( $ncols, @tup );

        ( $ncols, $bin ) = unpack( 'na*', $bin );

        while ( $ncols ) {
            my $dat_kind;
            ( $dat_kind, $bin ) = unpack( 'Aa*', $bin );
            if ($dat_kind =~ /[nu]/) {
                push @tup, [ $dat_kind ];
            }
            else {
                my $data;
                ($data, $bin) = unpack( 'N/aa*', $bin );
                push @tup, [ $dat_kind, $data ];
            }
            $ncols--;
        }

        $_[0]{'tup'}{$tup_kind} = \@tup;
    }

    return $len;
}

# message: B(T) "Truncate"
#   lsn=int64         # XLogData part
#   current_lsn=int64 # XLogData part
#   current_ts=int64  # XLogData part
#   cascade=bool
#   restart=bool
#   relid=int32[]
sub Truncate($$$) {
    my $opts;
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    ( $_[0]{'lsn'}, $_[0]{'current_lsn'}, $_[0]{'current_ts'},
      $opts ) = unpack( 'x5 xQ>Q>Q> xx[N]c', $_[1] );

    $_[0]{'cascade'} = $opts & 1;
    $_[0]{'restart'} = ($opts & 2) > 0;
    @{ $_[0]{'relid'} } = unpack( 'x5 xx[QQQ] xx[N]xN*', $_[1] );

    return $len;
}





sub XLogData($$$) {
    my $len = unpack( 'xN', $_[1] ) + 1;

    return 0 if $len > length $_[1];

    return $len;
}

BEGIN {
    *CopyOutResponse = \&CopyInResponse;
    *NoticeResponse  = \&ErrorResponse;
}

1

__END__

=pod

=back

=head1 SEE ALSO

Module B<pgShark>.

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
