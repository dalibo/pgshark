# This program is open source, licensed under the simplified BSD license.  For
# license terms, see the LICENSE file.

=head1 pgShark::protocol_2

pgShark::protocol_2 - is the collection of functions able to deal with procol
v2 of PostgreSQL

=head1 DESCRIPTION

This Perl module is aimed to be used by module pgShark. However, its functions
can be useful for other purpose to deal or parse PostgreSQL message of
protocol v2.

Unlike the protocole version 3, version 2 is stateful. Because of this, in
most function, this is the responsability of the caller to keep track of the
state of each sessions by giving a hashref where states are kept. This hashref
**MUST** concern the ONLY current session (Frontend/Backend couple) data are
parsed for.

=head1 FUNCTIONS

=over

=cut

package pgShark::protocol_2;

use strict;
use warnings;

use Exporter;
use Pod::Usage;

our $VERSION   = 0.2;
our @ISA       = ('Exporter');
our @EXPORT    = qw/pgsql_parser_backend pgsql_parser_frontend
    get_msg_type_frontend get_msg_type_backend get_msg_parser get_msg_len/;
our @EXPORT_OK = qw/pgsql_parser_backend pgsql_parser_frontend
    get_msg_type_frontend get_msg_type_backend get_msg_parser get_msg_len/;

my %frontend_msg_type = (
    # CancelRequest has no code
    # CopyDataRows has no code
    'F' => 'FunctionCall',
    # PasswordPacket has no code
    'Q' => 'Query',
    # SSLRequest has no code
    # StartupPacket has no code
    'X' => 'Terminate'
);

my %backend_msg_type = (
    'D' => 'DataRow', # aka AsciiRow in v2
    'R' => 'Authentication',
    'K' => 'BackendKeyData',
    'B' => 'DataRow', # aka BinaryRow in v2
    'C' => 'CommandComplete', # aka CompletedResponse in v2
    # CopyDataRows has no code
    'G' => 'CopyInResponse',
    'H' => 'CopyOutResponse',
    'P' => 'CursorResponse',
    'I' => 'EmptyQueryResponse',
    'E' => 'ErrorResponse',
    'V' => 'FunctionCallResponse',
    'N' => 'NoticeResponse',
    'A' => 'NotificationResponse',
    'Z' => 'ReadyForQuery',
    'T' => 'RowDescription',
);

my %authentication_codes = (
    0 => 'AuthenticationOk',
    1 => 'AuthenticationKerberosV4',
    2 => 'AuthenticationKerberosV5',
    3 => 'AuthenticationCleartextPassword',
    4 => 'AuthenticationCryptPassword',
    5 => 'AuthenticationMD5Password',
    6 => 'AuthenticationSCMCredential',
);

my %parsers = (
    'DataRow'                         => \&DataRow,
    'AuthenticationOk'                => \&AuthenticationOk,
    'AuthenticationKerberosV4'        => \&AuthenticationKerberosV4,
    'AuthenticationKerberosV5'        => \&AuthenticationKerberosV5,
    'AuthenticationCleartextPassword' => \&AuthenticationCleartextPassword,
    'AuthenticationCryptPassword'     => \&AuthenticationCryptPassword,
    'AuthenticationMD5Password'       => \&AuthenticationMD5Password,
    'AuthenticationSCMCredential'     => \&AuthenticationSCMCredential,
    'BackendKeyData'                  => \&BackendKeyData,
    'DataRow'                         => \&DataRow,
    'CancelRequest'                   => \&CancelRequest,
    'CommandComplete'                 => \&CommandComplete,
    'CopyData'                        => \&CopyData,
    'CopyInResponse'                  => \&CopyInResponse,
    'CopyOutResponse'                 => \&CopyOutResponse,
    'CursorResponse'                  => \&CursorResponse,
    'EmptyQueryResponse'              => \&EmptyQueryResponse,
    'ErrorResponse'                   => \&ErrorResponse,
    'FunctionCall'                    => \&FunctionCall,
    'FunctionCallResponse'            => \&FunctionCallResponse,
    'NoticeResponse'                  => \&NoticeResponse,
    'NotificationResponse'            => \&NotificationResponse,
    'PasswordPacket'                  => \&PasswordPacket,
    'Query'                           => \&Query,
    'ReadyForQuery'                   => \&ReadyForQuery,
    'RowDescription'                  => \&RowDescription,
    'SSLAnswer'                       => \&SSLAnswer,
    'SSLRequest'                      => \&SSLRequest,
    'StartupMessage'                  => \&StartupMessage,
    'Terminate'                       => \&Terminate,
);

my %msg_len = (
    'DataRow'                => \&DataRow_len,
    'CommandComplete'        => \&CommandComplete_len,
    'CopyData'               => \&CopyData_len,
    'CursorResponse'         => \&CursorResponse_len,
    'ErrorResponse'          => \&ErrorResponse_len,
    'FunctionCall'           => \&FunctionCall_len,
    'FunctionCallResponse'   => \&FunctionCallResponse_len,
    'NotificationResponse'   => \&NotificationResponse_len,
    'PasswordPacket'         => \&PasswordPacket_len,
    'Query'                  => \&Query_len,
    'RowDescription'         => \&RowDescription_len
);

# all known messages minus V and R which needs more work
# and G & H which needs to set some state
my $backend_type_re = qr/^([DKBCPIEVNAZT])/;

my $sslanswer_re    = qr/^[NY]$/;
my $end_copy_re     = qr/^\\.\n/s;
my $query_re        = qr/^Q/s;
my $function_re     = qr/^F\x00/;
my $func_resp_re    = qr/^V([G0])/;
my $terminate_re    = qr/^X/;
my $copymode_re     = qr/^([GH])/;
my $auth_re         = qr/^R.{4}/s;

=item *
B<get_msg_parser ($data, \%state)>

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

Returns the length of the message of given as second parameter with type given
as first parameter.

The third parameter is used to keep track of session state.

=cut

sub get_msg_len($$$) {
    my $type     = shift;
    my $raw_data = shift;
    my $curr_sess = shift;

    return 1 if $type eq 'CopyInResponse'
        or $type eq 'CopyOutResponse'
        or $type eq 'ReadyForQuery'
        or $type eq 'Terminate'
        or $type eq 'SSLAnswer';

    return 5 if $type eq 'AuthenticationOk'
        or $type eq 'AuthenticationKerberosV4'
        or $type eq 'AuthenticationKerberosV5'
        or $type eq 'AuthenticationSCMCredential'
        or $type eq 'AuthenticationCleartextPassword';

    return 7 if $type eq 'AuthenticationCryptPassword';
    
    return 8 if $type eq 'SSLRequest';

    return 9 if $type eq 'AuthenticationMD5Password'
        or $type eq 'BackendKeyData';

    return 16 if $type eq 'CancelRequest';

    return 296 if $type eq 'StartupMessage';

    &{ $msg_len{$type} }($raw_data, $curr_sess) if defined $msg_len{$type};
        
    return -1;
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
    my $raw_data = shift;
    my $curr_sess = shift;

    return 'SSLAnswer' if $raw_data =~ $sslanswer_re;

    if (defined $curr_sess->{'copy_mode'}) {
        delete $curr_sess->{'copy_mode'} if $raw_data =~ $end_copy_re;

        return 'CopyData'; # aka CopyDataRows in v2;
    }

    if ($raw_data =~ /^T/) {
        $curr_sess->{'num_fields'} = unpack( 'xn', $raw_data );
        # use Data::Dumper;
        # print Dumper($curr_sess->{'num_fields'});
        return 'RowDescription';
    }

    return $backend_msg_type{$1} if $raw_data =~ $backend_type_re;

    if ($raw_data =~ $copymode_re) {
        $curr_sess->{'copy_mode'} = 1;
        return $backend_msg_type{$1};
    }

    # message: B(R) "Authentication*"
    if ( $raw_data =~ $auth_re ) {
        my $code = unpack( 'xN', $raw_data );

        $curr_sess->{'ask_passwd'} = 1 if $code == 3
            or $code == 4 or $code == 5;

        return $authentication_codes{$code};
    }

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
    my $raw_data = shift;
    my $curr_sess = shift;

    if (defined $curr_sess->{'copy_mode'}) {
        delete $curr_sess->{'copy_mode'} if $raw_data =~ $end_copy_re;

        return 'CopyData';
    }

    if ( defined $curr_sess->{'ask_passwd'} ) {
        delete $curr_sess->{'ask_passwd'};
        return 'PasswordPacket';
    }

    return 'Query' if $raw_data =~ $query_re;
    return 'FunctionCall' if $raw_data =~ $function_re;
    return 'Terminate' if $raw_data =~ $terminate_re;

    if (length $raw_data >= 8) {
        my $code;
        $code = unpack( 'x4N', $raw_data );

        return 'CancelRequest'  if $code == 80877102;
        return 'SSLRequest'     if $code == 80877103;
        return 'StartupMessage' if $code == 131072;
    }

    # not known !
    return '';
}

=item *
B<pgsql_parser_backend (\%pg_msg, $data, \%state)>

Parse and dissect a buffer, looking for a valid pgsql v2 message coming from a
backend. Then it sets the given hashref as first parameter with the message
properties. Properties set in the given hashref depend on the message type. See
the function code comments for more information about them.

The data to parsed are given as second parameter.

The third parameter helps to keep track of the state of each
sessions by giving a hashref as third parameter.

This function is static, so it can be used outside of the class for any other
purpose.

The function tries to keep some compatibility with messages type returned from the
v3 parser. Here is how messages are mapped between v2 and v3:

  "AsciiRow"               => "DataRow"
  "BinaryRow"              => "DataRow"
  "CompletedResponse"      => "CommandComplete"
  "CopyDataRows"           => "CopyData"
  "FunctionResultResponse" => "FunctionCallResponse"
  "FunctionVoidResponse"   => "FunctionCallResponse"

CAUTION: message "CursorResponse" is protocol v2 only !

CAUTION: This function MUST returns the total length of the parsed message so
it can be removed from the TCP monolog buffer. 0 means lack of data to
process the current message. On error, returns -1

=cut
sub pgsql_parser_backend($$$) {
    my $pg_msg    = shift;
    my $raw_data  = shift;
    my $curr_sess = shift;
    my $type      = get_msg_type_backend($raw_data, $curr_sess);

    printf STDERR "type: $type\n";

    return 0  if not defined $type;
    return -1 if $type eq '';

    $pg_msg->{'type'} = $type;

    return 1 if $type eq 'CopyInResponse'
        or $type eq 'CopyOutResponse'
        or $type eq 'ReadyForQuery';

    return 2 if $type eq 'EmptyQueryResponse';;

    return &{ $parsers{$type} }( $pg_msg, $raw_data, $curr_sess )
        if ( defined $parsers{$type} );
    
    return -1;
}

=item *
B<pgsql_parser_frontend (\%pg_msg, $data, \%state)>

Parse and dissect a buffer, looking for a valid pgsql v2 message coming from a
frontend. It sets the given hashref as first parameter with the message
properties. Properties set in the given hashref depend on the message type. See
the function code comments for more information about them.

The data to parsed are given in the second parameter.

The third parameter helps to keep track of the state of each
sessions by giving a hashref as third parameter.

This function is static, so it can be used outside of the class for any other
purpose.

The function tries to keep some compatibility with messages type returned from the
v3 parser. Here is how messages are mapped between v2 and v3:

  "CopyDataRows"           => "CopyData"
  "StartupPacket"          => "StartupMessage"

CAUTION: message "CursorResponse" is protocol v2 only !

CAUTION: This function MUST returns the total length of the parsed message so
it can be removed from the TCP monolog buffer. 0 means lack of data to
process the current message. On error, returns -1

=cut
sub pgsql_parser_frontend($$$) {
    my $pg_msg    = shift;
    my $raw_data  = shift;
    my $curr_sess = shift;
    my $type      = get_msg_type_frontend($raw_data, $curr_sess);

    printf STDERR "type: $type\n";

    return 0  if not defined $type;
    return -1 if $type eq '';

    $pg_msg->{'type'} = $type;

    return 1 if $type eq 'Terminate';

    return 8 if $type eq 'SSLRequest';

    return &{ $parsers{$type} }( $pg_msg, $raw_data, $curr_sess )
        if ( defined $parsers{$type} );
    
    return -1;
}

sub CommandComplete_len ($$) {
    # add type + null terminated String
    my $msg_len = length( unpack( 'xZ*', $_[1] ) ) + 2;

    return 0 if $msg_len > length $_[1];

    return $msg_len;
}

sub CopyDataRows_len ($$) {
    my $end = index( $_[1], "\n" );

    return 0 if $end == -1;

    return $end + 1;
}

sub CursorResponse_len ($$) {
    my $msg_len = 2 + length unpack( 'xZ*', $_[1] );

    return 0 if $msg_len > length $_[1];

    return $msg_len;
}

sub DataRow_len ($$) {
    my $raw_data  = $_[0];
    my $curr_sess = $_[1];
    my $num_bytes = 1 + int( $curr_sess->{'num_fields'} / 8 );
    my $num_bits  = 8 * $num_bytes;
    my $data_len  = length $raw_data;
    my $msg_len   = 1 + $num_bytes;

    # DataRow message are really prone to be splitted between multi network
    # packets
    return 0 if $data_len < $msg_len;

    my @field_notnull = split( //, unpack( "xB$num_bits", $raw_data ) );

    for ( my $i = 0; $i < $curr_sess->{'num_fields'}; $i++ ) {
        next unless $field_notnull[$i] eq '1';

        return 0 if $msg_len + 4 > $data_len;
        
        $msg_len += unpack( "x${msg_len}N", $raw_data );

        return 0 if $msg_len > $data_len;
    }

    return $msg_len;
}

sub ErrorResponse_len ($$) {
    my $msg_len = 2 + length unpack( 'xZ*', $_[1] );

    return 0 if $msg_len > length $_[1];

    return $msg_len;
}

sub FunctionCall_len ($$) {
    my $pg_msg = $_[0];
    my $raw_data = $_[1];
    my $msg_len = 0;
    my $num_args = 0;
    my $data_len = length $raw_data;

    return 0 if length $raw_data < 10;

    $num_args = unpack( 'x6N', $raw_data );

    # compute the message size and check for fragmentation
    $msg_len = 10;
    for ( my $i = 0; $i < $num_args; $i++ ) {
        return 0 if $msg_len + 4 > $data_len;

        $msg_len += unpack( "x${msg_len}N", $raw_data );

        return 0 if $msg_len > $data_len;
    }

    return $msg_len;
}

sub FunctionCallResponse_len ($$) {
    my $msg_len;

    return 2 if unpack( 'xA', $_[1] ) eq '0';

    $msg_len = 6 + unpack( 'xxN', $_[1] );

    return 0 if $msg_len > length $_[1];

    return $msg_len;
}

sub NotificationResponse_len ($$) {
    my $msg_len = 6 + length unpack( 'x5Z*', $_[1] );

    return 0 if $msg_len > length $_[1];

    return $msg_len;
}

sub PasswordPacket_len ($$) {
    my $msg_len = unpack( 'N', $_[1] );

    return 0 if $msg_len > length $_[1];

    return $msg_len;
}

sub Query_len ($$) {
    my $msg_len = 2 + length unpack( 'xZ*', $_[1] );

    return 0 if $msg_len > length $_[1];

    return $msg_len;
}

sub RowDescription_len ($$) {
    my $raw_data = $_[0];
    my $curr_sess = $_[1];
    my $data_len = length $raw_data;
    my $i = 0;
    my $msg;
    my $msg_len;
    my $num_fields;

    return 0 if length $raw_data < 3;

    $num_fields = unpack( 'xn', $raw_data );

    return 3 if $num_fields == 0;

    $msg = substr( $raw_data, 3 );

    $msg_len = 3;

    while ( $i < $num_fields and $msg) {
        my $len = 11 + length unpack( 'Z*', $msg );

        return 0 if length $msg < $len; 

        $msg = substr( $msg, $len );
        $msg_len += $len;
        $i++;
    }

    # we couldn't parser all the fields
    return 0 if $i != $num_fields;

    return $msg_len;
}

sub DataRow($$$) {
    my $pg_msg  = $_[0];
    my $raw_data  = $_[1];
    my $curr_sess = $_[2];
    my $num_bytes = 1 + int( $curr_sess->{'num_fields'} / 8 );
    my $num_bits  = 8 * $num_bytes;
    my $data_len  = length $raw_data;
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
        next unless $field_notnull[$i] eq '1';

        return 0 if $msg_len + 4 > $data_len;

        $msg_len += unpack( "x${msg_len}N", $raw_data );

        return 0 if $msg_len > $data_len;
    }

    $msg = substr( $raw_data, 1 + $num_bytes );

    for ( my $i = 0; $i < $pg_msg->{'num_values'}; $i++ ) {

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

    return $msg_len;
}

# AuthenticationOk
#   code=int32
sub AuthenticationOk($$) {
    $_[0]{'code'} = 0;
    return 5;
}

# AuthenticationKerberosV4
#   code=int32
sub AuthenticationKerberosV4($$$) {
    $_[0]{'code'} = 1;
    return 5;
}

# AuthenticationKerberosV5
#   code=int32
sub AuthenticationKerberosV5($$$) {
    $_[0]{'code'} = 2;
    return 5;
}

# AuthenticationCleartextPassword
#   code=int32
sub AuthenticationCleartextPassword($$$) {
    $_[0]{'code'}       = 3;
    $_[2]{'ask_passwd'} = 1;
    return 5;
}

# AuthenticationCryptPassword
#   code=int32
#   salt=Byte2
sub AuthenticationCryptPassword($$$) {
    $_[0]{'code'}       = 4;
    $_[0]{'salt'}       = substr( $_[1], 5, 2 );
    $_[2]{'ask_passwd'} = 1;
    return 7;
}

# AuthenticationMD5Password
#   code=int32
#   salt=Byte4
sub AuthenticationMD5Password($$$) {
    $_[0]{'code'}       = 5;
    $_[0]{'salt'}       = substr( $_[1], 5, 4 );
    $_[2]{'ask_passwd'} = 1;
    return 9;
}
       
# AuthenticationSCMCredential
#   code=int32 
sub AuthenticationSCMCredential($$$) {
    $_[0]{'code'} = 6;
    return 5;
}

# message: B(K) "BackendKeyData"
sub BackendKeyData($$$) {    
    ( $_[0]{'pid'}, $_[0]{'key'} ) = unpack( 'xNN', $_[1] );
    return 9;
}

# message: CancelRequest (F)
# TODO: NOT TESTED yet
sub CancelRequest($$$) {
    ( $_[0]{'pid'}, $_[0]{'key'} ) = unpack( 'x8NN', $_[1] );
    return 16;
}

# message: B(C) "CompletedResponse"
# aka CommandComplete in v3
#   type=char
#   name=String
sub CommandComplete($$$) {
    my $msg_len;

    $_[0]{'command'} = unpack( 'xZ*', $_[1] );

    # add type + null terminated String
    $msg_len = length( $_[0]{'command'} ) + 2;

    return 0 if $msg_len > length $_[1];

    return $msg_len;
}

# message: B or F "CopyData"
#   row=Byte[n]
# TODO: NOT TESTED yet
sub CopyData($$$) {
    my $end = index( $_[1], "\n" );

    # we don't have the full row (fragmentation)
    return 0 if $end == -1;

    $_[0]{'row'} = substr( $_[1], 0, $end + 1 );

    delete $_[2]{'copy_mode'} if $_[0]{'row'} eq "\\.\n";

    return length $_[0]{'row'};
}

# message: B(G) "CopyInResponse"
# TODO: NOT TESTED yet
sub CopyInResponse($$$) {
    $_[2]{'copy_mode'} = 1;
    return 1;
}

# message: B(H) "CopyOutResponse"
# TODO: NOT TESTED yet
sub CopyOutResponse($$$) {
    $_[2]{'copy_mode'} = 1;
    return 1;
}

# message: B(P) "CursorResponse"
sub CursorResponse($$$) {
    my $msg_len;

    $_[0]{'name'} = unpack( 'xZ*', $_[1] );

    # add type + null terminated String
    $msg_len = 2 + length $_[0]{'name'};

    return 0 if $msg_len > length $_[1];

    return $msg_len;
}

# message: B(I) "EmptyQueryResponse"
# it has an additionnal empty string (1-byte) as parameter
sub EmptyQueryResponse($$$) { return 2 }

# message: B(E) "ErrorResponse"
# We try to be compatible with v3 here
#   M => String
sub ErrorResponse($$$) {
    my $msg_len;

    $_[0]{'fields'} = { 'M' => unpack( 'xZ*', $_[1] ) };

    # add type + null terminated String
    $msg_len = 2 + length $_[0]{'fields'}{'M'};

    return 0 if $msg_len > length $_[1];
    return $msg_len;
}

# message: F(F) "FunctionCall"
#   func_oid=Int32
#   num_args=Int32
#   args[]=(len=int32,value=Byte[len])[nb_args]
# TODO: NOT TESTED yet
sub FunctionCall($$$) {
    my $pg_msg = $_[0];
    my $raw_data = $_[1];
    my $msg_len = 0;
    my $data_len = length $raw_data;
    my @args;
    my $msg;

    # fragmentation...
    return 0 if length $raw_data < 10;

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

    return $msg_len;
}

# message: B(V) "FunctionResultResponse" and "FunctionVoidResponse"
# aka "FunctionCallResponse" in v3
#   len=Int32
#   value=Byte[len]
# TODO: NOT TESTED yet
sub FunctionCallResponse($$$) {
    my $msg_len;

    $_[0]{'status'} = unpack( 'xA', $_[1] );
    

    if ($_[0]{'status'} eq '0') {
        $_[0]{'len'} = 0;
        $_[0]{'value'} = undef;
        return 2;
    }

    $_[0]{'len'} = unpack( 'x2N', $_[1] );
    $_[0]{'value'} = substr( $_[1], 6, $_[0]{'len'} );

    $msg_len = $_[0]{'len'} + 6;

    return 0 if $msg_len > length $_[1];

    return $msg_len;
}

# message: B(A) "NotificationResponse"
# We try to be compatible with v3 here
#   pid=int32
#   channel=String
#   payload=undef (NOT in protocol v2!)
# TODO: NOT TESTED yet
sub NotificationResponse($$$) {
    my $msg_len;

    ( $_[0]{'pid'}, $_[0]{'channel'} ) = unpack( 'xNZ*', $_[1] );
    $_[0]{'payload'} = undef;

    # add type + pid + null terminated String
    $msg_len = 6 + length $_[0]{'channel'};

    return 0 if $msg_len > length $_[1];

    return $msg_len;
}

# message: F "PasswordPacket"
# aka "PasswordMessage" in v3
#    password=String
sub PasswordPacket($$$) {
    my $msg_len;

    ( $msg_len, $_[0]{'password'} ) = unpack( 'NZ*', $_[1] );

    return 0 if $msg_len > length $_[1];

    return $msg_len;
}

# message: F(Q) "Query"
#    query=String
sub Query($$$) {
    my $msg_len;

    $_[0]{'query'} = unpack( 'xZ*', $_[1] );

    # add type + null terminated String
    $msg_len = 2 + length $_[0]{'query'};

    return 0 if $msg_len > length $_[1];

    return $msg_len;
}

# message: B(Z) "ReadyForQuery"
# We try to be compatible with proto v3 here
#   status=undef (NOT definied in v2 !)
sub ReadyForQuery($$$) {
    $_[0]{'status'} = undef;
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
sub RowDescription($$$) {
    my $pg_msg = $_[0];
    my $raw_data = $_[1];
    my $curr_sess = $_[2];
    my $data_len = length $raw_data;
    my $i = 0;
    my @fields;
    my $msg;
    my $msg_len;

    return 0 if length $raw_data < 3;

    $pg_msg->{'num_fields'} = unpack( 'xn', $raw_data );
    return 3 if $pg_msg->{'num_fields'} == 0;

    $msg = substr( $raw_data, 3 );

    $msg_len = 3;

    while ( $i < $pg_msg->{'num_fields'} and $msg) {

        my ( $type, $type_len, $type_mod );
        my @field;
        my $len;
        my $name = unpack( 'Z*', $msg );

        $len = 1 + length $name;
        return 0 if length $msg < $len;

        $msg = substr( $msg, $len );

        return 0 if length $msg < 10; 

        ( $type, $type_len, $type_mod ) = unpack( 'NnN', $msg );

        @field = ( $name, undef, undef, $type, $type_len, $type_mod, undef );
        push @fields, [@field];

        $msg = substr( $msg, 10 );
        $msg_len += $len + 10;
        $i++;
    }

    # we couldn't parser all the fields
    return 0 if $i != $pg_msg->{'num_fields'};

    $pg_msg->{'fields'} = [@fields];

    # save the number of fields for messages AsciiRow and BinaryRow
    $curr_sess->{'num_fields'} = $pg_msg->{'num_fields'};

    return $msg_len;
}

# message: SSLAnswer (B)
sub SSLAnswer($$$) {
    $_[0]{'ssl_answer'} = substr( $_[1], 0, 1 );
    return 1;
}

sub SSLRequest($$$) { return 8 }

# message: StartupPacket (F)
# aka StartupMessage in v3
# We try to be compatible with v3 here
#   version=2
#   params = (param => String)
sub StartupMessage($$$) {
    my $msg;
    my %params;

    return 0 if length $_[1] < 296;

    $_[0]{'version'} = 2;
    # $_[0]{'params'}{'database'} = substr( $_[1], 8,  64 );
    # $_[0]{'params'}{'user'}     = substr( $_[1], 72, 64 );
    $_[0]{'params'}{'database'} = unpack( 'x8Z*', $_[1] );
    $_[0]{'params'}{'user'}     = unpack( 'x72Z*', $_[1] );

    return 296;
}

sub Terminate($$$) { return 1 }

BEGIN {
    *NoticeResponse = \&ErrorResponse;
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