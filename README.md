
    
    pgShark is a Perl module able to mess with PostgreSQL network
    traffic

Synopsis
==================

A simple exemple to count the number of connections and disconnections on localhost, live version:

```perl
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
```

Description
=========================

This Perl module is able to study PostgreSQL traffic captured from a
network interface and call various functions for each messages of the
protocol. The network dump could be live or from a pcap file (using
tcpdump as instance).

pgShark comes with various sample scripts able to do various things with
these network dumps. See help page of each of them for more
informations.

Methods
================================

    *   new (\%settings)

        Static method.

        Creates a new pgShark object and returns it. It takes a hash as
        parameter with the following settings:

            {
                'host' => IP address of the server
                'port' => Port of the PostgreSQL server
                'protocol' => the protocol version, ie. 2 or 3
                'procs' => {
                    # Hash of callbacks for each messages.
                    'message name' => \&callback
                    ...
                }
                'debug' => $level
            }

        When 'host' key is not given, pgShark will wait for a message coming
        from the backend or the frontend with no doubt before calling user
        callbacks. Depending on the network activity, it can takes more or
        less time and messages might be lost (usually, COPY related ones).
        If you really need *ALL* messages, set the 'host' key explicitly.

        pgShark is not able to detect which port the server is listening.
        Default is PostgreSQL's ones, ie. 5432. Make sure to always set the
        proper port or pgShark will just filter out your PostgreSQL traffic
        if it's not on 5432.

        If not defined, the protocol version by default is 3.

        The 'procs' hash associate a callback to each messages of the
        PostgreSQL protocol you are interested in. See the following link
        about available message names and definitions:

          http://www.postgresql.org/docs/current/static/protocol-message-formats.html

        One messages type has been added to both protocols: SSLAnswer.

        The 'debug' key in settings can be set between 0 and 6, 0 is the
        default with no debug message, 6 is the most verbose. Because of
        internal performance consideration, you MUST set the environment
        variable DEBUG to '1' to actually activate the debugging messages.

    *   live ($interface, \$err)

        Open a live capture on given interface from first parameter. The
        second parameter is a reference to a string. It will be filled with
        the error message if the method fails.

        Returns 0 on success, 1 on failure

    *   open ($file, \$err)

        Open a given pcap file from first parameter. The second parameter is
        a reference to a string. It will be filled with the error message if
        the method fails.

        Returns 0 on success, 1 on failure.

    *   close ()

        Close the pcap handle previously opened with this object using
        either pgShark::live() or pgShark::open() methods.

    *   process_all ()

        Loop over all available packets from the previously opened pcap
        handle.

    *   dec2dot ($ip_addr)

        Static method.

        Convert a decimal IP address representation given as first parameter
        to the human notation "ww.xx.yy.zz".

    *   normalize_query ($query)

        Static method.

        Returns the normalized version of the query given as first
        parameter.

Binaries
==================

    For details, see the output of parameter "--help" for each of them.

    *   pgs-badger

        This script analyse the pcap traffics and outputs various statistics
        about what was found in PostgreSQL protocol.

        The report contains most popular queries, slowest cumulated ones,
        slowest queries ever, classification of queries by type, sessions
        time, number of connexion, errors, notices, etc.

        The network dump could be live or from a pcap file (using tcpdump
        for instance).

        In a futur version this script is supposed to talk with pgbadger
        directly !

    *   pgs-debug

        Outputs the PostgreSQL messages in human readable format. Useful to
        analyze what is in a network dump before using pgshark on some other
        duties.

    *   pgs-normalize

        The "pgs-normalize" script tries to normalize queries and prepared
        statements and output them to stdout. Its purpose is to give you a
        list of unique queries, whatever the number of time they have been
        sent by clients and whatever their parameters were.

    *   pgs-record

        "pgs-record" filters network traffic and dump PostgreSQL related
        activity to a pcap file. The pcap file can then be processed with
        all available pgShark tools.

        "pgs-record" rely on perl Net::Pcap module. However, unlike
        Net::Pcap, "tcpdump" is able to set a bigger capture buffer using
        recent libpcap. Default buffer size is often too small to be able to
        dump all tcp datagram quickly enough. Because of this buffer size
        (1MB), on high loaded systems, you might loose packets. Therefor, by
        default, "pgs-record" will try to act as a wrapper around c<tcpdump>
        if it is available on the system and set the buffer to "32M".

        Capturing high throughput traffic, make sure your CPU, disks and
        memory are good enough to deal with the amount of data. You might
        want to set the capture buffer to 256MB or more and redirect
        directly to a file for future use.

    *   pgs-replay

        <pgs-replay> send the PostgreSQL messages to a given PostgreSQL
        cluster. The network dump could be live or from a pcap file (using
        tcpdump for instance).

        This script only supports protocol v3, making it compatilible with
        versions 7.4 to 9.2 of PostgreSQL.

        This script currently does not support any kind of authentication on
        the remote PostgreSQL cluster where messages are send. Make sure it
        can connect using ident, peer or trust.

    *   pgs-sql

        Writes captured queries on stdout. Because of the SQL language
        doesn't support unnamed prepared statement, this script actually try
        to names them. Presently, this script doesn't support cursors nor
        COPY messages.

    *   pgs-stat

        Outputs various informations about PostgreSQL activity on the
        network on a given sampling period.

See also
===========

    This module rely on two modules to parse message of protocols v2 and v3:
    pgShark::protocol_2 and pgShark::protocol_3.

LICENSING
================

    This program is open source, licensed under the simplified BSD license.
    For license terms, see the LICENSE provided with the sources.

AUTHORS
============

    Jehan-Guillaume de Rorthais <jgdr@dalibo.com>

    Nicolas Thauvin <nicolas.thauvin@dalibo.com>

    Guillaume Lelarge <guillaume.lelarge@dalibo.com>

    Copyright: (C) 2012-2014 Jehan-Guillaume de Rorthais - All rights
    reserved.

    Dalibo's team. http://www.dalibo.org

