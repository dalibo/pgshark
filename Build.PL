#!/usr/bin/env perl

use strict;
use warnings;
use Module::Build;

my $build = Module::Build->new(
    module_name => 'pgShark',
    license     => 'bsd',
    requires    => {
        'perl'        => '5.8.0',
        'Net::Pcap'   => 0,
        'Digest::MD5' => 0,
    },
    create_packlist    => 1,
    create_readme      => 1,
    create_makefile_pl => 'traditional',
    dist_version_from  => 'lib/pgShark.pm',
    dist_abstract      => 'Messing with PostgreSQL network traffic',
    #dist_author        => 'Jehan-Guillaume (ioguix) de Rorthais <jgdr@dalibo.com>',
    author_from        => 'lib/pgShark.pm',
    meta_merge         => {
        resources => {
            homepage     => 'https://github.com/dalibo/pgshark',
            bugtracker   => 'https://github.com/dalibo/pgshark/issues',
            repository  => 'https://github.com/dalibo/pgshark'
        }
  },
);

$build->create_build_script;
