use strict;
use warnings;

use ExtUtils::MakeMaker;

my %WriteMakefileArgs = (
    'ABSTRACT'              => 'A Net::Server::Mail::ESMTP STARTTLS verb support extension',
    'AUTHOR'                => 'Mytram <r.mytram@gmail.com>',
    'BUILD_REQUIRES'        => {},
    'DISTNAME'              => 'Net-Server-Mail-ESMTP-STARTTLS',
    'EXE_FILES'             => [],
    'LICENSE'               => 'perl',
    'NAME'                  => 'Net::Server::Mail::ESMTP::STARTTLS',
    'PREREQ_PM'             => {
        'IO::Socket::SSL'   => '1.831',
    },
    'VERSION_FROM'          => 'lib/Net/Server/Mail/ESMTP/STARTTLS.pm',
    'test'                  => {
        'TESTS' => 't/*.t'
    },
    META_MERGE => {
	resources => {
	    repository => 'https://github.com/mytram/Net-Server-Mail-ESMTP-STARTTLS',
	},
   },

);

WriteMakefile(%WriteMakefileArgs);
