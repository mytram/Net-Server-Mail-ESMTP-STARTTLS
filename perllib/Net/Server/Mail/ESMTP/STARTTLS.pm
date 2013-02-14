#
# Copyright 2013 Mytram (r.mytram@gmail.com). All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

package Net::Server::Mail::ESMTP::STARTTLS;

use 5.008;
use strict;
use Carp;

# IO::Socket::SSL v1.83 has a bug in readline in list context that causes
# Net::Server::Mail to fail to read commands correctly

use IO::Socket::SSL 1.84;
use base qw(Net::Server::Mail::ESMTP::Extension);

our $VERSION = "0.01";

# No parameter
use constant {
	REPLY_READY_TO_START	=> 220,
	REPLY_SYNTAX_ERROR	=> 502,
	REPLY_NOT_AVAILABLE	=> 454,
};

# https://tools.ietf.org/html/rfc2487

sub verb {
    my $self = shift;
    return ([ 'STARTTLS' => \&starttls ]);
}

sub keyword { 'STARTTLS' }

=item starttls($server)

starttls() is invoked on the server when the verb starttls is issued
by the SMTP client.

Return a non undef to signal the server to close the socket.

=cut

sub starttls {
    my $server = shift;
    my $args = shift;

    if ($args) {
	# No parameter verb
        $server->reply(REPLY_SYNTAX_ERROR,  'Syntax error (no parameters allowed)');
        return;
    }

    my $ssl_config = $server->{options}{ssl_config} if exists $server->{options}{ssl_config};
    if ( !$ssl_config || ref $ssl_config ne 'HASH'  ) {
        $server->reply(REPLY_NOT_AVAILABLE, 'TLS not available due to temporary reason');
        return;
    }

    $server->reply(REPLY_READY_TO_START, 'Ready to start TLS');

    my $ssl_socket = IO::Socket::SSL->start_SSL(
        $server->{options}{socket},
        %$ssl_config,
        SSL_server => 1,
    );

    # Use SSL_startHandshake to control nonblocking behaviour
    # See perldoc IO::Socket::SSL for more

    if ( !$ssl_socket || !$ssl_socket->isa('IO::Socket::SSL') ) {
        return 0; # to single the server to close the socket
    }

    return;
}

1;
