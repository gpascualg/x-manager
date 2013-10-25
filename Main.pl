#!/usr/bin/perl

use strict;
use warnings;

#use Carp;
use Time::HiRes qw(usleep);
use Carp::Assert;
use IO::Socket::INET;
use IO::Socket::UNIX;
use IO::Select;
use Data::Dumper;

use xConfig;
use xUser;
use xSYS;

#$SIG{ __DIE__ } = sub { Carp::confess( @_ ) };

$| = 1;

{
    my %clients = ();
    my $config = new xConfig();
    my $stop = 0;
    my $sysadmin = 0;

    my %callbacks = (
        'Identify' => sub {
            my($socket, $username, $privKey) = @_;

            $clients{$socket} = new xUser($config, $username, $privKey, $sysadmin);
            my $result = $clients{$socket}->authentificate();
            if ($result != 0)
            {
                $clients{$socket} = undef; # Avoid further processing
            }

            return $result;
        },

        'UsedBandwith' => sub {
            my($socket) = @_;
            return $clients{$socket}->getBandwith();
        },

        'Quota' => sub {
            my($socket) = @_;
            return $clients{$socket}->getQuota();
        },

        'SYS_DAEMON_STOP' => sub
        {
            $stop = 1;
            return 0;
        },

        'SYS_UserAdd' => sub {
            my($socket, $username, $password) = @_;
            return xSYS::AddUser($config, $username, $password);
        },
        
        'SYS_UserDel' => sub {
            my($socket, $username) = @_;
            return xSYS::DelUser($config, $username);
        },

        'SYS_BandwithCalc' => sub {
            my($socket, $username) = @_;
            return xSYS::CalculateQuota($config, $username);
        },

        'SYS_RestoreQuota' => sub {
            my($socket, $username) = @_;
            return xSYS::RestoreQuota($config, $username);
        }
    );

    my $pid = fork;
    my $socket = undef;
    my $socketPath = '/var/run/xmanager.sock';

    sub sockconnect
    {
        unlink($socketPath);
        $socket = IO::Socket::UNIX->new(
               Type     => SOCK_STREAM,
               Local    => $socketPath,
               Listen   => 5,
            )
                or die("Can't create server socket: $!\n");

        chmod 0666, $socketPath;
    }

    local $SIG{PIPE} = 'sockconnect';

    if ($pid == 0)
    {
        # CHILD
        $socket = new IO::Socket::INET (
            LocalHost => '127.0.0.1',
            LocalPort => '8000',
            Proto => 'tcp',
            Listen => 5,
            Reuse => 1,
            ReuseAddr => 1
        )
            or die "ERROR in Socket Creation : $!\n";
    }
    else
    {
        sockconnect();
        $sysadmin = 1;
    }

    my $select = IO::Select->new($socket) or die "IO::Select $!";

    while (!$stop)
    {
        my @ready_clients = $select->can_read(0);
        foreach my $rc (@ready_clients)
        {
            if($rc == $socket)
            {
                my $new = $socket->accept();
                $select->add($new);
                $clients{$new} = undef;
                assert($select->count - 1 == keys(%clients));
            }
            else
            {
                my $read = $rc->sysread(my $data, 1024);

                if ($read)
                {
                    parseRecv($data, $rc);
                }
                else
                {
                    delete $clients{$rc};
                    closeSocket($select, $rc);
                    assert($select->count - 1 == keys(%clients));
                }
            }
        }

        usleep(250000);
    }
    
    if ($pid)
    {
        kill 1, $pid;
    }
    
    exit 0;

    sub parseRecv
    {
        my($data, $socket) = @_;

        my @parameters = split(/::/, $data);
        my $ret = -1;
        if (defined($callbacks{$parameters[0]}))
        {
            my $f = $parameters[0];
            # Has not already identified?
            if ($f ne "Identify" and not defined $clients{$socket})
            {
                print "Trying to call $f whithout being identified\n";
                $ret = -2;
            }
            # Is it a SYS function?
            elsif($f =~ m/^SYS_/ and not $sysadmin)
            {
                print "Trying to call $f while not being sysadmin\n";
                $ret = -1;
            }
            else
            {
                my @arguments = splice @parameters, 1;
                $ret = $callbacks{$f}->($socket, @arguments);
            }
        }

        $socket->send(pack("I", $ret));
    }

    my $user = new xUser($config, "login_user", "md5_pass");
    $user->authentificate();
}

sub closeSocket
{
    my($select, $socket) = @_;

    $select->remove($socket);
    $socket->close;
};


__END__