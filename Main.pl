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
        
        'SYS_FreeSpace' => sub {
            return $config->getFreeSpace();
        },

        'SYS_UserAdd' => sub {
            my($socket, $username, $password, $plan) = @_;
            return xSYS::AddUser($config, $username, $password, $plan);
        },
        
        'SYS_UserDel' => sub {
            my($socket, $username) = @_;
            return xSYS::DelUser($config, $username);
        },
        
        'SYS_DomainAdd' => sub {
            my($socket, $username, $domain) = @_;
            return $clients{$socket}->setupSubdomain($username, $domain);
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
    
    # Get space in /
    my $freeSpace = `df / | head -2 | tail -1 | awk '{print \$4}'`;
    my $usedLoop = `df | grep /dev/loop | awk '{print \$2 " " \$3}'`;
    my @loops = split("\n", $usedLoop);
    
    # We substract total loop space, and add used space (as it has already been substracted from rootfs)
    foreach my $loop (@loops)
    {
        my @params = split(" ", $loop);
        $freeSpace -= $params[0];
        $freeSpace += $params[1];
    }
        
    $config->setFreeSpace($freeSpace);  
        
    # Find how many loops we have
    my $availableLoops = `ls /dev/loop* | egrep 'loop[0-9]+\$'`;
    my $totalLoops = substr($availableLoops, -2, 1);
    $config->setLoops($totalLoops + 1);

    # Fork and start setting variables
    my $pid = fork;
    my $socket = undef;
    my $socketPath = '/var/run/xmanager.sock';

    sub sockconnect
    {
        # Only for parent!
        if ($pid == 0)
        {
            return;
        }
        
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
        xSYS::initialize();
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
        xSYS::deinitialize();
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
}

sub closeSocket
{
    my($select, $socket) = @_;

    $select->remove($socket);
    $socket->close;
};


__END__