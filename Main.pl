#!/usr/bin/perl

no warnings;

use strict;
use warnings;

#use Carp;
use JSON;
use Time::HiRes qw(usleep);
use Carp::Assert;
use IO::Socket::INET;
use IO::Socket::UNIX;
use IO::Select;
use Data::Dumper;

use xConfig;
use xUser;
use xSYS;
use xResponse;

#$SIG{ __DIE__ } = sub { Carp::confess( @_ ) };

$| = 1;
our $errno = 0;
our $errmsg = 0;

{
    my $config = new xConfig();
    my $stop = 0;
    my $sysadmin = 0;

    my %callbacks = (
        'Banwidth' => sub {
            my($client, %args) = @_;
            return $client->getBandwith();
        },

        'UsedBandwith' => sub {
            my($client, %args) = @_;
            return $client->getUsedBandwith();
        },

        'Quota' => sub {
            my($client, %args) = @_;
            return $client->getQuota();
        },

        'UsedQuota' => sub {
            my($client, %args) = @_;
            return $client->getUsedQuota();
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
            my($client, %args) = @_;
            
            my $username = $args{'Username'};
            my $password = $args{'Password'};
            my $plan = $args{'Plan'};
            
            return xSYS::AddUser($config, $username, $password, $plan);
        },
        
        'SYS_UserDel' => sub {
            my($client, %args) = @_;
            
            my $username = $args{'Username'};
            
            return xSYS::DelUser($config, $username);
        },
        
        'SYS_DomainAdd' => sub {
            my($client, %args) = @_;
            
            my $username = $args{'Username'};
            my $domain = $args{'Domain'};
            
            return $client->setupSubdomain($username, $domain);
        },

        'SYS_CheckBandwith' => sub {            
            my($client, %args) = @_;
            
            my $username = $args{'Username'};
            
            return xSYS::CheckBandwidth($config, $username);
        },

        'SYS_RestoreBandwidth' => sub {
            my($client, %args) = @_;
            
            my $username = $args{'Username'};
            
            return xSYS::RestoreBandwidth($config, $username);
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
        xSYS::initialize($config);
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
                    closeSocket($select, $rc);
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

        
        my $packet = undef;
        
        eval
        {
            $packet = decode_json($data);
        }
        or do
        {
            my $response = new xResponse('1', '-1', 'Incorrect JSON format');
            return $response->send($socket);
        };
        
        unless (exists $packet->{'Auth'})
        {
            my $response = new xResponse('1', '-2', 'Invalid packet header, no Auth');
            return $response->send($socket);
        }
        
        my $client = new xUser($config, $packet->{'Auth'}{'Username'}, $packet->{'Auth'}{'PrivateKey'}, $sysadmin);
        my $result = $client->authentificate();
        if ($result != 0)
        {
            my $response = new xResponse('1', '-3', 'Could not authentificate');
            return $response->send($socket);
        }
        
        unless (exists $packet->{'Call'})
        {
            my $response = new xResponse('1', '-4', 'Invalid packet body, no Call');
            return $response->send($socket);
        }
        
        my $function = $packet->{'Call'}{'Function'};
        unless (defined($callbacks{$function}))
        {
            my $response = new xResponse('1', '-5', 'Function not found');
            return $response->send($socket);
        }
        
        if($function =~ m/^SYS_/ and not $sysadmin)
        {
            my $response = new xResponse('1', '-5', 'Function not found');
            return $response->send($socket);
        }
        
        $::errno = 0;
        $::errmsg = '';
        
        $result = $callbacks{$function}->($client, $packet->{'Call'}{'Arguments'});
        my $response = new xResponse($::errno != 0, $result, $::errmsg);
        return $response->send($socket);
    }
}

sub closeSocket
{
    my($select, $socket) = @_;

    $select->remove($socket);
    $socket->close;
};


__END__