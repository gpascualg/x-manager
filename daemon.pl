#!/usr/bin/perl

### BEGIN INIT INFO
# Provides: x-manager
# Required-Start:
# Required-Stop:
# Should-Start:
# Should-Stop:
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Start and stop xManager
# Description: xManager
### END INIT INFO

use Proc::Daemon;
use IO::Socket::UNIX;

$| = 1;

my $daemon = Proc::Daemon->new(
    work_dir        => '/root/x-manager',
    child_STDOUT    => '/root/x-manager/out',
    child_STDERR    => '/root/x-manager/err',
    pid_file        => '/root/x-manager/pid',
    exec_command    => 'perl /root/x-manager/Main.pl',
);

sub do_stop
{
    my $socket = IO::Socket::UNIX->new(
        Type => SOCK_STREAM,
        Peer => '/var/run/xmanager.sock',
    );

    if (not $socket)
    {
        print("Can't create socket\n");
    }
    else
    {
        $socket->send("Identify::::");
        $socket->read(my $data, 4);
        $socket->send("SYS_DAEMON_STOP::");
        $socket->read($data, 4);
        $socket->close;
        
        print("Daemon stopped\n");
    }
}

sub do_start
{
    $exists = kill 0, `head -1 /root/x-manager/pid`;
    unless ($exists)
    {
        $PID = $daemon->Init();
        print "Daemon started\n";
    }
    else
    {
        print "Daemon already running\n";
    }
}

my($arg) = @ARGV;

if ($arg eq "start")
{
    do_start();
}
elsif ($arg eq "stop")
{
    do_stop();
}
elsif($arg eq "restart")
{
    do_stop();
    waitpid(`head -1 /root/x-manager/pid`, 0);
    do_start();
}
else
{
    die("Nothing to do\n");
}
