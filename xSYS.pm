#!/usr/bin/perl

use Crypt::PasswdMD5;
use POSIX ":sys_wait_h";
use threads;
use Thread::Queue;
    
package xSYS;

# In B
%planToQuota = (
    0 => 524288000,
    1 => 1073741824,
    2 => 2147483648
);

# In B
%planToBandwith = (
    0 => 2147483648,
    1 => 5368709120,
    2 => 21474836480
);

my $forked = 0;
$SIG{CHLD} = \&REAPER;
sub REAPER {
    my $pid = waitpid(-1, POSIX::WNOHANG);
    if ($pid == -1) {
        # no child waiting.  Ignore it.
    } 
    elsif (main::WIFEXITED($?)) 
    {
        if ($forked > 0)
        {
            --$forked;
            if ($forked == 0)
            {
                # Free RAM! Commands above abuse it
                `sync`;
                `echo 3 > /proc/sys/vm/drop_caches`;
            }
        }
    } 
    else 
    {
        #print "False alarm on $pid.\n";
    }
    
    $SIG{CHLD} = \&REAPER;          # in case of unreliable signals
} 

my $userQueue = undef;
my $userThread = undef;
my $fstabQueue = undef;
my $fstabThread = undef;
my $shadow = undef;

sub initialize
{
    my($config) = @_;
    
    $shadow = $config->getBaseDir() . 'shadow';
    $userQueue = Thread::Queue->new();
    $userThread = threads->create(
        sub {
            $SIG{'KILL'} = sub { threads->exit(); };
            
            while (defined(my $user = $userQueue->dequeue())) {
                my @params = split("\0\0", $user);
                my $mode = $params[0];
                my $username = $params[1];
                
                # Add user
                if ($mode == 0)
                {
                    my $password = $params[2];
                    
                    @args = (
                        '/usr/sbin/useradd', 
                        '-s', '/usr/sbin/nologin',
                        '-g', $params[3],
                        '-d', $params[4], 
                        '-p', $password,
                        $username
                    );
                
                    $result = system(@args);
                    if ($result != 0)
                    {
                        print "[FAIL] Error $result on useradd `$params[0]`, `$params[1]`, `$params[2]`, $params[3], $params[4]\n";
                    }
                    
                    # Add user to custom shadow file
                    `echo '$username:$password' >> $shadow`;
                }
                else
                {
                    # Delete user
                    @args = (
                        '/usr/sbin/userdel',
                        '-r',
                        "$username"
                    );
                        
                    # Execute and ignore mail/home directories errors
                    if (system(@args) & ~3072)
                    {
                        print "[FAIL] Error $result on userdel `$params[0]`, `$params[1]`\n";
                    }

                    # Delete user from shadow
                    open(my $FH, "<$shadow");
                    if ($FH != 0)
                    {
                        my @lines = <$FH>;
                        close($FH);
                        
                        open($FH, ">$shadow");
                        if ($FH != 0)
                        {
                            my @newlines;
                                
                            foreach $line (@lines)
                            {
                                # TODO: This regex should be done with an escaped version of $WWWDir
                                if (not ($line =~ m/^$username:/))
                                {                
                                    push(@newlines, $line);
                                }
                            }
                            
                            print $FH @newlines;
                            close($FH);
                        }
                    }
                }
            }
        }
    );
    
    $fstabQueue = Thread::Queue->new();
    $fstabThread = threads->create(
        sub {
            $SIG{'KILL'} = sub { threads->exit(); };
            
            while (defined(my $action = $fstabQueue->dequeue())) {
                my @params = split("\0\0", $action, 2);
                my $mode = $params[0];
                my $args = $params[1];
                
                # Add to fstab
                if ($mode == 0)
                {
                    my $FH = xIO::openLock('/etc/fstab', 'w');
                    print $FH $args;
                    xIO::closeLock($FH);
                }
                else
                {
                    # Delete user from fstab
                    my $FH = xIO::openLock('/etc/fstab', 'r');
                    if ($FH != 0)
                    {
                        my @lines = <$FH>;
                        xIO::closeLock($FH);
                        
                        my @newlines;                            
                        foreach $line (@lines)
                        {
                            # TODO: This regex should be done with an escaped version of $WWWDir
                            if (not ($line =~ m/$args/))
                            {                
                                push(@newlines, $line);
                            }
                        }
                            
                        $FH = xIO::openLock('/etc/fstab', 'w+');
                        if ($FH != 0)
                        {                            
                            print $FH @newlines;
                            xIO::closeLock($FH);
                        }
                    }
                }
            }
        }
    );
}

sub deinitialize
{
    $userThread->kill('KILL')->detach();
    $fstabThread->kill('KILL')->detach();
}
    
sub AddUser
{
    my($config, $username, $password, $plan) = @_;
    
    # Setup configurations
    my $quota = $planToQuota{$plan};
    my $quotaMB = $quota / 1024;
    my $bandwith = $planToBandwith{$plan};
    
    # Check that we have 1/2 more than the required space, just in case
    if ($config->getFreeSpace() < $quotaMB + ($quotaMB / 2))
    {
        return 1;
    }
    
    # If the user exists, return
    if (getpwnam($username))
    {
        return 2;
    }    
    
    # Create user (enqueue it)
    my $salt = `mkpasswd.pl --nospecial`;
    my $md5Pass = main::unix_md5_crypt($password, $salt);        
    my $group = $config->getWWWGroup();
    my $home = $config->getWWWDir($username);
    $userQueue->enqueue("0\0\0$username\0\0$md5Pass\0\0$group\0\0$home");
    
    # Loops should be checked on main
    my $loop = $config->pullLoop();
    
    # Increase forked count
    ++$forked;
    
    # Substract free space
    $config->substractSpace($quotaMB);
    
    # Enqueue fstab modification
    my $virtualFile = $config->getBaseDir() . 'virtual/' . $username . '.ext4';
    my $WWWDir = $config->getWWWDir($username);
    $fstabQueue->enqueue("0\0\0$virtualFile    $WWWDir ext4    rw,loop,noexec,usrquota,grpquota,nosuid,nodev  0 0\n");
    
    # Fork because it may take a while depending on file size
    unless (fork)
    {    
        # We'll create a mount point!
        # Chown and chmod base dir for root only
        mkdir $WWWDir;
        chown "root", "root", $WWWDir;
            
        # Create the LVM
        `touch $virtualFile`;
        #`dd if=/dev/zero of=$virtualFile count=1024000`;
        `truncate -s $quota $virtualFile`;
        `/sbin/mkfs -t ext4 -q $virtualFile -F`;
        
        # Check loops
        if ($loop)
        {
            # We must create another loop
            `mknod -m640 /dev/loop$loop b 7 $loop`;
            `chown root:disk /dev/loop$loop`;
        }
        
        # Mount using the whole command, as fstab modification may not be ready yet
        `mount -o loop,rw,usrquota,grpquota,noexec,nosuid,nodev $virtualFile $WWWDir`;
        
        # Chown and chmod config dir for root only
        mkdir $WWWDir . '/config';
        chown "root", "root", $WWWDir . '/config';
        chmod 0750, $WWWDir . '/config';
        
        # Create config files
        `echo "$quota" > $WWWDir/config/diskquota`;
        `echo "$bandwith" > $WWWDir/config/bandwith`;
        
        # Chown and chmod logs dir for root only
        mkdir $WWWDir . '/logs';
        chown "root", "root", $WWWDir . '/logs';
        chmod 0750, $WWWDir . '/logs';
        `touch $WWWDir/logs/access.log`;
        
        # Flag as ready
        `touch $WWWDir/config/.ready`;
        
        # Start inotifywait
        system("./htWait.sh $WWWDir &");
        
        exit;
    }
    
    return 0;
}

sub DelUser
{
    my($config, $username) = @_;
    
    # Does the user exist? If not, return error
    unless (getpwnam($username))
    {
        return 1;
    }
    
    # Queue user for deleting
    $userQueue->enqueue("1\0\0$username");
    
    # Set some variables
    my $WWWDir = $config->getWWWDir($username);
    my $virtualFile = $config->getBaseDir() . 'virtual/' . $username . '.ext4';
    my $sitesAvailable = $config->getSitesAvailableDir();
    my $sitesEnabled = $config->getSitesEnabledDir();
    
    # Stop inotify
    xSYS::DoKill(`ps -ef | egrep './htWait.sh $WWWDir\$' | awk '{print \$2}' | head -1`);
    
    # Readd space
    $config->addSpace(`head -1 $WWWDir/config/diskquota`);
    
    # Delete virtual hosts
    open($FH, "<$WWWDir/config/hosts");
    while (my $line = <$FH>)
    {
        chop($line); # Remove \n
        `rm $sitesEnabled/$line`;
        `rm $sitesAvailable/$line`;
    }
    close($FH);
    
    # Unmount filesystem and delete
    `umount -l $WWWDir`;
    `rm -rf $WWWDir`;
    `rm -f $virtualFile`;

    # Delete user from fstab
    $fstabQueue->enqueue("1\0\0 \/www\/$username ");
        
    return 0;
}

sub CheckBandwidth
{
    my($config, $username) = @_;
    
    my $sent = xSYS::CalculateBandwith($config, $username);
    my $quota = xSYS::GetBandwidth($config, $username);

    if ($sent >= $quota)
    {
        # WHOPS! Impose limitations
        my $filepath = $config->getWWWDir($username) . '/hosts';
        my $FH = undef;
        if (open($FH, "<$filepath"))
        {
            while (my $line = <$FH>)
            {
                $line =~ s/^\s+//;
                $line =~ s/\s+$//;
                $conf = $config->getSitesAvailableDir() . '/' . $line . '.vhost';

                my $cf = undef;
                if (open($cf, "<$conf"))
                {
                    my @lines = <$cf>;
                    close($cf);
                    
                    my %findreplace = (
                        'set \$limited_quota 0' => 'set $limited_quota 1',
                    );
                    my @newlines = xSYS::FindAndReplace(\@lines, \%findreplace);
                    
                    if (open($cf, ">$conf"))
                    {
                        print $cf @newlines;
                        close($cf);
                    }
                }
            }

            close $FH;
        }
        
        return 0;
    }
    
    return 1;
}

sub RestoreBandwidth
{
    my($config, $username) = @_;
    
    # WHOPS! Impose limitations
    my $filepath = $config->getWWWDir($username) . '/hosts';
    my $FH = undef;
    if (open($FH, "<$filepath"))
    {
        while (my $line = <$FH>)
        {        
            $line =~ s/^\s+//;
            $line =~ s/\s+$//;
            $conf = $config->getSitesAvailableDir() . '/' . $line . '.vhost';

            my $cf = undef;
            if (open($cf, "<$conf"))
            {
                my @lines = <$cf>;
                close($cf);
                
                my %findreplace = (
                    'set \$limited_quota 1' => 'set $limited_quota 0',
                );
                my @newlines = xSYS::FindAndReplace(\@lines, \%findreplace);
                
                if (open($cf, ">$conf"))
                {
                    print $cf @newlines;
                    close($cf);
                }
            }
        }

        close $FH;
    }
        
    return 0;
}

sub FindAndReplace
{
    my @lines = @{+shift};
    my %findreplace = %{+shift};
    
    my @newlines;
                
    foreach $line (@lines)
    {
        while (my ($find, $replace) = each (%findreplace))
        {
            $line =~ s/$find/$replace/g;
        }
        
        push(@newlines, $line);
    }
    
    return @newlines;
}

sub trim
{
    my $str = shift;
    $str =~ s/^[ \n\t]+//;
    $str =~ s/[ \n\t]+$//;
    return $str;
}

sub DoKill
{
    my $pid = shift;
    $pid = xSYS::trim($pid);
    
    foreach my $cpid (`ps -o pid= --ppid $pid`)
    {
        xSYS::DoKill($cpid);
    }
    
    `kill -9 $pid > /dev/null 2>&1`
}

sub CalculateBandwith
{
    my($config, $username) = @_;
    
    my $total = 0;
    
    my $dir = $config->getWWWDir($username) . '/logs/';
    foreach my $fp (glob("$dir/*.log"))
    {
        my $FH = undef;
        if (open($FH, "<$fp"))
        {
            while (my $line = <$FH>)
            {
                my @fields = split(' ', $line);
                # [0] = Date
                # [1] = Bytes
                $total += int($fields[1]);
            }

            close $FH;
        }
    }
    
    return $total;
}

sub GetBandwith
{
    my($config, $username) = @_;
    my $f = $config->getWWWDir($username) . '/config/bandwith';
    
    return `head -1 $f`;
}

sub GetQuota
{
    my($config, $username) = @_;
    my $f = $config->getWWWDir($username) . '/config/diskquota';
    
    return `head -1 $f`;
}

sub CalculateQuota
{
    my($config, $username) = @_;
    return `df | egrep ' /www/$username\$' | awk '{print \$3}'`;
}

1;

__END__