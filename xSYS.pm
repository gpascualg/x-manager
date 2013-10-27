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
}

sub deinitialize
{
    $userThread->kill('KILL')->detach();
}
    
sub AddUser
{
    my($config, $username, $password, $plan) = @_;
    
    # Setup configurations
    $quota = $planToQuota{$plan};
    $quotaMB = $quota / 1024;
    $bandwith = $planToBandwith{$plan};
    
    # Check that we have 1/2 more than the required space, just in case
    if ($config->getFreeSpace() < $quotaMB + ($quotaMB / 2))
    {
        return 1;
    }
    
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
    
    unless (fork)
    {    
        # We'll create a mount point!
        # Chown and chmod base dir for root only
        my $WWWDir = $config->getWWWDir($username);
        mkdir $WWWDir;
        chown "root", "root", $WWWDir;

        my $virtualFile = $config->getBaseDir() . 'virtual/' . $username . '.ext4';
        
        # Modify fstab
        my $FH = xIO::openLock('/etc/fstab', 'w');
        print $FH "$virtualFile    $WWWDir ext4    rw,loop,noexec,usrquota,grpquota  0 0\n";
        xIO::closeLock($FH);
    
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
        
        # Mount it
        `mount $WWWDir`;
        
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
    `umount $WWWDir`;
    `rm -rf $WWWDir`;
    `rm -f $virtualFile`;

    # Delete user from fstab
    $FH = xIO::openLock('/etc/fstab', 'r');
    if ($FH != 0)
    {
        my @lines = <$FH>;
        xIO::closeLock($FH);
        
        $FH = xIO::openLock('/etc/fstab', 'w+');
        if ($FH != 0)
        {
            my @newlines;
                
            foreach $line (@lines)
            {
                # TODO: This regex should be done with an escaped version of $WWWDir
                if (not ($line =~ m/\/www\/$username/))
                {                
                    push(@newlines, $line);
                }
            }
            
            print $FH @newlines;
            xIO::closeLock($FH);
        }
    }
    
    return 0;
}

sub CalculateQuota
{
    my($config, $username) = @_;
    
    my $sent = xSYS::BandwithCalculate($config, $username);
    my $quota = xSYS::GetQuota($config, $username);

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

sub RestoreQuota
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

sub BandwithCalculate
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

sub GetQuota
{
    my($config, $username) = @_;
    my $f = $config->getWWWDir($username) . '/quota';
    
    if (open(FILE, "<$conf"))
    {
        my @lines = <FILE>;
        close(FILE);
        return int(String::Util::trim($lines[0]));
    }
    
    return "";
}

1;

__END__