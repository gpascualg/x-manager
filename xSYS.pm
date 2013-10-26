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

my $userAddQueue = Thread::Queue->new();

my $userThread = threads->create(
    sub {
        while (defined(my $user = $userAddQueue->dequeue())) {
            my @params = split(' ', $user);
            
            @args = (
                '/usr/sbin/useradd', 
                '-s', '/usr/sbin/nologin',
                '-g', $params[2],
                '-d', $params[3], 
                '-p', $params[1],
                $params[0]
            );
        
            $result = system(@args);
            if ($result != 0)
            {
                print "Could not add: /$user/ due to: $result\n";
            }
        }
    }
);

sub end
{
    $userAddQueue->end();
    $userThread->join();
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
    my $salt = `mkpasswd.pl`;
    my $md5Pass = main::unix_md5_crypt($password, $salt);        
    my $group = $config->getWWWGroup();
    my $home = $config->getWWWDir($username);
    $userAddQueue->enqueue("$username $md5Pass $group $home");
    
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
        $WWWDir = $config->getWWWDir($username);
        mkdir $WWWDir;
        chown "root", "root", $WWWDir;

        # Modify fstab
        my $FH = xIO::openLock('/etc/fstab', 'w');
        print $FH "/root/virtual/$username.ext4    /www/$username ext4    rw,loop,noexec,usrquota,grpquota  0 0\n";
        xIO::closeLock($FH);
    
        # Create the LVM
        `touch /root/virtual/$username.ext4`;
        #`dd if=/dev/zero of=/root/virtual/$username.ext4 count=1024000`;
        `truncate -s $quota /root/virtual/$username.ext4`;
        `/sbin/mkfs -t ext4 -q /root/virtual/$username.ext4 -F`;
        
        # Check loops
        if ($loop)
        {
            # We must create another loop
            `mknod -m640 /dev/loop$loop b 7 $loop`;
            `chown root:disk /dev/loop$loop`;
        }
        
        # Mount it
        `mount /www/$username`;
        
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
    
    # Delete user
    @args = (
        '/usr/sbin/userdel',
        '-r',
        "$username"
    );
    
    # Execute and ignore mail/home directories errors
    if (system(@args) & ~3072)
    {
        return 1;
    }
    
    # Readd space
    $config->addSpace(`head -1 /www/$username/config/diskquota`);
    
    # Unmount filesystem and delete
    `umount /www/$username`;
    `rm -rf /www/$username`;
    `rm -f /root/virtual/$username.ext4`;

    # Delete user from fstab
    my $FH = xIO::openLock('/etc/fstab', 'r');
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