#!/usr/bin/perl

use Crypt::PasswdMD5;

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
use POSIX qw(:sys_wait_h);
sub REAPER 
{
    while ((my $pid = waitpid(-1,WNOHANG)) > 0) {
        sleep 1;
    }
    
    # Free only if no forked process
    if ($forked == 0)
    {
        # Free RAM! Commands above abuse it
        `sync`;
        `echo 3 > /proc/sys/vm/drop_caches`;
    }
}

$SIG{CHLD} = \&REAPER;

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
    
    my $salt = `mkpasswd.pl`;
    my $md5Pass = main::unix_md5_crypt($password, $salt);

    @args = (
        '/usr/sbin/useradd', 
        '-s', '/usr/sbin/nologin',
        '-g', $config->getWWWGroup(),
        '-d', $config->getWWWDir($username), 
        '-p', $md5_pass,
        "$username"
    );
    
    my $result = system(@args);
    if ($result != 0)
    {
        return 2;
    }
    
    $config->substractSpace($quotaMB);
    
    # We'll create a mount point!
    # Chown and chmod base dir for root only
    $WWWDir = $config->getWWWDir($username);
    mkdir $WWWDir;
    chown "root", "root", $WWWDir;
    
    # Loops should be checked on main
    my $loop = $config->pullLoop();

    # Create the mount file of 500MB
    # Do it in a separated fork, as to avoid locking out users
    ++$forked;
    unless (fork)
    {    
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
        
        # Free RAM! Commands above abuse it
        `sync`;
        `echo 3 > /proc/sys/vm/drop_caches`;
        
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