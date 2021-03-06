#!/usr/bin/perl

use Time::Out qw(timeout) ;

use xConfig;
use xIO;
use xSYS;

package xUser;
sub new
{
    my $class = shift;
    my $self = {
        _config     => shift,
        _username   => shift,
        _md5Pass    => shift,
        _sysadmin   => shift,
    };
    
    bless $self, $class;
    return $self;
}

sub authentificate
{
    my($self) = @_;
    
    # SYSAdmins skip password verification, as they won't be using any
    if ($self->{_sysadmin})
    {
        return 0;
    }
    
    # Check for weird characters
    if (sanitize($self->{_username}, 'a-zA-Z0-9-_') != 1)
    {
        $::errno = 1;
        $::errmsg = 'Username contains invalid characters';
        return 1;
    }
    
    # Check for user in validity list
    if (open(my $FH, '<' . $self->{_config}->getBaseDir() . 'shadow'))
    {
        while (my $line = <$FH>)
        {
            my @fields = split(':', $line);
            chop($fields[1]); # Remove \n
            # [0] = Username
            # [1] = Password (hash$password)
            if ($fields[0] eq $self->{_username})
            {
                my @password = split('\$', $fields[1]);
                my $md5Priv = main::unix_md5_crypt($self->{_md5Pass}, $password[2]);
                
                if ($md5Priv eq $fields[1])
                {
                    $self->{_md5Pass} = $password[3];
                    return 0;
                }
            }
        }
    }
    
    $::errno = 1;
    $::errmsg = 'Invalid username/password';
    return 2;
}

sub setupSubdomain
{
    my($self, $username, $htmlDir) = @_;
    
    my $wwwDir = $self->{_config}->getWWWDir($username);
    
    unless (-e $wwwDir)
    {
        $::errno = 1;
        $::errmsg = 'Username is not found';
        return 1;
    }
    
    # We fork because the website may not be created yet, and we have to wait
    unless (fork)
    {
        # Wait for the device to be mounted (60 seconds time out) and everything done
        Time::Out::timeout 60 => sub {
            my $file = $wwwDir . '/config/.ready';
            
            while (1) 
            {
                if (-e $file)
                {
                    last;
                }
                
                sleep(1);
            }
        };
        if ($@)
        {
            print "[FAIL] Could not create subdomain `$htmlDir` for `$username`\n";
            exit;
        }
        
        # Make public_html folder, chown and chmod
        my $domain = $self->{_config}->getHTMLDefaultDomain($username, $htmlDir);
        my $publicHTMLPath = $wwwDir . '/' . $domain;
        my $logsPath = $wwwDir . '/logs/access.log';
        my $confPath = $wwwDir . '/config';
        my $group = $self->{_config}->getWWWGroup();
        
        mkdir $publicHTMLPath;
        `chown $username:$group $publicHTMLPath`;
        chmod 0650, $publicHTMLPath;
        
        # At it to the hosts files
        my $hosts = $wwwDir . '/config/hosts';
        `echo $domain >> $hosts`;
        
        # Make a copy of the template file
        my $templateSitesFile = $self->{_config}->getSitesAvailableDir() . '/template';
        my $domainSitesFile = $self->{_config}->getSitesAvailableDir() . '/' . $domain;
        my $linkSitesFile = $self->{_config}->getSitesEnabledDir() . '/' . $domain;
        `cp $templateSitesFile $domainSitesFile`;
        
        # Open file and replace
        my $FH = undef;
        if (open($FH, "<$domainSitesFile"))
        {
            my @lines = <$FH>;
            close($FH);
            
            my %findreplace = (
                '{SERVER_ROOT}' => $publicHTMLPath,
                '{SERVER_NAME}' => $domain,
                '{SERVER_LOGS}' => $logsPath,
                '{SERVER_CONF}' => $confPath
            );
            my @newlines = xSYS::FindAndReplace(\@lines, \%findreplace);
            
            if (open($FH, ">$domainSitesFile"))
            {
                print $FH @newlines;
                close($FH);
            }
        }
        
        # Make a syslink
        `ln -s $domainSitesFile $linkSitesFile`;
        
        # Nginx must be reloaded
        `/etc/init.d/nginx reload`;
        
        exit;
    }
    
    return 0;
}

sub GetBandwidth
{
    my($self) = @_;
    return xSYS::GetBandwidth($self->{_config}, $self->{_username});
}

sub getUsedBandwidth
{
    my($self) = @_;
    return xSYS::CalculateBandwidth($self->{_config}, $self->{_username});
}

sub getQuota
{
    my($self) = @_;
    return xSYS::GetQuota($self->{_config}, $self->{_username});
}

sub getUsedQuota
{
    my($self) = @_;
    return xSYS::CalculateQuota($self->{_config}, $self->{_username});
}
    
sub sanitize
{
    my($value, $OK_CHARS) = @_;
    
    my $org = $value;
    $value =~ s/[^$OK_CHARS]//go;        
    
    return ($value eq $org);
}

1;

__END__