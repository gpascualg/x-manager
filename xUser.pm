#!/usr/bin/perl

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
        _privKey    => shift,
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
        return 1;
    }
    
    # Check for user in validity list
    if (open(my $FH, '<' . $self->{_config}->getBaseDir() . 'shadow'))
    {
        while (my $line = <$FH>)
        {
            my @fields = split(':', $line);
            # [0] = Username
            # [1] = Password (hash$password)
            if ($fields[0] eq $self->{_username})
            {
                my @password = split('$', $fields[1], 2);
                my $md5Priv = main::unix_md5_crypt($password[1], $password[0]);
                
                if ($md5Priv == $self->{_privKey})
                {
                    return 0;
                }
            }
            $total += int($fields[1]);
        }
    }
    
    return 2;
}

sub setupSubdomain
{
    my($self, $htmlDir, $pool) = @_;
    
    # Make public_html folder, chown and chmod
    my $domain = $self->{_config}->getHTMLDefaultDomain($username, $htmlDir);    
    my $wwwDir = $self->{_config}->getWWWDir($username);
    my $publicHTMLPath = $wwwDir . '/' . $domain;
    my $logsPath = $self->{_config}->getWWWDir($username) . '/logs';
    
    mkdir $publicHTMLPath;
    chown $username, $config->getWWWGroup(), $publicHTMLPath;
    chmod 0644, $publicHTMLPath;
    
    my $FH = xIO::openLock($self->{_config}->getSitesAvailableDir() . '/' . $domain);
    
    xIO::closeLock($FH);
}

sub getBandwith
{
    my($self) = @_;
    return xSYS::BandwithCalculate($self->{_config}, $self->{_username});
}

sub getQuota
{
    my($self) = @_;
    return xSYS::GetQuota($self->{_config}, $self->{_username});
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