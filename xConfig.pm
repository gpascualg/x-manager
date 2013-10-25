#!/usr/bin/perl

package xConfig;

sub new
{
    my $class = shift;
    my $self = {
        _baseDir            => '/root/x-manager/',
        _WWWDir             => '/www/',
        _WWWGroup           => 'www-data',
        _sitesAvailable     => '/etc/nginx/sites-available',
        _sitesEnabled       => '/etc/nginx/sites-enabled',
        _domainName         => 'populohosting.com',
        _freeSpace          => 0,
    };
    
    bless $self, $class;
    return $self;
}

sub getBaseDir
{
    my($self) = @_;
    return $self->{_baseDir};    
}

sub getWWWDir
{
    my($self, $username) = @_;
    return $self->{_WWWDir} . $username;
}

sub getWWWGroup
{
    my($self) = @_;
    return $self->{_WWWGroup};
}

sub getHTMLDefaultDir
{
    my($self) = @_;
    return $self->{_domainName};
}

sub getHTMLDefaultDomain
{
    my($self, $username, $htmlDir) = @_;
    
    if ($htmlDir == "")
    {
        return $username . $self->getHTMLDefaultDir();
    }
    
    return $username . $htmlDir;
}

sub getSitesAvailableDir()
{
    my($self) = @_;
    return $self->{_sitesAvailable};
}

sub getSitesEnabledDir()
{
    my($self) = @_;
    return $self->{_sitesEnabled};
}

sub getFreeSpace()
{
    my($self) = @_;
    return $self->{_freeSpace};
}

sub setFreeSpace()
{
    my($self, $freeSpace) = @_;
    $self->{_freeSpace} = $freeSpace;
}

sub substractSpace()
{
    my($self, $space) = @_;
    $self->{_freeSpace} -= $space;
}

1;

__END__