#!/usr/bin/perl

use Fcntl qw(:DEFAULT :flock SEEK_END);
use strict;

package xIO;
sub new
{
    my $class = shift;
    my $self = {
    };
    
    bless $self, $class;
    return $self;
}

sub openLock
{
    my($filename, $flags) = @_;
    
    if ($flags eq 'w+')
    {
        $flags = Fcntl::O_WRONLY | Fcntl::O_TRUNC;
    }
    elsif ($flags eq 'w')
    {
        $flags = Fcntl::O_WRONLY | Fcntl::O_APPEND;
    }
    else
    {
        $flags = Fcntl::O_RDONLY;
    }
    
    sysopen(my $FH, $filename, $flags)
        or return 0;
        
    flock($FH, Fcntl::LOCK_EX)
        or return 0;

    return $FH;
}

sub closeLock
{
    my($FH) = @_;
    
    flock($FH, Fcntl::LOCK_UN)
        or return 0;
        
    close($FH);
}

1;

__END__