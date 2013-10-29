no warnings;

use strict;
use feature "switch";
use v5.10.1;

use Data::Dumper;

my %locations = ();
my %files = ();

sub Main
{
    my $pwd = $ARGV[1];
    
    my @cmd = split(' ', $ARGV[0], 3);
    my $filePath = $cmd[0] . $cmd[2];
    my @temp = split('/', $cmd[0], 3); # Divide in . / DOMAIN / PATH
    my $domain = $temp[1];    
    my $relativePath = "/" . $temp[2];

    # We want to emulate an Apache like system, so we will have to keep going from / directory, to top most one
    SearchInDir("$pwd/$domain", $relativePath);
}

sub SearchInDir
{
    my($path, $relativePath) = @_;
        
    if (-e $path . "/.htaccess")
    {
        DoParse($path . "/.htaccess", $relativePath);
    }
    
    print "IN: $path - $relativePath\n";
    
    my @files = <$path/*>;
    foreach my $file (@files) {
        if ($file) {
            my @temp = split('/', $file);
            
            SearchInDir($file, $relativePath . pop(@temp) . "/");
        }
    }
}

sub DoParse
{
    my($file, $location) = @_;
    
    print "Parsing: $file - $location\n";
}

Main();
