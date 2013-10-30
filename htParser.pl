no warnings;

use strict;
use feature "switch";
use v5.10.1;

use Data::Dumper;

my $pwd = $ARGV[1];
my @cmd = split(' ', $ARGV[0], 3);
my $filePath = $cmd[0] . $cmd[2];
my $relativePath = substr($cmd[0], 2);
my @t = split('/', $relativePath, 2);
my $domain = $t[0];
$relativePath = substr($relativePath , length($domain));

open(my $FH, $filePath);
my @lines = <$FH>;
close($FH);

my @conditions = ();
my @rewrites = ();
my @server = ();
my @temporal = ();
my %location = ();
my $doRewrites = 0;
my $isTryFiles = 0;

foreach my $line (@lines)
{
    # Split params, only function and argument!
    my @params = split(" ", $line, 2);
    my $isGlobalFunc = 1;
    
    given ($params[0])
    {
        when ("Options") {}
        when ("DefaultLanguage") {}
        when ("SetEnv") {}
        when ("AddType") {}
        when ("AddLanguage") {}
        when ("Order") {}
        
        when ("Deny")
        {
            my $deny = '';
            my @conds = split(' ', $params[1]);
            foreach my $cond (@conds)
            {
                if ($cond eq 'all')
                {
                    $deny .= ' all';
                }
            }
            
            if ($deny ne '')
            {
                if (@conditions == 0)
                {
                    push(@server, "deny$deny;");
                }
                else
                {
                    push(@temporal, "deny$deny;");
                }
            }
        }
        
        when ("DirectoryIndex")
        {
            if (@conditions == 0)
            {
                push(@server, "index " . $params[1] . ";");
            }
            else
            {
                push(@temporal, "index " . $params[1] . ";");
            }
        }
        
        when ("AddDefaultCharset")
        {
            if (@conditions == 0)
            {
                push(@server, "charset " . lc($params[1]) . ";");
            }
            else
            {
                push(@temporal, "charset " . lc($params[1]) . ";");
            }
        }
        
        when ("ServerSignature")
        {
            if (@conditions == 0)
            {
                push(@server, "autoindex " . lc($params[1]) . ";");
            }
            else
            {
                push(@temporal, "autoindex " . lc($params[1]) . ";");
            }
        }
        
        when ("ErrorDocument")
        {
            if (@conditions == 0)
            {
                push(@server, "error_page " . $params[1] . ";");
            }
            else
            {
                push(@temporal, "error_page " . $params[1] . ";");
            }
        }
        
        when ("RewriteEngine")
        {
            if ($params[1] eq "On")
            {
                $doRewrites = 1;
            }
        }
        
        when ("<Files")
        {
            my @matches = ($params[1] =~ /(.+?)>/ );
            if (@matches == 0)
            {
                continue;
            } 
            
            push(@conditions, "location " . $matches[0]);
        }
        
        when ("</Files>")
        {
            my $string = pop(@conditions) . " {\n";
            
            while (defined (my $temp = shift(@temporal)))
            {
                $string .= $temp . "\n";
            }
            
            $string .= "}\n";
            
            push(@server, $string);
        }
        
        when ("RewriteCond")
        {
            $isTryFiles = 0;
            
            my @matches = ($params[1] =~ /\%\{(.+?)\}/ );
            if (@matches == 0)
            {
                continue;
            }    
            
            my $variable = '$' . lc($matches[0]);
            my $cond = substr($params[1], 3 + length($variable));
            $cond = trim($cond);
            my $negative = '';
            my $wildcard = '';
            
            if (substr($cond, 0, 1) eq '!')
            {
                $negative = '!';
                $cond = substr($cond, 1);
            }
            
            @matches = ($cond =~ /\[(.+?)\]/ );
            if (@matches > 0)
            {
                my $len = length($matches[0]);
                @matches = split(',', $matches[0]);
                foreach my $condition (@matches)
                {
                    $condition = trim($condition);
                    if ($condition eq 'NC')
                    {
                        $wildcard = '*';
                    }                    
                }
                
                $cond = substr($cond, 0, -1 * $len - 2);
            }
            
            $cond = trim($cond);
            
            if ($cond eq '-f' || $cond eq '-d')
            {
                $isTryFiles = 1;
                continue;
            }
            
            push(@conditions, "if ($variable $negative~$wildcard \"$cond\")");
        }
        
        when ("RewriteRule")
        {
            my @args = split(' ', $params[1], 3);
            my $F = 0;
            my $type = '';
            my $last = 0;
            my $wildcard = '';
            my $loc = $relativePath;
            
            if (@args == 3)
            {
                my @matches = ($args[2] =~ /\[(.+?)\]/ );
                if (@matches > 0)
                {
                    my $len = length($matches[0]);
                    @matches = split(',', $matches[0]);
                    foreach my $condition (@matches)
                    {
                        $condition = trim($condition);
                        if ($condition eq 'L')
                        {
                            if ($type eq '')
                            {
                                $type = 'last';
                            }
                            $last = 1;
                        }
                        elsif ($condition eq 'F')
                        {
                            $F = 1;
                            $last = 1;
                        }
                        elsif ($condition eq 'R')
                        {
                            $type = 'redirect';
                        }
                        elsif ($condition eq 'R=301')
                        {
                            $type = 'permanent';
                        }
                        elsif ($condition eq 'NC')
                        {
                            $wildcard = '*';
                        }
                    }
                }
            }
            
            if ($isTryFiles)
            {
                #push(@conditions, "if (\$request_filename ~ \"$args[0]\")");
                #push(@rewrites, "try_files \$uri \$uri/ $args[1]");
                push(@rewrites, "rewrite $args[0] $args[1] last;");
            }
            else
            {
                if ($F)
                {
                    $loc = $args[0];
                    push(@rewrites, "return 403;");
                }
                else
                {
                    push(@rewrites, "rewrite $args[0] $args[1] $type;");
                }
            }
            
            if ($last)
            {
                my $i = 0;
                my $string = '';
                while (defined (my $condition = shift(@conditions)))
                {
                    $string .= $condition . "{\n";
                    ++$i;
                }
                
                while (defined (my $rewrite = shift(@rewrites)))
                {
                    $string .= $rewrite . "\n";
                }
            
                while ($i > 0)
                {
                    $string .= "}\n";
                    --$i;
                }
                
                print $string;
                
                unless (defined($location{$loc}))
                {
                    $location{$loc} = new htLocation($loc);
                }
                $location{$loc}->push($string);
            }
        }
    }
}


my $out = '';
while (defined (my $entry = shift(@server)))
{
    $out .= $entry . "\n";
}

$i = 0;
while (($key, $value) = each(%location)){
    $string = $value->pop();
    
    if ($key eq '')
    {   
        `rm -f $pwd/config/$domain.root.nginx`;
        open(my $FH, ">$pwd/config/$domain.root.nginx");
        print $FH $string;
        close($FH);
    }
    else
    {
        `rm -f $pwd/config/$domain.$i.nginx`;
        open(my $FH, ">$pwd/config/$domain.$i.nginx");
        print $FH $string;
        close($FH);
        ++$i;
    }
}

my $relativeHeaders = "\nlocation $relativePath {\n";
my $relative = '';
while (defined (my $entry = shift(@location)))
{
    $relative .= $entry . "\n";
}

$relativePath =~ s/\///;

if ($relativePath eq '')
{
    `rm -f $pwd/config/$domain.$relativePath.nginx`;
    open(my $FH, ">$pwd/config/$domain.$relativePath.nginx");
    print $FH $out;
    close($FH);
    
    
}
else
{
    `rm -f $pwd/config/$domain.$relativePath.nginx`;
    open(my $FH, ">$pwd/config/$domain.$relativePath.nginx");
    print $FH $out . $relativeHeaders . $relative . "}\n";
    close($FH);
}

# Test for errors on configuration
my $out = `nginx -t 2>&1`;
my @lines = split("\n", $out);

for my $line (@lines)
{
        my @matches = ($line =~ /nginx: \[emerg\] (.+?) in \/www\/(.+?):/);
        if (@matches == 2)
        {
            my $path = "/www/" . $matches[1];
            `rm $path`;
        }
}

# Reload configuration
`/etc/init.d/nginx reload &> /dev/null`;

sub trim
{
    my $str = shift;
    $str =~ s/^[ \n\t]+//;
    $str =~ s/[ \n\t]+$//;
    return $str;
}
