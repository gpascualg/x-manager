no warnings;

use strict;
use feature "switch";
use v5.10.1;

use Data::Dumper;

my $htaccessContent = '
<Files ~ "\.tpl$">
  Order allow,deny
  Deny from all
</Files>

<ifModule mod_rewrite.c>
	RewriteEngine On

	RewriteCond %{REQUEST_FILENAME} !-f
	RewriteCond %{REQUEST_FILENAME} !-d
	RewriteRule ^(.*)$ ./index.php?/$1 [L]
</ifModule>

';

my @lines = split("\n", $htaccessContent);
my @conditions = ();
my @rewrites = ();
my @server = ();
my @location = ();
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
                push(@server, "deny$deny;");
            }
        }
        
        when ("DirectoryIndex")
        {
            push(@server, "index " . $params[1] . ";");
        }
        
        when ("AddDefaultCharset")
        {
            push(@server, "charset " . lc($params[1]) . ";");
        }
        
        when ("ServerSignature")
        {
            push(@server, "autoindex " . lc($params[1]) . ";");
        }
        
        when ("ErrorDocument")
        {
            push(@server, "error_page " . $params[1] . ";");
        }
        
        when ("RewriteEngine")
        {
            if ($params[1] eq "On")
            {
                $doRewrites = 1;
            }
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
                    }
                }
            }
            
            if ($isTryFiles)
            {
                push(@conditions, "if (\$request_filename ~ \"$args[0]\")");
                push(@rewrites, "try_files \$uri \$uri/ $args[1]");
            }
            else
            {
                if ($F)
                {
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
                
                push(@location, $string);
            }
        }
    }
}

print Dumper(\@server);
print Dumper(\@location);

sub trim()
{
    my $str = shift;
    $str =~ s/^[ \n\t]+//;
    $str =~ s/[ \n\t]+$//;
    return $str;
}