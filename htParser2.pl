no warnings;

use strict;
use feature "switch";
use v5.10.1;

use Data::Dumper;
use htLocation;

my %locations = ();

my %reinterpreter = (
    'HTTP_USER_AGENT' => 'http_user_agent',
    'HTTP_REFERER' => 'http_referer',
    'HTTP_COOKIE' => 'http_cookie',
    'HTTP_FORWARDED' => 'http_forwarded',
    'HTTP_HOST' => 'http_host',
    'HTTP_PROXY_CONNECTION' => 'http_proxy_connection',
    'HTTP_ACCEPT' => 'http_accept',
    'REMOTE_ADDR' => 'remote_addr',
    'REMOTE_PORT' => 'remote_port',
    'REMOTE_USER' => 'remote_user',
    'REQUEST_METHOD' => 'request_method',
    'SCRIPT_FILENAME' => 'uri',
    'PATH_INFO' => 'uri',
    'QUERY_STRING' => 'args',
    'DOCUMENT_ROOT' => 'document_root',
    'SERVER_NAME' => 'server_name',
    'SERVER_ADDR' => 'server_addr',
    'SERVER_PORT' => 'server_port',
    'SERVER_PROTOCOL' => 'server_protocol',
    'REQUEST_URI' => 'uri',
    'REQUEST_FILENAME' => 'request_filename'
);

sub Main
{
    my $pwd = $ARGV[1];
    
    my @cmd = split(' ', $ARGV[0], 3);
    my $filePath = $cmd[0] . $cmd[2];
    my @temp = split('/', $cmd[0], 3); # Divide in . / DOMAIN / PATH
    my $domain = $temp[1];    
    my $relativePath = "/";

    # We want to emulate an Apache like system, so we will have to keep going from / directory, to top most one
    SearchInDir("$pwd/$domain", $relativePath);
    
    my $fi = 0;
    while ((my $key, my $value) = each(%locations))
    {
        my $string = $value->pop();
        
        if ($key eq '/')
        {   
            `rm -f $pwd/config/$domain.root.nginx`;
            open(my $FH, ">$pwd/config/$domain.root.nginx");
            print $FH $string;
            close($FH);
        }
        else
        {
            $string = "location $key {\n" . $string . "}\n";
            
            `rm -f $pwd/config/$domain.$fi.nginx`;
            open(my $FH, ">$pwd/config/$domain.$fi.nginx");
            print $FH $string;
            close($FH);
            ++$fi;
        }
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
}

sub SearchInDir
{
    my($path, $relativePath) = @_;
        
    if (-e $path . "/.htaccess")
    {
        DoParse($path . "/.htaccess", $relativePath);
    }
        
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
    my($file, $relativePath) = @_;
    my @conditions = ();
    my @rewrites = ();
    my @temporal = ();
    my $isTryFiles = 0;
    my $currentVariable = 1;
    
    unless (defined($locations{$relativePath}))
    {
        $locations{$relativePath} = new htLocation();
    }
    my $location = $locations{$relativePath};
    
    open(my $FH, $file);
    my @lines = <$FH>;
    close($FH);

    foreach my $line (@lines)
    {
        # Split params, only function and argument!
        my @params = split(" ", $line, 2);
    
        given ($params[0])
        {
            when ("Options") {}
            when ("DefaultLanguage") {}
            when ("SetEnv") {}
            when ("AddType") {}
            when ("AddLanguage") {}
            when ("Order") {}
            when ("RewriteEngine") {}
            
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
                
                $location->push($string);
            }
        
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
                        $location->push("deny$deny;");
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
                    $location->push("index " . $params[1] . ";");
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
                    $location->push("charset " . lc($params[1]) . ";");
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
                    $location->push("autoindex " . lc($params[1]) . ";");
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
                    $location->push("error_page " . $params[1] . ";");
                }
                else
                {
                    push(@temporal, "error_page " . $params[1] . ";");
                }
            }
            
            when ("RewriteCond")
            {
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
                    $isTryFiles = 0;
                    my $currentValue = 'A';
                    my $currentChain = '';
                    
                    my $i = 0;
                    my $string = '';
                    while (defined (my $condition = shift(@conditions)))
                    {
                        $currentChain .= $currentValue;
                        $string .= $condition . "{\nset \$test$currentVariable = \"{\$test$currentVariable}$currentValue\";\n}\n";
                        $currentValue = chr(ord($currentValue) + 1);
                    }
                    
                    $string .= "if (\$test$currentVariable = $currentChain) {\n";
                    while (defined (my $rewrite = shift(@rewrites)))
                    {
                        $string .= $rewrite . "\n";
                    }
                    $string .= "}\n";
                                        
                    unless (defined($locations{$loc}))
                    {
                        $locations{$loc} = new htLocation();
                    }
                    $locations{$loc}->push($string);
                }
            }
        }
    }
}

sub trim
{
    my $str = shift;
    $str =~ s/^[ \n\t]+//;
    $str =~ s/[ \n\t]+$//;
    return $str;
}

Main();
