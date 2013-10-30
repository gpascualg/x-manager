
package htLocation;
sub new
{
    my $class = shift;
    my $self = {};
    $self->{_string} = [];
    
    bless $self, $class;
    return $self;
}

sub push
{
    my($self, $string) = @_;
    
    push(@{$self->{_strings}}, $string);
}

sub pop
{
    my $self = shift;
    my $string = '';
    
    while (defined(my $str = shift(@{$self->{_strings}})))
    {
        $string .= $str;
    }
    
    return $string;
}

1;

__END__