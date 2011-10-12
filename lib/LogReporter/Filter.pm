package LogReporter::Filter;
use Moose;
use namespace::autoclean;

#requires 'filter';

sub filter {
    my ($self, $line, $meta) = @_;
    # Default is to pass all lines
    return 1;
}

1;
