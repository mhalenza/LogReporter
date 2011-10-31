package LogReporter::Filter;
use Moose;

#requires 'filter';

sub filter {
    my ($self, $line, $meta) = @_;
    # Default is to pass all lines
    return 1;
}


__PACKAGE__->meta->make_immutable;
1;
