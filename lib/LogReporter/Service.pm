package LogReporter::Service;
use Moose;
use namespace::autoclean;

has 'sources' => (
    is       => 'rw',
    isa      => 'ArrayRef[LogReporter::Source]',
    required => 1,
);

has 'filters' => (
    is       => 'rw',
    isa      => 'ArrayRef[LogReporter::Filter]',
    required => 1,
);

sub init {
    my ($self) = @_;
    foreach my $filter (@{ $self->filters }){
        $filter->register_service($self);
    }
}

sub process_line {
    my ($self, $line, $meta) = @_;
}

sub finalize {
#    my ($self) = @_;
}

sub get_output {
#    my ($self) = @_;
    return "";
}


1;
