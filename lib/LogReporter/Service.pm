package LogReporter::Service;
use Moose;
use namespace::autoclean;

has 'name' => (
    is => 'ro',
    isa => 'Str',
    required => 1,
);

has 'sources' => (
    is => 'rw',
    isa => 'ArrayRef[ LogReporter::Source ]',
    required => 1,
);

has 'data' => (
    is => 'rw',
    isa => 'HashRef',
    default => sub { {}; },
);

sub init {
    my ($self) = @_;
    foreach my $source (@{ $self->sources }){
        $source->register_service($self);
    }
}

sub process_line {
    my ($self, $line, $meta) = @_;
    die "Not implemented!";
}

sub finalize {
    my ($self) = @_;
}

sub get_data {
    my ($self) = @_;
    return $self->data;
}


1;
