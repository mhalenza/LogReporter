package LogReporter::Service;
use Moose;

has 'name' => (
    is => 'ro',
    isa => 'Str',
    required => 1,
);

has 'sources' => (
    is => 'ro',
    isa => 'ArrayRef[ LogReporter::Source ]',
    required => 1,
);

has 'data' => (
    is => 'rw',
    isa => 'HashRef',
    default => sub { {}; },
);

has 'filters' => (
    is => 'ro',
    isa => 'ArrayRef[ LogReporter::Filter ]',
    required => 1,
);

has 'master' => (
    is => 'ro',
    isa => 'LogReporter',
    required => 1,
);

sub init {
    my ($self) = @_;
    foreach my $source (@{ $self->sources }){
        $source->register_service($self);
    }
}

sub process_line {
    my ($self, $line, $meta) = @_;
    my $filters = $self->filters;
    foreach my $filter (@$filters){
#       print STDERR "  F: $filter\n";
        unless ( $filter->filter(\$line,$meta) ){
            return 0;
        }
#       print STDERR "    L: $line\n";
    }
    return 1;
}

sub finalize {
    my ($self) = @_;
}

sub get_output {
    my ($self) = @_;
}


__PACKAGE__->meta->make_immutable;
1;
