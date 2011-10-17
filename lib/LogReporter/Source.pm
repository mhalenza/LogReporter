package LogReporter::Source;
use Moose;
use namespace::autoclean;
use feature ':5.10';

has 'name' => (
    is => 'ro',
    isa => 'Str',
    required => 1,
);

has 'filters' => (
    is => 'ro',
    isa => 'ArrayRef[ LogReporter::Filter ]',
    required => 1,
    traits => ['Array'],
    handles => {
        filters_push => 'push',
    },
);

has '_services' => (
    is => 'rw',
    isa => 'ArrayRef[ LogReporter::Service ]',
    required => 1,
    default => sub { [] },
    traits => ['Array'],
    handles => {
        _services_push => 'push',
    },
);


sub register_service {
    my ($self, $service) = @_;
    $self->_services_push($service);
}

sub init {
    my ($self) = @_;
    my $filters = $self->filters;
    unless ( ref $filters->[0] && $filters->[0]->can('isa') && $filters->[0]->isa('LogReporter::Filter::Date') ){
        unshift @$filters, LogReporter::Filter::ISO8601->new(format => '^(\S+)\s+');
    }
    unless ( ref $filters->[1] && $filters->[1]->can('isa') && $filters->[1]->isa('LogReporter::Filter::DateRange') ){
        splice @$filters, 1, 0, LogReporter::Filter::DateRange->new(
            range => LogReporter->instance->config->{Range}, # This is horrible spaghetti logic :(
        );
    }
}
sub get_line {
    my ($self) = @_;
    die "Not implemented!";
}
sub finalize {
    my ($self) = @_;
}

sub run {
    my ($self) = @_;
    my $filters = $self->filters;
    my $services = $self->_services;
    
    LINE: while( my $line = $self->get_line() ){
        my $meta = {};
#        say "L: $line";
        foreach my $filter (@$filters){
#            say " F: $filter";
            unless ( $filter->filter(\$line,$meta) ){
                next LINE;
            }
        }
#        say " L: $line\n";
        foreach my $service (@$services){
            $service->process_line( $line, $meta );
        }
    }
}


1;
