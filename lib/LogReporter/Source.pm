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
        _services_count => 'count',
    },
);


sub register_service {
    my ($self, $service) = @_;
    $self->_services_push($service);
}

sub init {
    my ($self) = @_;
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

    unless (length @$services){
        warn "Skipping source " . $self->name() . " because no interested services.\n";
        return;
    }
    
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
