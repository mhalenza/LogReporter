package LogReporter::Source;
use Moose;
use namespace::autoclean;

has 'name' => (
    is => 'ro',
    isa => 'Str',
    required => 1,
);

has 'filters' => (
    is => 'ro',
    isa => 'ArrayRef[LogReporter::Filter]',
    required => 1,
);

has '_services' => (
    is => 'rw',
    isa => 'ArrayRef[LogReporter::Service]',
    required => 1,
    default => sub { [] },
);


sub register_service {
    my ($self, $service) = @_;
    $self->_services->push($service);
}

sub init { }
sub get_line { }
sub finalize { }

sub run {
    my ($self) = @_;
    my $filters = $self->filters;
    my $services = $self->_services;
    
    LINE: while( my $line = $self->get_line() ){
        my $meta = {};
        foreach my $filter (@$filters){
            unless ( $filter->filter(\$line,$meta) ){
                next LINE;
            }
        }
        foreach my $service (@$services){
            $service->process_line( \$line, $meta );
        }
    }
}


1;
