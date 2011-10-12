package LogReporter::Filter::DateRange;
use Moose;
use namespace::autoclean;
use DateTime;
use DateTime::Span;
extends 'LogReporter::Filter';

has 'range' => (
    is => 'ro',
    isa => 'DateTime::Span',
    required => 1,
);

has 'param' => (
    is => 'ro',
    isa => 'Str',
    required => 1,
    default => sub { 'dt' },
);

sub filter {
    my ($self, $line, $meta) = @_;
    my $dt = $meta->{ $self->{param} };
    if ( $self->range()->contains( $dt ) ){
        return 1;
    } else {
        return 0;
    }
}


1;
