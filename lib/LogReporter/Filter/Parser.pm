package LogReporter::Filter::Parser;
use Moose;
use namespace::autoclean;

extends 'LogReporter::Filter';

has 'format' => (
    is => 'ro',
    isa => 'Str',
    required => 1,
);

sub filter {
    my ($self, $line, $meta) = @_;
    my $finder = $self->format();
    if ( $$line =~ $finder ){
        my $res = { %+ };
        $$line =~ s/$finder//;
        $meta->{$_} = $res->{$_} for keys %$res;
    }
    return 1;
}


1;
