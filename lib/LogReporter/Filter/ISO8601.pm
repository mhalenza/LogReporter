package LogReporter::Filter::ISO8601;
use Moose;
use namespace::autoclean;
use DateTime;
use DateTime::Format::ISO8601;

extends 'LogReporter::Filter';
with 'LogReporter::Filter::Date';

has 'format' => (
    is => 'ro',
    isa => 'Str',
    required => 1,
);


sub filter {
    my ($self, $line, $meta) = @_;
    my $finder = $self->format();
    if ( $$line =~ $finder ){
        my $found = $1;
        $$line =~ s/$finder//;
        my $dt = DateTime::Format::ISO8601->parse_datetime( $found );
        $meta->{timestamp} = $dt;
        return 1;
    } else {
        return 0;
    }
}


1;
