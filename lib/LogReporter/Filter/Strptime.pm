package LogReporter::Filter::Strptime;
use Moose;
use namespace::autoclean;
use DateTime;
use DateTime::Format::Strptime;

extends 'LogReporter::Filter';
with 'LogReporter::Filter::Date';

has 'finder' => (
    is => 'ro',
    isa => 'Str',
    required => 1,
);

has 'format' => (
    is => 'ro',
    isa => 'Str',
    required => 1,
);

has '_parser' => (
    is => 'ro',
    isa => 'DateTime::Format::Strptime',
    required => 1,
    lazy => 1,
    builder => '_build_parser',
);

sub _build_parser {
    my ($self) = @_;
    return DateTime::Format::Strptime->new(
        pattern => $self->format(),
        on_error => 'croak',
    );
}


sub filter {
    my ($self, $line, $meta) = @_;
    my $finder = $self->finder();
    if ( $$line =~ $finder ){
        my $found = $1;
        $$line =~ s/$finder//;
        my $dt = $self->_parser->parse_datetime( $found );
        $meta->{timestamp} = $dt;
        return 1;
    } else {
        return 0;
    }
}


1;
