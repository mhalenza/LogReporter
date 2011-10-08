package LogReporter::Filter::Date;
use Moose;
use namespace::autoclean;
use DateTime;
use DateTime::Format::Builder;

has 'format' => (
    is => 'ro',
    isa => 'Str',
    required => 1,
);

has 'fields' => (
    is => 'ro',
    isa => 'ArrayRef[Str]',
    required => 1,
);

has '_parser' => (
    is => 'rw',
    isa => 'DateTime::Format::Builder',
    required => 1,
    init_arg => undef, # don't let parser be passed to new()
    lazy_build => 1,
    builder => '_build_parser',
);

sub _build_parser {
    my ($self) = @_;
    my $finder = $self->format;
    my $fields = $self->fields;
    my $parser = DateTime::Format::Builder->create_parser(
        regex  => qr/$finder/,
        params => $fields,
    );
    return $parser;
}

sub filter {
    my ($self, $line, $meta) = @_;
    my $finder = $self->format();
    if ( $$line =~ m/($finder)/ ){
        my $found = $1;
        $$line =~ s/$finder//;
        my $dt = $self->_parser->parse_datetime($found);
        $meta->{timestamp} = $dt;
    } else {
        return 0;
    }
}


with 'LogReporter::Filter';
1;
