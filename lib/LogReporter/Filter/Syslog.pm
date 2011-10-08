package LogReporter::Filter::Syslog;
use Moose;
use namespace::autoclean;

has 'facility' => (
    is => 'ro',
    isa => 'Str',
);

has 'level' => (
    is => 'ro',
    isa => 'Int',
);

sub filter {
    my ($self, $line, $meta) = @_;
    #TODO: implement
    return 1;
}


with 'LogReporter::Filter';
1;
