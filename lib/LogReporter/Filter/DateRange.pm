package LogReporter::Filter::DateRange;
use Moose;
use namespace::autoclean;
use DateTime;

sub filter {
    my ($self, $line) = @_;
}

with 'LogReporter::Filter';
1;
