package LogReporter::Filter::Syslog;
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
        my ($facility, $level, $host) = @+{'f','l','h'};
        $$line =~ s/$finder//;
        $meta->{syslog} = {
            facility => $facility,
            level => $level,
            host => $host,
        };
        return 1;
    } else {
        return 0;
    }
}


1;
