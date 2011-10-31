package LogReporter::Service::Crond;
use Moose;
extends 'LogReporter::Service';

override process_line => sub {
    my ($self, $line, $meta) = @_;
};


__PACKAGE__->meta->make_immutable;
1;
