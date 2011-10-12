package LogReporter::Service::Iptables;
use Moose;
use namespace::autoclean;
extends 'LogReporter::Service';

override process_line => sub {
    my ($self, $line, $meta) = @_;
    
};

1;
