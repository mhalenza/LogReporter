package LogReporter::Service::zz_uptime;
use Moose;
use namespace::autoclean;
extends 'LogReporter::Service';
no warnings 'misc';

override get_output => sub {
    my ($self) = @_;
    print `uptime`;
};

1;
