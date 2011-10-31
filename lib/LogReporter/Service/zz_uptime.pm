package LogReporter::Service::zz_uptime;
use Moose;
extends 'LogReporter::Service';
no warnings 'misc';

override get_output => sub {
    my ($self) = @_;
    print `uptime`;
};


__PACKAGE__->meta->make_immutable;
1;
