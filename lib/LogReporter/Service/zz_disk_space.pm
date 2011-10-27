package LogReporter::Service::zz_disk_space;
use Moose;
use namespace::autoclean;
extends 'LogReporter::Service';
no warnings 'misc';

has 'df_cmd' => (
    is => 'rw',
    isa => 'Str',
    required => 1,
    default => sub { 'df -h -l -x tmpfs -x udf -x iso9660'; },
);

has 'du_cmd' => (
    is => 'rw',
    isa => 'Str',
    required => 1,
    default => sub { 'du -s --block-size=1048576 -h $XXX | sort -n -r -k 1'; },
);

has 'dirs' => (
    is => 'rw',
    isa => 'ArrayRef[ Str ]',
    required => 1,
    default => sub { []; },
);

override get_output => sub {
    my ($self) = @_;
    
    print `$df_cmd`;
};

1;
