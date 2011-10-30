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
    default => sub { 'du -s --block-size=1048576 -h $XXX'; },
);

has 'dirs' => (
    is => 'rw',
    isa => 'ArrayRef[ Str ]',
    required => 1,
    default => sub { []; },
);

override get_output => sub {
    my ($self) = @_;
    my $df_cmd = $self->df_cmd;
    print `$df_cmd`;
    
    if ( scalar @{ $self->dirs } > 0 ){
        print "\n";
        my $du_cmd = $self->du_cmd;
        print "Size    Directory\n";
        my $dirs = join ' ', @{ $self->dirs };
        $du_cmd =~ s/\$XXX/$dirs/;
        print `$du_cmd`;
    }
};

1;
