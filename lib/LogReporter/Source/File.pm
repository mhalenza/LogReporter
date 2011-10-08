package LogReporter::Source::File;
use Moose;
extends 'LogReporter::Source';
use namespace::autoclean;

has 'files' => (
    is => 'ro',
    isa => 'ArrayRef[Str]',
    required => 1,
);

has '_fh' => (
    traits  => ['Array'],
    is => 'rw',
    isa => 'ArrayRef[FileHandle]',
    required => 1,
    default => sub { [] },
    handles => {
        _fh_push => 'push',
    },
);

override init => sub {
    my ($self) = @_;
    #super();
    foreach my $file ( @{ $self->files } ){
        open my $FH, "<", $file or die "open($file): $!";
        $self->_fh_push($FH);
    }
    
};

override get_line => sub {
    my ($self) = @_;
    #super();
    return undef;
};

override finalize => sub {
    my ($self) = @_;
    #super();
};

1;
