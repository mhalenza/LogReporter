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
    clearer => '_fh_clear',
    handles => {
        _fh_push => 'push',
        _fh_shift => 'shift',
    },
);
has '_active_fh' => (
    is => 'rw',
    isa => 'FileHandle',
);

override init => sub {
    my ($self) = @_;
    super();
    foreach my $file ( @{ $self->files } ){
        open my $FH, "<", $file or die "open($file): $!";
        $self->_fh_push($FH);
    }
};

override get_line => sub {
    my ($self) = @_;
    my $fhs = $self->_fh;
    my $line;

    foreach my $fh (@$fhs){
        $line = <$fh>;
        chomp $line;
        return $line if defined $line;
    }
    return undef;
};

override finalize => sub {
    my ($self) = @_;
    super();
    foreach my $FH ( @{ $self->_fh } ){
        close $FH;
    }
    $self->_fh_clear();
};

1;
