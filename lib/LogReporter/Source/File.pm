package LogReporter::Source::File;
use Moose;
use namespace::autoclean;

extends 'LogReporter::Source';

has 'files' => (
    is => 'ro',
    isa => 'ArrayRef[Str]',
    required => 1,
);

has '_fh' => (
    traits  => ['Array'],
    is => 'rw',
    isa => 'ArrayRef[ FileHandle ]',
    required => 1,
    default => sub { [] },
    clearer => '_fh_clear',
    handles => {
        _fh_push => 'push',
    },
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
        if (defined $line){
            chomp $line;
            return $line;
        }
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
