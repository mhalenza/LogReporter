package LogReporter::Source::File;
use Moose;
use feature ':5.10';
use File::Glob qw/bsd_glob/;

extends 'LogReporter::Source';

has 'files' => (
    is => 'ro',
    isa => 'ArrayRef[Str]',
    required => 1,
);

has '_fh' => (
    traits  => ['Hash'],
    is => 'rw',
    isa => 'HashRef[ FileHandle ]',
    required => 1,
    default => sub { {}; },
    clearer => '_fh_clear',
    handles => {
        _fh_set => 'set',
        _fh_get => 'get',
        _fh_del => 'delete',
        _fh_pairs => 'kv',
    },
);

has '_active_fh' => (
    is => 'rw',
    isa => 'FileHandle',
);

override init => sub {
    my ($self) = @_;
    super();
    my @files = ();
    foreach my $file ( @{ $self->files } ){
        if ($file =~ /\*/){
            push @files, bsd_glob($file);
        } else {
            push @files, $file;
        }
    }
    foreach my $file ( @files ){
        if ( open(my $FH, "<", $file) ){
            print STDERR "  Opened $file\n";
            $self->_fh_set($file, $FH);
        } else {
            print STDERR "  Failed to open $file:  $!\n";
        }
        
    }
};

override run => sub {
    my ($self) = @_;

    unless ($self->_services_count){
        print STDERR "Skipping source " . $self->name() . " because no interested services\n";
        return;
    }

    foreach my $kv ($self->_fh_pairs) {
        print STDERR "FS: " . $kv->[0] . "\n";
        $self->_active_fh($kv->[1]);
        super();
    }
};

override get_line => sub {
    my ($self) = @_;
    my $fh = $self->_active_fh;
    my $line;

    $line = <$fh>;
    if (defined $line){
        chomp $line;
        return $line;
    }
    return undef;
};

override finalize => sub {
    my ($self) = @_;
    super();
    foreach my $FH ( $self->_fh_pairs ){
        close $FH->[1];
    }
    $self->_fh_clear();
};


__PACKAGE__->meta->make_immutable;
1;
