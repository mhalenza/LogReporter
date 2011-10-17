package LogReporter::Service::LogwatchScripted;
use Moose;
use namespace::autoclean;
extends 'LogReporter::Service';
use IPC::Run qw/harness/;

=pod
This is supposed to be a wrapper around the original Logwatch service scripts.
It doesn't work because the earlier filters modify the line
 as well as the fact that I don't do the same preprocessing as Logwatch.

This is included for shiggles.
=cut

has 'ipc' => (
    is => 'rw',
    isa => 'IPC::Run',
);

has 'IN' => (
    is => 'rw',
    isa => 'Ref[Str]',
    required => 1,
    default => sub { \""; }
);
has 'OUT' => (
    is => 'rw',
    isa => 'Ref[Str]',
    required => 1,
    default => sub { \""; }
);

override init => sub {
    my ($self) = @_;
    super();
    
    $self->ipc( harness(\@cmd, $self->IN(), $self->OUT()) );
};

override process_line => sub {
    my ($self, $line, $meta) = @_;
    ${ $self->IN() } .= $line;
    $self->ipc->pump_nb() while length ${$self->IN};
};

override finalize => sub {
    my ($self) = @_;
    super();
    $self->ipc->pump_nb() while length ${$self->IN};
};

1;
