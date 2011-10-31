package LogReporter::Filter::Meta;
use Moose;
extends 'LogReporter::Filter';

has 'key' => (
    is => 'ro',
    isa => 'Str',
    required => 1,
);

has 'value' => (
    is => 'ro',
    isa => 'RegexpRef|Str',
    required => 1,
);

sub filter {
    my ($self, $line, $meta) = @_;
    my $k = $self->key;
    my $v = $self->value;
    if ( exists $meta->{$k} ){
        if ( $meta->{$k} =~ $v ){
            return 1;
        }
    }
    return 0;
}

1;
