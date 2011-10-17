package LogReporter::Templated;
use Moose::Role;
use namespace::autoclean;
use Template;

has 'tt2' => (
    is => 'rw',
    isa => 'Template',
    builder => '_build_tt2',
);

requires 'template_name';

sub _build_tt2 {
    my $tt2 = Template->new(
        INCLUDE_PATH => [
            "$FindBin::Bin/../conf/tmpl/",
        ],
        START_TAG => '{{',
        END_TAG => '}}',
        POST_CHOMP => 1,
        PREPROCESS => 'HEADER',
        POSTPROCESS => 'FOOTER',
    );
    
    return $tt2;
}

sub process {
    my ($self, $data) = @_;
    my $output;
    $self->tt2->process($self->template_name, $data, \$output) or die $self->tt2->error();
    return $output;
}

1;
