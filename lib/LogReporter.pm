package LogReporter;
use MooseX::Singleton;
use feature ':5.10';

use LogReporter::Util;
use LogReporter::Source;
use LogReporter::Source::File;
use LogReporter::Filter;
use LogReporter::Filter::Date;
use LogReporter::Filter::ISO8601;
use LogReporter::Filter::DateRange;
use LogReporter::Service;

use DateTime;
use DateTime::Span;
use Template;

use List::MoreUtils qw/apply natatime/;
use Data::Dumper; $Data::Dumper::Indent = 1;

has 'config' => (
    is => 'ro',
    isa => 'HashRef',
    required => 1,
);

has '_all_sources' => (
    is => 'ro',
    isa => 'HashRef[ LogReporter::Source ]',
    default => sub { {} },
);

has '_all_services' => (
    is => 'ro',
    isa => 'ArrayRef[ LogReporter::Service ]',
    default => sub { []; },
);

sub run {
    my ($self) = @_;
    
    my $source_config = delete $self->config->{sources};
    my $service_config = delete $self->config->{services};
    
    $self->_setup_sources($source_config);
    $self->_setup_services($service_config);
    
    print STDERR "Initializing sources\n";
    apply { $_->init() } values %{$self->_all_sources};
    print STDERR "Initializing services\n";
    apply { $_->init() } @{$self->_all_services};
    
    print STDERR "Running sources\n";
    apply { $_->run() } values %{$self->_all_sources};
    
    print STDERR "Finalizing sources\n";
    apply { $_->finalize() } values %{$self->_all_sources};
    print STDERR "Finalizing services\n";
    apply { $_->finalize() } @{$self->_all_services};
    
    $self->_collect_output();
}

sub _setup_sources {
    my ($self, $source_config) = @_;
    
    foreach my $src_name (keys %$source_config){
        my $src_config = $source_config->{$src_name};
        my $files = $src_config->{files};
        my $filters = [];
        
        my $it = natatime 2, @{$src_config->{filters} || []};
        while( my ($name, $conf) = $it->() ){
            $self->_load_filter($name);
            push @$filters, "LogReporter::Filter::$name"->new(
                %$conf,
            );
        }
        
        my $src_obj = LogReporter::Source::File->new(
            name => $src_name,
            files => $files,
            filters => $filters,
        );
        
        $self->_all_sources->{$src_name} = $src_obj;
    }
}

sub _load_filter {
    my ($self, $filter_name) = @_;
    eval "use LogReporter::Filter::$filter_name ()";
    die $@ if $@;
}

sub _setup_services {
    my ($self, $service_config) = @_;

    my $it = natatime 2, @{ $service_config };
    while ( my ($svc_name,$svc_config) = $it->() ){
        next if $svc_config->{disabled};
        
        my $filters = [];
        my $it = natatime 2, @{ delete $svc_config->{filters} || []};
        
        while( my ($name, $conf) = $it->() ){
            $self->_load_filter($name);
            push @$filters, "LogReporter::Filter::$name"->new(
                %$conf,
            );
        }
        
        my $sources = delete $svc_config->{sources};
        my $src_objs = [ map { $self->_all_sources->{$_} } @$sources ];

        $self->_load_service($svc_name);
        my $svc_obj = "LogReporter::Service::$svc_name"->new(
            name => $svc_name,
            sources => $src_objs,
            filters => $filters,
            %$svc_config,
        );
        
        push @{ $self->_all_services }, $svc_obj;
    }
}

sub _load_service {
    my ($self, $service_name) = @_;
    eval "use LogReporter::Service::$service_name ()";
    die $@ if $@;
}

sub _collect_output {
    my ($self) = @_;
    
    my $tt2 = Template->new(
        INCLUDE_PATH => [
            "$FindBin::Bin/../conf/tmpl/",
        ],
        START_TAG => '{{',
        END_TAG => '}}',
        POST_CHOMP => 1,
    );
    
    print STDERR "Collecting output\n";
    my $all_output;
    open my $OUTFH, '>', \$all_output or die "open(\\\$all_output): $!";
    
    $tt2->process('MAIN_HEADER',{ conf => $self->config, START_TIME => $^T },$OUTFH)
      or warn "MAIN_HEADER process: ".$tt2->error();
    foreach my $service (@{$self->_all_services}){
        $tt2->process('HEADER',{ svc => $service->name },$OUTFH)
          or warn "HEADER process: ".$tt2->error();
          
        my $old_stdout = select($OUTFH);
        $service->get_output();
        select($old_stdout);
        
        $tt2->process('FOOTER',{ svc => $service->name },$OUTFH)
          or warn "FOOTER process: " . $tt2->error();
    }
    $tt2->process('MAIN_FOOTER',{ conf => $self->config },$OUTFH)
      or warn "MAIN_FOOTER process: ". $tt2->error();
    
    #print STDERR "FINAL OUTPUT:\n$all_output";
    print $all_output; # This should be the *only* thing that prints to STDOUT!
}


__PACKAGE__->meta->make_immutable;
1;
