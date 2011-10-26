package LogReporter;
use MooseX::Singleton;
use namespace::autoclean;
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
    isa => 'HashRef[ LogReporter::Service ]',
    default => sub { {} },
);

sub run {
    my ($self) = @_;
    
    my $source_config = delete $self->config->{sources};
    my $service_config = delete $self->config->{services};
    
    $self->_setup_sources($source_config);
    $self->_setup_services($service_config);
    
    say "Initializing sources";
    apply { $_->init() } values %{$self->_all_sources};
    say "Initializing services";
    apply { $_->init() } values %{$self->_all_services};
    
    say "Running sources";
    apply { $_->run() } values %{$self->_all_sources};
    
    say "Finalizing sources";
    apply { $_->finalize() } values %{$self->_all_sources};
    say "Finalizing services";
    apply { $_->finalize() } values %{$self->_all_services};
    
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
        
#        say Dumper($files,$filters);
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
    
    foreach my $svc_name (keys %$service_config){
        my $svc_config = $service_config->{$svc_name};
        my $sources = delete $svc_config->{sources};
        
        my $src_objs = [ map { $self->_all_sources->{$_} } @$sources ];
        
        my $filters = [];
        my $it = natatime 2, @{ delete $svc_config->{filters} || []};
        while( my ($name, $conf) = $it->() ){
            $self->_load_filter($name);
            push @$filters, "LogReporter::Filter::$name"->new(
                %$conf,
            );
        }
        
        $self->_load_service($svc_name);
        my $svc_obj = "LogReporter::Service::$svc_name"->new(
            name => $svc_name,
            sources => $src_objs,
            filters => $filters,
            %$svc_config,
        );
        
        $self->_all_services->{$svc_name} = $svc_obj;
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
    
    say "Collecting output";
    my $all_output;
    $tt2->process('MAIN_HEADER',{ conf => $self->config, START_TIME => $^T },\$all_output)
      or warn "MAIN_HEADER process: ".$tt2->error();
    foreach my $service (values %{$self->_all_services}){
        $tt2->process('HEADER',{ svc => $service->name },\$all_output)
          or warn "HEADER process: ".$tt2->error();
        $all_output .= $service->get_output();
        $tt2->process('FOOTER',{ svc => $service->name },\$all_output)
          or warn "FOOTER process: " . $tt2->error();
    }
    $tt2->process('MAIN_FOOTER',{ conf => $self->config },\$all_output)
      or warn "MAIN_FOOTER process: ". $tt2->error();
    print "FINAL OUTPUT:\n$all_output";
}


1;
