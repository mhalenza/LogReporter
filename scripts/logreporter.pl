#!/usr/bin/env perl
use strict;
use warnings;
use feature ':5.10';

use Carp;
use Config::General;
use Data::Dumper; #$Data::Dumper::Indent = 2;
use List::MoreUtils qw/apply natatime/;

use FindBin;
use lib "$FindBin::Bin/../lib";
use LogReporter::Filter;
use LogReporter::Filter::Date;
use LogReporter::Filter::DateRange;
use LogReporter::Filter::Syslog;
use LogReporter::Source;
use LogReporter::Source::File;
use LogReporter::Service;


my $BaseDir = "/usr/share/logreporter";
my $ConfigDir = "/etc/logreporter";
my $PerlVersion = "$^X";

### Load config
my $all_config = read_config('conf/logreporter.conf');
my $source_config = delete $all_config->{sources};
my $service_config = delete $all_config->{services};
print Dumper($all_config,$source_config,$service_config);

## Process config
my ($all_sources, $all_services) = ({},{});

foreach my $src_name (keys %$source_config){
    my $src_config = $source_config->{$src_name};
    my $files = $src_config->{files};
    my $filters = [];
    
    my $it = natatime 2, @{$src_config->{filters}};
    while( my ($name, $conf) = $it->() ){
        push @$filters, "LogReporter::Filter::$name"->new(
            %$conf
        );
    }
    
    my $src_obj = LogReporter::Source::File->new(
        name => $src_name,
        files => $files,
        filters => $filters,
    );
    
    $all_sources->{$src_name} = $src_obj;
}

foreach my $svc_name (keys %$service_config){
    my $svc_config = $service_config->{$svc_name};
    my $sources = $svc_config->{sources};
    my $filters = $svc_config->{filters};
    
    my $src_objs = [ map { $all_sources->{$_} } @$sources ];
    
    my $svc_obj = LogReporter::Service->new(
        name => $svc_name,
        filters => $filters,
        sources => $src_objs,
    );
}

say "Initializing sources";
apply { $_->init() } values %$all_sources;
say "Initializing services";
apply { $_->init() } values %$all_services;

say "Running sources";
apply { $_->run() } values %$all_sources;

say "Finalizing sources";
apply { $_->finalize() } values %$all_sources;
say "Finalizing services";
apply { $_->finalize() } values %$all_services;

say "Collecting output";
my $all_output = "";
foreach my $service (values %$all_services){
    $all_output .= $service->get_output();
}

print "FINAL OUTPUT:\n--------------------------------------------\n";
print $all_output;
print "--------------------------------------------\n";
exit;


sub read_config {
    my ($name) = @_;
    our $config;
    do $name;
    return $config;
}
