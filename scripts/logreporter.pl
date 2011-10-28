#!/usr/bin/env perl
use strict;
use warnings;
use feature ':5.10';

use Carp;
use Config::General;
use Data::Dumper; #$Data::Dumper::Indent = 2;
$|++;

use FindBin;
use lib "$FindBin::Bin/../lib";

use LogReporter;

my $config = $ARGV[0] || "$FindBin::Bin/../conf/logreporter.conf";

print STDERR "Starting logreporter run at ".localtime()."\n";

### Load config
my $all_config = read_config($config);
#say Dumper($all_config);

LogReporter->new(
    config => $all_config,
)->run();

sub read_config {
    my ($name) = @_;
    print STDERR "Loading config from '$name'\n";
    our $config;
    do $name;
    die $@ if $@;
    return $config;
}

