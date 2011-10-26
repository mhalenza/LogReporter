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

#my $ConfigDir = "/usr/local/logreporter/conf/";
my $ConfigDir = "$FindBin::Bin/../conf/";
my $PerlVersion = "$^X";

### Load config
my $all_config = read_config($ConfigDir . 'logreporter.conf');
#say Dumper($all_config);

LogReporter->new(
    config => $all_config,
)->run();

sub read_config {
    my ($name) = @_;
    say "Loading config from '$name'";
    our $config;
    do $name;
    die $@ if $@;
    return $config;
}

