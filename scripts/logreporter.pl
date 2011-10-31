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
use LogReporter::ConfigLoader;

my $config_file = $ARGV[0] || "$FindBin::Bin/../conf/logreporter.perl";

print STDERR "Starting logreporter run at ".localtime()."\n";

### Load config
print STDERR "Loading config from '$config_file'\n";
my $config = LoadConfig($config_file);
#say Dumper($config);

LogReporter->new(
    config => $config,
)->run();

exit 0;
