package LogReporter::ConfigLoader;
use strict;
use warnings;

use Exporter 'import';
our @EXPORT = qw/LoadConfig/;

sub LoadConfig {
    my ($filename) = @_;
    my ($config, $EX);
    {
        local $@;
        $config = do $filename;
        $EX = $@;
    }
    die $EX if $EX;
    return $config;
}


1;
