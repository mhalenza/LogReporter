package LogReporter::Service::Postfix::Functions;
use strict;
use warnings;

use Exporter 'import';
our @EXPORT = (qw/formathost/);

# Formats IP and hostname for even column spacing
sub formathost {
   my ($hostip, $hostname) = @_;
   return undef  if ($hostip =~ /^$/ and $hostname =~ /^$/);
   return sprintf "%-15s  %s", $hostip, lc $hostname;
}



1;
