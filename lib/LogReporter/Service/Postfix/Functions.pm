package LogReporter::Service::Postfix;
use strict;
use warnings;

# Formats IP and hostname for even column spacing
sub formathost {
   my ($hostip, $hostname) = @_;
   return undef  if ($hostip =~ /^$/ and $hostname =~ /^$/);
   return sprintf "%-$Opts{'ipaddr_width'}s  %s", $hostip, lc $hostname;
}



1;
