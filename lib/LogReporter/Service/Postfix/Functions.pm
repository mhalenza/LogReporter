package LogReporter::Service::Postfix::Functions;
use strict;
use warnings;
use LogReporter::Service::Postfix::Constants;

use Exporter 'import';
our @EXPORT = (qw/formathost cleanhostreply get_dsn_msg/);

# Formats IP and hostname for even column spacing
sub formathost {
   my ($hostip, $hostname) = @_;
   return undef  if ($hostip =~ /^$/ and $hostname =~ /^$/);
   return sprintf "%-15s  %s", $hostip, lc $hostname;
}


# Clean up a server's reply, to give some uniformity to reports
# XXX postfix reports dsn=5.0.0, host's reply may contain its own dsn's such as 511 and #5.1.1
# XXX should these be used instead?
#
sub cleanhostreply($ $ $ $) {
    my ($hostreply,$relay,$recip,$domain) = @_;
    
    my $fmtdhost = "";
    my ($r1, $r2, $host, $event);
    
    #print "RELAY: $relay, RECIP: $recip, DOMAIN: $domain\n";
    #print "HOSTREPLY: \"$hostreply\"\n";
    if (($host,$r1) = ($hostreply =~ /host (\S+) said: $re_DSN[\- ]"?(.*)"?$/o)) {
        # Strip recipient address from host's reply - we already have it in $recip.
        $r1 =~ s/[<(]?$recip[>)]?\W*//ig;
        
        # Strip and capture "in reply to XYZ command" from host's reply
        if ($r1 =~ s/\s*[(]?(in reply to .* command)[)]?//) {
            $r2 = ": $1";
        }
    }
    elsif ($hostreply =~ /^connect to (\S+): (.*)$/) {
        $host = $1; $r1 = $2;
    }
    elsif ($hostreply =~ /^(delivery temporarily suspended): connect to (\S+): (.*)$/) {
        $host = $2; $r1 = "$1: $3";
    }
    elsif (($event,$host,$r1) = ($hostreply =~ /(lost connection|conversation) with (\S+) (.*)$/)) {
        $r1 = "$event $r1";
    }
    elsif ($hostreply =~ /^(.*: \S+maildrop: Unable to create a dot-lock) at .*$/) {
        $r1 = "$1";
    }
    else {
        $r1 = $hostreply;
    }
    
    #print "R1: $r1, R2: $r2\n";
    if ($host =~ /^$/) {
        if ($relay =~ /([^[]+)\[($re_IP)\]/o) {
            $fmtdhost = formathost($2,$1);
        }
    }
    elsif ($host =~ /^([^[]+)\[($re_IP)\]/o) {
        $fmtdhost = formathost($2,$1);
    }
    else {
        $fmtdhost = $host;
    }
    
    # Coerce some uniformity upon the numerous forms of unknown recipients
    if (   $r1 =~ s/^user unknown(; rejecting)?$//i
    or $r1 =~ s/^invalid recipient[ :]//i
    or $r1 =~ s/^unknown user( account)?$//i
    or $r1 =~ s/^recipient unknown$//i
    or $r1 =~ s/^recipient address rejected: (?:undeliverable address: )?(?:no such user|user unknown)?(?: in .* table)?\s*//i
    or $r1 =~ s/^sorry, no mailbox here by that name[.\s]+//i
    or $r1 =~ s/^unknown recipient address(?:[.]| in .* recipient table)?\s*//i
    or $r1 =~ s/^user unknown in .* recipient table\s*//i ){
        $r1 = "Unknown recipient address" . ($r1 !~ /^$/ ? $r1 : "");
    }
    $r1 =~ s/for name=$domain //ig;
    
    return ("\u$r1$r2", $fmtdhost);
}


# Returns an RFC 3463 DSN messages given a DSN code
#
sub get_dsn_msg {
    my $dsn = shift;
    my ($msg, $class, $subject, $detail);
    
    return "DSN unavailable"  if ($dsn =~ /^$/);
    
    unless ($dsn =~ /^(\d)\.((\d{1,3})\.\d{1,3})$/) {
        print "Error: not a DSN code $dsn\n";
        return "Invalid DSN";
    }
    
    $class = $1; $subject = $3; $detail = $2;
    #print "Class: $class, Subject: $subject, Detail: $detail\n";
    
    if (exists $dsn_codes{class}{$class}) {
        $msg = $dsn_codes{class}{$class};
    }
    if (exists $dsn_codes{subject}{$subject}) {
        $msg .= ': ' . $dsn_codes{subject}{$subject};
    }
    if (exists $dsn_codes{detail}{$detail}) {
        $msg .= ': ' . $dsn_codes{detail}{$detail};
    }
    
    #print "get_dsn_msg: $msg\n" if ($msg);
    return $dsn . ': ' . $msg;
}

1;
