package LogReporter::Service::Postfix;
use Moose;
use namespace::autoclean;
extends 'LogReporter::Service';
no warnings 'misc';
use LogReporter::Service::Postfix::Constants;
use LogReporter::Service::Postfix::Functions;

override init => sub {
    my ($self) = @_;
    super();
    my $data = $self->data;
    $data->{UNMATCHED} = {};
    $data->{Totals} = {};
    $data->{Counts} = {};
};

override process_line => sub {
    my ($self, $line, $meta) = @_;
    my $data = $self->data;
    my $subprog = $meta->{sp};
    
    # We don't care about these, but see also less frequent log entries at the end
    next if (
           ( $line =~ /^Deleted: \d message$/ )
        or ( $line =~ /: replace: header / )
        or ( $line =~ /: Greylisted for / ) # Greylisting has it's own statistics tool
        #XXX Perhaps the following are candidates for extended statistics
        or ( $line =~ /certificate verification failed for/o )     
        or ( $line =~ /Server certificate could not be verified/o )
        or ( $line =~ /certificate peer name verification failed/o )
        # SSL rubbish when logging at/above INFO level
        or ( $line =~ /^[a-f\d]{4} [a-f\d]{2}/ )
        or ( $line =~ /^[a-f\d]{4} - <SPACES/ )
        # more from mail.info level and above
        or ( $line =~ m/^read from [a-f\d]{8}/ )
        or ( $line =~ m/^write to [a-f\d]{8}/ )
    );
    
    # fatal errors
    if ( $line =~ /^fatal: (.*)$/ ){
        my ($reason) = $1;
        if ( $reason =~ /^[^ ]*\(\d+\): Message file too big$/ ){
            #TD fatal: root(0): Message file too big
            $data->{Totals}->{'FatalFileTooBig'}++;
            # XXX its not clear this is at all useful - consider falling through to last case
        } elsif ( $reason =~ /^config variable ([^ ]*): (.*)$/ ){
            #TD fatal: config variable inet_interfaces: host not found: 10.0.0.1:2525
            #TD fatal: config variable inet_interfaces: host not found: all:2525
            $data->{Totals}->{'FatalConfigError'}++;
            $data->{Counts}->{'FatalConfigError'}{$reason}++;
        } else {
            #TD fatal: watchdog timeout
            #TD fatal: bad boolean configuration: smtpd_use_tls =
            $data->{Totals}->{'FatalError'}++;
            $data->{Counts}->{'FatalError'}{"\u$reason"}++;
        }
    }
    
    ### postfix-script
    elsif ( $subprog eq 'postfix-script' ){
        if ( $line =~ /^starting the Postfix mail system/ ){
            $data->{Totals}->{'PostfixStart'}++;
        } elsif ( $line =~ /^stopping the Postfix mail system/ ){
            $data->{Totals}->{'PostfixStop'}++;
        } elsif ( $line =~ /^refreshing the Postfix mail system/ ){
            $data->{Totals}->{'PostfixRefresh'}++;
        } elsif ( $line =~ /^waiting for the Postfix mail system to terminate/ ){
            $data->{Totals}->{'PostfixWaiting'}++;
        } else {
            $data->{UNMATCHED}->{'postfix-script'}->{$line}++
        }
    }
    
    # common log entries up front
    elsif ( $line =~ /^connect from/ ){
        #TD25 connect from sample.net[10.0.0.1]
        #TD connect from mail.example.com[2001:dead:beef::1]
        #TD connect from localhost.localdomain[127.0.0.1]
        $data->{Totals}->{'ConnectionInbound'}++;
    }
    elsif ( $line =~ /^disconnect from/ ){
        #TD25 disconnect from sample.net[10.0.0.1]
        #TD disconnect from mail.example.com[2001:dead:beef::1]
        $data->{Totals}->{'Disconnection'}++;
    }
    elsif ( my ($host,$hostip,$reason) = ($line =~ /^connect to ([^[]*)\[($re_IP)\]: (.*)$/o) ){
        # all "connect to" messages indicate a problem with the connection
        #TD connect to example.org[10.0.0.1]: Connection refused (port 25)
        #TD connect to mail.sample.com[10.0.0.1]: No route to host (port 25)
        #TD connect to sample.net[192.168.0.1]: read timeout (port 25)
        #TD connect to mail.example.com[10.0.0.1]: server dropped connection without sending the initial SMTP greeting (port 25)
        #TD connect to mail.example.com[192.168.0.1]: server dropped connection without sending the initial SMTP greeting (port 25)
        #TD connect to ipv6-1.example.com[2001:dead:beef::1]: Connection refused (port 25)
        #TD connect to ipv6-2.example.com[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]: Connection refused (port 25)
        #TD connect to ipv6-3.example.com[1080:0:0:0:8:800:200C:4171]: Connection refused (port 25)
        #TD connect to ipv6-4.example.com[3ffe:2a00:100:7031::1]: Connection refused (port 25)
        #TD connect to ipv6-5.example.com[1080::8:800:200C:417A]: Connection refused (port 25)
        #TD connect to ipv6-6.example.com[::192.9.5.5]: Connection refused (port 25)
        #TD connect to ipv6-7.example.com[::FFFF:129.144.52.38]: Connection refused (port 25)
        #TD connect to ipv6-8.example.com[2010:836B:4179::836B:4179]: Connection refused (port 25)
        $data->{Totals}->{'ConnectToFailure'}++;
        $data->{Counts}->{'ConnectToFailure'}{$reason}{formathost($hostip,$host)}++;
    }
    elsif ( my ($reason) = ($line =~ /^panic: (.*)$/) ){
        #TD panic: myfree: corrupt or unallocated memory block
        $data->{Totals}->{'PanicError'}++;
        $data->{Counts}->{'PanicError'}{"\u$reason"}++;
    }
    
    # ^warning: ...
    elsif ( my ($warning) = ($line =~ /^warning: (.*)$/ ) ){
        $self->handle_warning($line, $warning);
    }
};


sub handle_warning {
    my ($self, $line, $warning) = @_;
    my $data = $self->data;
    
    # Skip these
    next if ( $warning =~ /$re_QID: skipping further client input$/o  );
    next if ( $warning =~ /^Mail system is down -- accessing queue directly$/ );
    next if ( $warning =~ /^SASL authentication failure: (?:Password verification failed|no secret in database)$/ );
    next if ( $warning =~ /^no MX host for .* has a valid A record$/ );
    next if ( $warning =~ /^uid=\d: Broken pipe$/ );

    #TD warning: connect to 127.0.0.1:12525: Connection refused
    #TD warning: problem talking to server 127.0.0.1:12525: Connection refused
    #TD warning: valid_ipv4_hostaddr: invalid octet count:

    my ($addr, $size);

    if (
    ($warning =~ /^(?:smtpd_peer_init: )?(?<hostip>$re_IP): hostname (?<host>[^ ]+) verification failed: (?<reason>.*)$/o ) or
    ($warning =~ /^(?:smtpd_peer_init: )?(?<hostip>$re_IP): (?<reason>address not listed for hostname) (?<host>.*)$/o ) ){
        my ($hostip,$host,$reason) = @+{'hostip','host','reason'};
        #TD warning: 10.0.0.1: hostname sample.com verification failed: Host not found 
        #TD warning: smtpd_peer_init: 192.168.0.1: hostname example.com verification failed: Name or service not known 
        #TD warning: 192.168.0.1: address not listed for hostname sample.net
        $data->{Totals}->{'HostnameVerification'}++;
        $data->{Counts}->{'HostnameVerification'}{"\u$reason"}{formathost($hostip,$host)}++;
    }
    
    elsif (
    ($warning =~ /^$re_QID: queue file size limit exceeded$/o ) or
    ($warning =~ /^uid=\d+: File too large$/) ){
        $data->{Totals}->{'WarnFileTooBig'}++;
    }
    
    elsif ( my ($source) = ($warning =~ /^database (?:[^ ]*) is older than source file ([\w\/]+)$/) ){
        #TD warning: database /etc/postfix/client_checks.db is older than source file /etc/postfix/client_checks 
        $data->{Totals}->{'DatabaseGeneration'}++;
        $data->{Counts}->{'DatabaseGeneration'}{$source}++;
    }
    
    elsif (
    ($warning =~ /^(?<r>open active) (?<qid>$re_QID): (?<r2>.*)$/o ) or
    ($warning =~ /^qmgr_active_corrupt: (?<r>save corrupt file queue active) id (?<qid>$re_QID): (?<r2>.*)$/o ) or
    ($warning =~ /^(?<qid>$re_QID): (?<r>write queue file): (?<r2>.*)$/o ) ){
        my ($qid,$reason,$reason2) = @+{'qid','r','r2'};
        #TD warning: open active BDB9B1309F7: No such file or directory
        #TD warning: qmgr_active_corrupt: save corrupt file queue active id 4F4272F342: No such file or directory
        #TD warning: E669DE52: write queue file: No such file or directory
        $data->{Totals}->{'QueueWriteError'}++;
        $data->{Counts}->{'QueueWriteError'}{"$reason: $reason2"}{$qid}++;
    }
    
    elsif ( my ($qid,$reason) = ($warning =~ /^qmgr_active_done_3_generic: remove ($re_QID) from active: (.*)$/o ) ){
        #TD warning: qmgr_active_done_3_generic: remove AF0F223FC05 from active: No such file or directory 
        $data->{Totals}->{'QueueWriteError'}++;
        $data->{Counts}->{'QueueWriteError'}{"remove from active: $reason"}{$qid}++;
    }
    
    elsif ( my ($queue,$qid) = ($warning =~ /^([^\/]*)\/($re_QID): Error writing message file$/o ) ){
        #TD warning: maildrop/C9E66ADF: Error writing message file 
        $data->{Totals}->{'MessageWriteError'}++;
        $data->{Counts}->{'MessageWriteError'}{$queue}{$qid}++;
    }
    
    elsif ( my ($process,$status) = ($warning =~ /^process ([^ ]*) pid \d+ exit status (\d+)$/) ){
        #TD warning: process /usr/lib/postfix/smtp pid 9724 exit status 1
        $data->{Totals}->{'ProcessExit'}++;
        $data->{Counts}->{'ProcessExit'}{"$process: exit status $status"}++;
    }
    
    elsif ( my ($reason) = ($warning =~ /^mailer loop: (.*)$/) ){
        #TD warning: mailer loop: best MX host for example.com is local
        $data->{Totals}->{'MailerLoop'}++;
        $data->{Counts}->{'MailerLoop'}{$reason}++;
    }
    
    elsif ( my ($reason,$domain) = ($warning =~ /^(malformed domain name in resource data of MX record) for (.*):$/) ){
        #TD warning: malformed domain name in resource data of MX record for mail.example.com:
        $data->{Totals}->{'MxError'}++;
        $data->{Counts}->{'MxError'}{"\u$reason"}{$domain}{""}++;
    }
    
    elsif ( my ($reason,$host,$reason2) = ($warning =~ /^(Unable to look up MX host) for ([^:]*): (.*)$/) ){
        #TD warning: Unable to look up MX host for example.com: Host not found
        $reason2 = 'Host not found'  if ($reason2 =~ /^Host not found, try again/);
        $data->{Totals}->{'MxError'}++;
        $data->{Counts}->{'MxError'}{"\u$reason"}{"\u$reason2"}{$host}{""}++;
    }
    
    elsif ( my ($reason,$host,$to,$reason2) = ($warning =~ /^(Unable to look up MX host) (.*) for Sender address ([^:]*): (.*)$/) ){
        #TD warning: Unable to look up MX host mail.example.com for Sender address from@example.com: hostname nor servname provided, or not known
        $reason2 = 'Host not found'  if ($reason2 =~ /^Host not found, try again/);
        my ($name, $domain) = split ('@', "\L$to");
        $data->{Totals}->{'MxError'}++;
        $data->{Counts}->{'MxError'}{"\u$reason"}{"\u$reason2"}{$host}{$name}++;
    }
    
    elsif (
    ($warning =~ /^([^[]+)\[($re_IP)\] sent \w+ header instead of SMTP command: (.*)$/o )  or
    ($warning =~ /^non-SMTP command from ([^[]+)\[($re_IP)\]: (.*)$/o ) ){
        my ($host,$hostip,$type) = ($1,$2,$3);
        # ancient
        #TD warning: example.com[192.168.0.1] sent message header instead of SMTP command: From: "Someone" <40245426501example.com>
        # current
        #TD warning: non-SMTP command from sample.net[10.0.0.1]: Received: from 192.168.0.1 (HELO bogus.sample.com)
        $data->{Totals}->{'SmtpConversationError'}++;
        $data->{Counts}->{'SmtpConversationError'}{formathost($hostip,$host)}{$type}++;
    }
    
    elsif ( my ($msg) = ($warning =~ /^valid_hostname: (.*)$/) ){
        #TD warning: valid_hostname: empty hostname 
        $data->{Totals}->{'HostnameValidationError'}++;
        $data->{Counts}->{'HostnameValidationError'}{$msg}++;
    }
    
    elsif ( my ($host,$hostip,$type) = ($warning =~ /^([^[]+)\[($re_IP)\]: SASL (.*) authentication failed/o ) ){
        #TD warning: example.com[192.168.0.1]: SASL DIGEST-MD5 authentication failed 
        $data->{Totals}->{'SaslAuthFail'}++;
        $data->{Counts}->{'SaslAuthFail'}{formathost($hostip,$host)}++;
    }
    
    elsif ( my ($host,$site,$reason) = ($warning =~ /^([^:]*): RBL lookup error:.* Name service error for (?:name=)?$re_IP\.([^:]*): (.*)$/o ) ){
        #TD warning: 192.168.0.1.sbl.spamhaus.org: RBL lookup error: Host or domain name not found. Name service error for name=192.168.0.1.sbl.spamhaus.org type=A: Host not found, try again
        #TD warning: 10.0.0.1.relays.osirusoft.com: RBL lookup error: Name service error for 10.0.0.1.relays.osirusoft.com: Host not found, try again 
        $data->{Totals}->{'RBLError'}++;
        $data->{Counts}->{'RBLError'}{$site}{$reason}{$host}++;
    }
    
    elsif (
    ($warning =~ /^host ([^[]+)\[($re_IP)\] (greeted me with my own hostname) ([^ ]*)$/o ) or
    ($warning =~ /^host ([^[]+)\[($re_IP)\] (replied to HELO\/EHLO with my own hostname) ([^ ]*)$/o ) ){
        my ($host,$hostip,$reason,$helo) = ($1,$2,$3,$4);
        #TD warning: host example.com[192.168.0.1] greeted me with my own hostname example.com 
        #TD warning: host example.com[192.168.0.1] replied to HELO/EHLO with my own hostname example.com
        $data->{Totals}->{'HeloError'}++;
        $data->{Counts}->{'HeloError'}{"\u$reason"}{formathost($hostip,$host)}++;
    }
    
    elsif ( my($host,$hostip,$cmd,$addr) = ($warning =~ /^Illegal address syntax from ([^[]+)\[($re_IP)\] in ([^ ]*) command: (.*)/o ) ){
        #TD warning: Illegal address syntax from example.com[192.168.0.1] in MAIL command: user@sample.net
        $addr =~ s/[<>]//g;
        $data->{Totals}->{'IllegalAddrSyntax'}++;
        $data->{Counts}->{'IllegalAddrSyntax'}{$cmd}{$addr}{formathost($hostip,$host)}++;
    }
    
    elsif (
    ($warning =~ /^numeric (hostname): ($re_IP)$/o ) or
    ($warning =~ /^numeric domain name in (resource data of MX record) for (.*)$/ ) ){
        my ($reason, $host) = ($1,$2);
        #TD warning: numeric hostname: 192.168.0.1
        #TD warning: numeric domain name in resource data of MX record for sample.com: 192.168.0.1
        if (($host,$hostip) = ($host =~ /([^:]+): ($re_IP)/o)) {
            $host = formathost($hostip,$host);
        }
        $data->{Totals}->{'NumericHostname'}++;
        $data->{Counts}->{'NumericHostname'}{"\u$reason"}{$host}++;
    }
    
    elsif ( my ($service,$when) = ($warning =~ /^premature end-of-input on ([^ ]+) (.*)$/ ) ){
        #TD warning: premature end-of-input on private/anvil while reading input attribute name
        $data->{Totals}->{'PrematureEOI'}++;
        $data->{Counts}->{'PrematureEOI'}{$service}{$when}++;
    }
    
    elsif ( my ($service,$reason) = ($warning =~ /^(.*): (bad command startup -- throttling)/o ) ){
        #TD warning: /usr/libexec/postfix/trivial-rewrite: bad command startup -- throttling
        $data->{Totals}->{'StartupError'}++;
        $data->{Counts}->{'StartupError'}{"Service: $service"}{$reason}++;
    }
    
    elsif ( my ($service,$reason) = ($warning =~ /(problem talking to service [^:]*): (.*)$/o ) ){
        #TD warning: problem talking to service rewrite: Connection reset by peer
        #TD warning: problem talking to service rewrite: Success
        $data->{Totals}->{'CommunicationError'}++;
        $data->{Counts}->{'CommunicationError'}{"\u$service"}{$reason}++;
    }
    
    elsif ( my ($map,$key) = ($warning =~ /^$re_QID: ([^ ]*) map lookup problem for (.*)$/o ) ){
        #TD warning: 6F74F74431: virtual_alias_maps map lookup problem for root@example.com
        $data->{Totals}->{'MapProblem'}++;
        $data->{Counts}->{'MapProblem'}{"$map"}{$key}++;
    }
    
    elsif ( my ($map,$reason) = ($warning =~ /pcre map ([^,]+), (.*)$/ ) ){
        #TD warning: pcre map /etc/postfix/body_checks, line 92: unknown regexp option "F": skipping this rule
        $data->{Totals}->{'MapProblem'}++;
        $data->{Counts}->{'MapProblem'}{$map}{$reason}++;
    }
    
    elsif ( my ($reason) = ($warning =~ /dict_ldap_lookup: (.*)$/ ) ){
        #TD warning: dict_ldap_lookup: Search error 80: Internal (implementation specific) error
        $data->{Totals}->{'LdapError'}++;
        $data->{Counts}->{'LdapError'}{$reason}++;
    }
    
    elsif ( my ($size,$host,$hostip) = ($warning =~ /^bad size limit "([^"]+)" in EHLO reply from ([^[]+)\[($re_IP)\]$/o ) ){
        #TD warning: bad size limit "-679215104" in EHLO reply from example.com[192.168.0.1] 
        $data->{Totals}->{'HeloError'}++;
        $data->{Counts}->{'HeloError'}{"Bad size limit in EHLO reply"}{formathost($hostip,$host)}{"$size"}++;
    }
    
    elsif ( my ($size,$host,$hostip,$service) = ($warning =~ /^Connection concurrency limit exceeded: (\d+) from ([^[]+)\[($re_IP)\] for service (.*)/o ) ){
        #TD warning: Connection concurrency limit exceeded: 51 from example.com[192.168.0.1] for service smtp
        $data->{Totals}->{'ConcurrencyLimit'}++;
        $data->{Counts}->{'ConcurrencyLimit'}{$service}{formathost($hostip,$host)}{$size}++;
    }
    
    else {
        #TD warning: No server certs available. TLS won't be enabled
        #TD warning: smtp_connect_addr: bind <localip>: Address already in use 
        $data->{Totals}->{'WarningsOther'}++;
        $data->{Counts}->{'WarningsOther'}{$warning}++;
    }
}


1;
