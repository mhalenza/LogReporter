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
    
    # ^$re_QID: ...
    elsif ( my ($qid, $p2) = ($line =~ /^($re_QID): (.*)$/o ) ){
        $self->handle_QID($line,$qid,$p2);
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

sub handle_QID {
    my ($self, $line, $qid, $p2) = @_;
    my $data = $self->data;
    
    return if ( $p2 =~ /^client=(?:[^ ]*\[[^ ]*\])\s*$/o );
    return if ( $p2 =~ /^skipped, still being delivered/o );
    return if ( $p2 =~ /^host [^ ]*\[[^ ]*\] said: 4[0-9][0-9]/o );
    return if ( $p2 =~ /^host [^ ]*\[[^ ]*\] refused to talk to me: 4[0-9][0-9]/o );
    # postsuper double reports the following 3 lines
    return if ( $p2 =~ /^released from hold$/o );
    return if ( $p2 =~ /^placed on hold$/o );
    return if ( $p2 =~ /^requeued$/o );
    
    #TD DA080C2E0B: client=example.com[192.168.0.1]
    #TD NOQUEUE: client=mail.example.com[2001:dead:beef::1]
    #TD F0EC9BBE2: client=mail.example.com[2001:dead:beef::1]
    #TD F0EC9BBE2: message-id=<C1BEA2A0.188572%from@example.com>
    
    return if ( $p2 =~ /^message-id=/ );
    # XXX probably don't care about message-id; for now, useful debug aid
    #if (($p3) = ($p2 =~ /^message-id=<(.*)>$/ )) {
    #   if (exists $Qids{$qid}) {
    #      print "Error: Duplicate QID: $qid, $p3\n";
    #   }
    #   $Qids{$qid}{'message-id'} = $p3;
    #}
    
    # $re_QID: reject: ...
    # $re_QID: reject_warning: ...
    if ( my ($rej_action,$p3) = ($p2 =~ /^(reject(?:_warning)?): (.*)$/ ) ){
        $self->handle_QID_reject($line, $rej_action, $p3);
    }

    # ^$re_QID: ...  (not rejects)
    elsif ( my ($bytes,$nrcpt) = ($p2 =~ /^from=<[^>]*>, size=(\d+), nrcpt=(\d+).*$/o ) ){
        #TD 4AEFAF569C11: from=<FROM: SOME USER@example.com>, size=4051, nrcpt=1 (queue active)
        #TD12 2A535C2E01: from=<anyone@example.com>, size=25302, nrcpt=2 (queue active)
        #TD F0EC9BBE2: from=<from@example.com>, size=5529, nrcpt=1 (queue active)
        # Distinguish bytes accepted vs. bytes delivered due to multiple recips
        #if (!exists $Qids{$qid}) {
        #   print "ERROR: no Qids{$qid} found\n";
        #}
        if (!exists $Qids{$qid} and !exists $Qids{$qid}{'nrcpt'}) {
            $Qids{$qid}{'nrcpt'} = $nrcpt;
            $Qids{$qid}{'size'} = $bytes;
            $Totals{'MsgsAccepted'}++;
            $Totals{'BytesAccepted'} += $bytes;
        }
        #else {
        #   Occurs for each deferral   
        #   print "DEBUG: RETRY($Qid) $p2\n";
        #}
    }
    
    ### sent, forwarded, bounced, softbounce, deferred, (un)deliverable
    elsif ( my ($to,$origto,$relay,$DDD,$status,$reason) = ($p2 =~ /^to=<([^>]*)>,(?: orig_to=\<([^>]*)>,)? relay=([^ ]*).*, ($re_DDD), status=([^ ]+) (.*)$/o  ) ){
        $self->process_sfbdu($line,$to,$origto,$relay,$DDD,$status,$reason);
    }
    
    # XXX don't care about this anymore; MsgsAccepted are counted with from= lines
    elsif ( $p2 =~ /^uid=(?:[^ ]*) from=<(?:[^>]*)>/o ){
        #TD2 1DFE2C2E18: uid=0 from=<root>
        #$Totals{'MsgsAccepted'}++;
    }
    
    elsif ( my ($from) = ($p2 =~ /^from=<([^>]*)>, status=expired, returned to sender$/o ) ){
        #TD 9294C8866: from=<from@example.com>, status=expired, returned to sender
        $from = "<>"  if ($from =~ /^$/);
        $Totals{'ReturnedToSender'}++;
        $Counts{'ReturnedToSender'}{$from}++;
    }
    
    elsif ( $p2 =~ /^resent-message-id=<?(?:[^>]*)>?$/o ){
        #TD 52A49200E1: resent-message-id=4739073.1
        #TD DB2E3C2E0E: resent-message-id=<ARF+DXZwLECdxm@mail.example.com>
        $Totals{'MsgsResent'}++;
    } 
    
    # see also ConnectionLost elsewhere
    elsif ( my ($host,$hostip,$reason) = ($p2 =~ /^lost connection with ([^[]*)\[($re_IP)\] (while .*)$/o ) ){
        #TD EB7D4341F0: lost connection with sample.net[10.0.0.1] while sending MAIL FROM
        #TD 5F6C7C2E0F: lost connection with sample.net[10.0.0.2] while receiving the initial server greeting
        $Totals{'ConnectionLost'}++;
        $Counts{'ConnectionLost'}{"\u$reason"}{formathost($hostip,$host)}++;
    }
    
    # see also TimeoutInbound elsewhere
    elsif ( my ($host,$hostip,$reason) = ($p2 =~ /^conversation with ([^[]*)\[($re_IP)\] timed out (while .*)$/o ) ){
        #TD C20574341F3: conversation with sample.net[10.0.0.1] timed out while receiving the initial SMTP greeting 
        $Totals{'TimeoutInbound'}++;
        $Counts{'TimeoutInbound'}{"\u$reason"}{formathost($hostip,$host)}++;
    }
    
    elsif ( $p2 =~ /^sender delay notification: $re_QID$/o ){
        #TD 8DB93C2FF2: sender delay notification: AA61EC2F9A 
        $Totals{'SenderDelayNotification'}++;
    }
    
    elsif ( my ($warning,$host,$hostip,$to,$reason) = ($p2 =~ /^warning: header (.*) from ([^[]+)\[($re_IP)\]; from=<(?:[^ ]*)> to=<([^ ]*)>(?: proto=[^ ]* helo=<[^ ]*>)?(?:: (.*))?$/o ) ){
        $reason = 'Unknown Reason'    if ($reason =~ /^$/);
        $Totals{'WarningHeader'}++;
        $Counts{'WarningHeader'}{$reason}{formathost($hostip,$host)}{$to}{$warning}++;
    }
    
    ### filter messages
    elsif ( ($host,$hostip,$trigger,$reason,$filter,$from,$to) = ($p2 =~ /^filter: RCPT from ([^[]+)\[($re_IP)\]: <([^>]*)>: (.*) triggers FILTER ([^;]+); from=<([^>]*)> to=<([^>]+)> proto=\S+ helo=<[^>]+>$/o )) {
        $from = "<>"		if ($from =~ /^$/);
        #TD NOQUEUE: filter: RCPT from example.com[10.0.0.1]: <>: Sender address triggers FILTER filter:somefilter; from=<> to=<to@sample.net> proto=SMTP helo=<example.com>
        #TD NOQUEUE: filter: RCPT from example.com[192.168.0.1]: <to@exmple.com>: Recipient address triggers FILTER smtp-amavis:[127.0.0.1]:10024; from=<from@sample.net> to=<to@example.com> proto=SMTP helo=<sample.net>
        $Totals{'Filtered'}++;
        $Counts{'Filtered'}{$reason}{$filter}{formathost($hostip,$host)}{$trigger}{$to}{$from}++;
    }
    
    ### Hold messages
    elsif ( my ($reason,$host,$hostip,$to) = ($p2 =~ /^hold: (?:header|body) (.*) from ([^[]+)\[($re_IP)\]; from=<(?:[^ ]*)> to=<([^ ]*)>(?: proto=[^ ]* helo=<[^ ]*>)?(?:: (.*))?$/o ) ){
        #TD E9E0CC2E22: hold: header Message-ID: <user@example.com> from localhost[127.0.0.1]; from=<test@sample.net> to=<user@example.com> proto=ESMTP helo=<sample.net>: Log message here
        #TD 76561D30BF: hold: header Received: from sample.net (sample.net[192.168.0.1])??by example.com (Postfix) with ESMTP id 676530BF??for <X>; Thu, 20 Oct 2006 13:27: from sample.net[192.168.0.2]; from=<user@sample.net> to=<touser@example.com> proto=ESMTP helo=<sample.net>
        $reason = 'Unknown Reason'    if ($reason =~ /^$/);
        $Totals{'Hold'}++;
        $Counts{'Hold'}{$reason}{formathost($hostip,$host)}{$to}++;
    }
    
    elsif ( my ($reason,$host,$to) = ($p2 =~ /^hold: (?:header|body) (.*) from (local); from=<(?:[^ ]*)>(?: to=<([^ ]*)>)?/o ) ){
        #TD 64215C2E55: hold: header Subject: Hold Test from local; from=<test@sample.net> to=<user@example.com>: testing hold messages
        #TD BAFC080410: hold: header Received: by example.com (Postfix, from userid 0 BAFC080410; Tue, 10 Apr 2007 03:11:21 +0200 (CEST) from local; from=<user@example.com>
        $reason = 'Unknown Reason'    if ($reason =~ /^$/);
        $to = 'Unknown'               if ($to =~ /^$/);
        $Totals{'Hold'}++;
        $Counts{'Hold'}{$reason}{$host}{$to}++;
    }
    
    elsif ( $p2 =~ /^removed\s*$/o ){
        # 52CBDC2E0F: removed
        if (exists $Qids{$qid}) {
            delete $Qids{$qid};
        }
        #else {
        #   happens when log lines are outside of logwatch's range
        #   or a log rotation occurred.
        #   print "Debug: Qids{$qid} nonexistent\n";
        #}
        $Totals{'RemovedFromQueue'}++;
    }
    
    elsif (
    ($p2 =~ /^enabling PIX (<CRLF>\.<CRLF>) workaround for ([^[]+)\[($re_IP)\]/o ) or
    ($p2 =~ /^enabling PIX workarounds: (.*) for ([^[]+)\[($re_IP)\]/o ) ){
        my ($type, $host, $hostip) =  ($1,$2,$3);
        #TD 6DE182FC0B: enabling PIX <CRLF>.<CRLF> workaround for example.com[192.168.0.1]
        #TD 272D0C2E55: enabling PIX <CRLF>.<CRLF> workaround for mail.sample.net[10.0.0.1]:25
        #TD 83343C2E16: enabling PIX workarounds: disable_esmtp delay_dotcrlf for spam.example.org[10.0.0.1]:25
        $Totals{'PixWorkaround'}++;
        $Counts{'PixWorkaround'}{$type}{formathost($hostip,$host)}++;
    }
    
    elsif ( my ($host,$hostip,$p3) = ($p2 =~ /^client=([^[]+)\[($re_IP)\],( sasl_(?:method|username|sender)=.*)$/o ) ){
        #TD 6C8F93041B: client=localhost[127.0.0.1], sasl_sender=someone@example.com 
        #TD 150B9837E4: client=example.com[192.168.0.1], sasl_method=PLAIN, sasl_username=anyone@sample.net
        #TD EFC962C4C1: client=example.com[192.168.0.1], sasl_method=LOGIN, sasl_username=user@example.com, sasl_sender=<id352ib@sample.net>
        my ($Method,$User,$Sender) = ($p3 =~ /^(?: sasl_method=([^,]+),?)?(?: sasl_username=([^,]+),?)?(?: sasl_sender=<([^>]*)>)?$/o );
        
        $User = 'Unknown'       if ($User =~ /^$/);
        $Method = 'Unknown'     if ($Method =~ /^$/);
        
        # sasl_sender occurs when AUTH verb is present in MAIL FROM, typically used for relaying
        # the username (eg. sasl_username) of authenticated users.
        if ($Sender) {
            $Totals{'SaslAuthRelay'}++;
            $Counts{'SaslAuthRelay'}{"$Sender ($User)"}{$Method}{formathost($hostip,$host)}++;
        } else {
            $Totals{'SaslAuth'}++;
            $Counts{'SaslAuth'}{$User}{$Method}{formathost($hostip,$host)}{$Sender}++;
        }
    }
    
    elsif ( $p2 =~ /^sender non-delivery notification/ ){
        #TD 5426ACC81: sender non-delivery notification: 7446BCD68
        $Totals{'DSNUndelivered'}++;
    }
    
    elsif ( $p2 =~ /^sender delivery status notification/ ){
        #TD 5426ACC81: sender delivery status notification: 7446BCD68
        $Totals{'DSNDelivered'}++;
    }
    
    elsif ( my ($host,$hostip,$site,$reason) = ($p2 =~ /^discard: RCPT from ([^[]+)\[($re_IP)\]: ([^:]*): ([^;]*);/o) ){
        #TD NOQUEUE: discard: RCPT from sample.net[192.168.0.1]: <sender@example.com>: Sender address - test; from=<sender@example.com> to=<To@sample.net> proto=ESMTP helo=<example.com>
        $Totals{'Discarded'}++;
        $Counts{'Discarded'}{formathost($hostip,$host)}{$site}{$reason}++;
    }
    
    elsif ( my ($cmd,$host,$hostip,$reason,$p3) = ($p2 =~ /^milter-reject: (\S+) from ([^[]+)\[($re_IP)\]: $re_DSN ([^;]+); (.*)$/o ) ){
        #TD NOQUEUE: milter-reject: MAIL from example.com[192.168.0.1]: 553 5.1.7 address incomplete; proto=ESMTP helo=<example.com>
        #TD NOQUEUE: milter-reject: CONNECT from sample.net[10.0.0.1]: 451 4.7.1 Service unavailable - try again later; proto=SMTP
        #TD C569C12: milter-reject: END-OF-MESSAGE from sample.net[10.0.0.1]: 5.7.1 black listed URL host sample.com by .black.uribl.com; from=<from@sample.net> to=<to@example.com> proto=ESMTP helo=<sample.net>
        # Note: reject_warning does not seem to occur
        $Totals{'RejectMilter'}++;
        #$Counts{'RejectMilter'}{$cmd}{formathost($hostip,$host)}{$reason}{$p3}++;
        $Counts{'RejectMilter'}{$cmd}{formathost($hostip,$host)}{$reason}++;
    }
    
    else {
        # keep this as the last condition in this else clause
        inc_unmatched('unknownqid', $OrigLine);
    }
}

sub handle_QID_reject {
    my ($self, $line, $rej_action, $p3) = @_;

    $rej_action =~ s/^r/R/; $rej_action =~ s/_warning$/Warn/;

    # $re_QID: reject: RCPT from ...
    if ( my ($p4) = ($p3 =~ /^RCPT from (.*)$/o ) ){
        # Recipient address rejected: Unknown users and via check_recipient_access
        
        if ( $p4 !~ /^([^[]+)\[($re_IP)\]: ($re_DSN) (.*)$/o ) {
            inc_unmatched('reject1', $OrigLine);
            next;
        }
        my ($host,$hostip,$dsn,$p5) = ($1,$2,$3,$4);
        
        $rej_action = "Temp$rej_action"    if ($dsn =~ /^4/);
        
        # XXX there may be many semicolon separated messages; need to parse based on "from="
        if ( ($recip,$reason,$p6) = ($p5 =~ /^<(.*)>: Recipient address rejected: ([^;]*);(.*)$/o )) {
            # Unknown users; local mailbox, alias, virtual, relay user, unspecified
            if ( $reason =~ s/^User unknown *//o ){
                my ($table) = ($reason =~ /^in ((?:\w+ )+table)/o);
                my ($from) = ($p6 =~ /^ from=<([^>]*)>/o);
                $table = "Address table unavailable"  if ($table =~ /^$/);     # when show_user_unknown_table_name=no
                $from = "<>"  if ($from =~ /^$/);
                
                #TD NOQUEUE: reject: RCPT from sample.net[192.168.0.1]: 550 <to@example.com>: Recipient address rejected: User unknown in local recipient table; from=<> to=<to@example.com> proto=SMTP helo=<sample.net>
                #TD NOQUEUE: reject_warning: RCPT from sample.net[192.168.0.1]: 550 <to@example.com>: Recipient address rejected: User unknown in local recipient table; from=<> to=<to@example.com> proto=SMTP helo=<sample.net>
                #TD NOQUEUE: reject: RCPT from localhost[127.0.0.1]: 550 5.1.1 <to@example.com>: Recipient address rejected: User unknown in virtual address table; from=<from@sample.net> to=<to@example.com> proto=ESMTP helo=<localhost>
                #TD NOQUEUE: reject: RCPT from example.com[10.0.0.1]: 450 4.1.1 <to@sample.net>: Recipient address rejected: User unknown in virtual mailbox table; from=<from@example.com> to=<to@sample.net> proto=ESMTP helo=<example.com>
                #TD NOQUEUE: reject: RCPT from sample.net[10.0.0.1]: 550 5.5.0 <to1@example.com>: Recipient address rejected: User unknown; from=<from1@sample.net> to=<to@example.com> proto=ESMTP helo=<[10.0.0.1]>
                #TD NOQUEUE: reject: RCPT from example.com[2001:dead:beef::1]: 450 <to@example.net>: Recipient address rejected: Greylisted; from=<from@example.com> to=<to@example.net> proto=ESMTP helo=<example.com>
                #print "User: $User, table: $table\n";
                
                $Totals{"${rej_action}UnknownUser"}++;
                $Counts{"${rej_action}UnknownUser"}{"\u$table"}{"\L$recip"}{$from}++;
            } else { # check_recipient_access
                #TD NOQUEUE: reject: RCPT from example.com[10.0.0.1]: 454 4.7.1 <to@sample.net>: Recipient address rejected: Access denied; from=<from@example.com> to=<to@sample.net> proto=SMTP helo=<example.com>
                #TD NOQUEUE: reject_warning: RCPT from example.com[10.0.0.1]: 454 4.7.1 <to@sample.net>: Recipient address rejected: Access denied; from=<from@example.com> to=<to@sample.net> proto=SMTP helo=<example.com>
                #TD NOQUEUE: reject: RCPT from example.com[10.0.0.1]: 450 4.1.2 <to@example.com>: Recipient address rejected: Domain not found; from=<from@sample.net> to=<to@example.com> proto=ESMTP helo=<sample.net>
                #TD NOQUEUE: reject: RCPT from example.com[10.0.0.1]: 554 <to@example.net>: Recipient address rejected: Please see http://www.openspf.org/why.html?sender=from%40example.net&ip=10.0.0.1&receiver=mx.example.net; from=<from@example.net> to=<to@example.net> proto=ESMTP helo=<to@example.com>
                #TD NOQUEUE: reject: RCPT from mail.example.com[10.0.0.1]: 550 <unknown@example.net>: Recipient address rejected: undeliverable address: host mail.example.net[192.168.0.1] said: 550 <unknown@example.net>: User unknown in virtual alias table (in reply to RCPT TO command); from=<from@example.com> to=<unknown@example.net> proto=SMTP helo=<mail.example.com>
                #TD NOQUEUE: reject: RCPT from unknown[10.0.0.1]: 554 <user@example.com>: Recipient address rejected: Please see http://spf.pobox.com/why.html?sender=user%40example.com&ip=10.0.0.1&receiver=mail; from=<user@example.com> to=<to@sample.net> proto=ESMTP helo=<10.0.0.1>
                
                if ($reason =~ m{^Please see http://[^/]+/why\.html}) {
                    $reason = 'SPF reject';
                } elsif ($reason =~ /^undeliverable address: host ([^[]+)\[($re_IP)\] said:/o) {
                    $reason = 'undeliverable address: remote host rejected recipient';
                }
                
                $Totals{"${rej_action}Recip"}++;
                $Counts{"${rej_action}Recip"}{"\u$reason"}{"\L$recip"}{formathost($hostip,$host)}++;
            }
        }
        
        elsif ( my ($to) = ($p5 =~ /^<([^ ]*)>.* Relay access denied.* to=([^ ]*)/o ) ){
            #TD NOQUEUE: reject: RCPT from example.com[192.168.0.1]: 554 <to@sample.net>: Relay access denied; from=<from@example.com> to=<to@sample.net> proto=SMTP helo=<example.com>
            #TD NOQUEUE: reject_warning: RCPT from example.com[192.168.0.1]: 554 <to@sample.net>: Relay access denied; from=<from@example.com> to=<to@sample.net> proto=SMTP helo=<example.com>
            # print "host: \"$host\", hostip: \"$hostip\", To: \"$to\"\n";
            $Totals{"${rej_action}Relay"}++;
            $Counts{"${rej_action}Relay"}{formathost($hostip,$host)}{$to}++;
        }
        
        elsif ( my ($from,$reason) =  ($p5 =~ /^<(.*)>: Sender address rejected: (.*);/o ) ){
            #TD NOQUEUE: reject: RCPT from sample.net[10.0.0.1]: 450 4.1.8 <from@sample.net>: Sender address rejected: Domain not found; from=<from@sample.com> to=<to@example.com> proto=ESMTP helo=<sample.net>
            #TD NOQUEUE: reject_warning: RCPT from sample.net[10.0.0.1]: 450 4.1.8 <from@sample.net>: Sender address rejected: Domain not found; from=<from@sample.com> to=<to@example.com> proto=ESMTP helo=<sample.net>
            #TD NOQUEUE: reject: RCPT from mail.example.com[10.0.0.1]: 550 <unknown@example.net>: Sender address rejected: undeliverable address: host mail.example.net[192.168.0.1] said: 550 <unknown@example.net>: User unknown in virtual alias table (in reply to RCPT TO command); from=<unknown@example.net> to=<user@example.net> proto=SMTP helo=<mail.example.com>
            # print "host: \"$host\", hostip: \"$hostip\", from: \"$from\", reason: \"$reason\"\n";
            $from = "<>"  if ($from =~ /^$/);
            if ($reason =~ /^undeliverable address: host ([^[]+)\[($re_IP)\] said:/o) {
                $reason = 'undeliverable address: remote host rejected sender';
            }
            $Totals{"${rej_action}Sender"}++;
            $Counts{"${rej_action}Sender"}{"\u$reason"}{formathost($hostip,$host)}{$from}++;
        }
        
        elsif ( my ($reason,$from,$recip) = ($p5 =~ /^<[^[]+\[$re_IP\]>: Client host rejected: (.*); from=<(.*)> to=<(.*)> proto=/o ) ){
            #TD NOQUEUE: reject: RCPT from sample.net[10.0.0.1]: 554 <sample.net[10.0.0.1]>: Client host rejected: Access denied; from=<from@sample.net> to=<to@example.com> proto=SMTP helo=<friend> 
            #TD NOQUEUE: reject_warning: RCPT from sample.net[10.0.0.1]: 554 <sample.net[10.0.0.1]>: Client host rejected: Access denied; from=<from@sample.net> to=<to@example.com> proto=SMTP helo=<friend> 
            #TD NOQUEUE: reject: RCPT from sample.net[10.0.0.1]: 450 Client host rejected: cannot find your hostname, [10.0.0.1]; from=<from@sample.net> to=<to@example.com> proto=ESMTP helo=<sample.net>
            $from = "<>"		if ($from =~ /^$/);
            $Totals{"${rej_action}Client"}++;
            $Counts{"${rej_action}Client"}{"\u$reason"}{formathost($hostip,$host)}{"\L$recip"}{$from}++;
        }
        
        elsif ( (my $p6) = ($p5 =~ /^Client host rejected: cannot find your (.*)$/o ) ){
            if ( my ($from,$recip,$helo) = ($p6 =~ /^hostname, \[$re_IP\]; from=<(.*?)> to=<(.*?)> proto=\S+ helo=<(.*)>/o ) ){
                #TD NOQUEUE: reject: RCPT from unknown[10.0.0.1]: 450 Client host rejected: cannot find your hostname, [10.0.0.1]; from=<from@example.com> to=<to@sample.net> proto=ESMTP helo=<example.com> 
                #TD NOQUEUE: reject_warning: RCPT from unknown[10.0.0.1]: 450 Client host rejected: cannot find your hostname, [10.0.0.1]; from=<from@example.com> to=<to@sample.net> proto=ESMTP helo=<example.com> 
                $from = "<>"		if ($from =~ /^$/);
                $Totals{"${rej_action}UnknownClient"}++;
                $Counts{"${rej_action}UnknownClient"}{$host}{$helo}{$from}{"\L$recip"}++;
                # reject_unknown_reverse_client_hostname (no DNS PTR record for client's IP)
            } elsif ( $p6 =~ /^reverse hostname, \[$re_IP\]/o ){
                #TD NOQUEUE: reject: RCPT from unknown[192.168.0.1]: 550 5.7.1 Client host rejected: cannot find your reverse hostname, [192.168.0.1]
                $Totals{"${rej_action}UnknownReverseClient"}++;
                $Counts{"${rej_action}UnknownReverseClient"}{$host}++
            } else {
                inc_unmatched('rejectclienthost', $OrigLine);
            }
        }
        
        elsif ( my ($site,$reason)  = ($p5 =~ /^Service unavailable; (?:Client host |Sender address )?\[[^ ]*\] blocked using ([^ ]*)(, reason: .*)?;/o ) ){
            # Note: similar code below: search RejectRBL
            #TD NOQUEUE: reject: RCPT from example.com[10.0.0.1]: 554 5.7.1 Service unavailable; Client host [10.0.0.1] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/query/bl?ip=10.0.0.1; from=<from@example.com> to=<to@sample.net> proto=ESMTP helo=<friend>
            #TD NOQUEUE: reject_warning: RCPT from example.com[10.0.0.1]: 554 5.7.1 Service unavailable; Client host [10.0.0.1] blocked using sbl-xbl.spamhaus.org; http://www.spamhaus.org/query/bl?ip=10.0.0.1; from=<from@example.com> to=<to@sample.net> proto=ESMTP helo=<friend>
            $Totals{"${rej_action}RBL"}++;
            if ($reason =~ /^$/) {
                $Counts{"${rej_action}RBL"}{$site}{formathost($hostip,$host)}++;
            } else {
                $Counts{"${rej_action}RBL"}{$site}{formathost($hostip,$host)}{$reason}++;
            }
        }
        
        elsif ( my ($reason,$helo) = ($p5 =~ /^<.*>: Helo command rejected: (.*);.* helo=<(.*)>$/o ) ){
            #TD NOQUEUE: reject: RCPT from sample.net[10.0.0.1]: 454 4.7.1 <localhost>: Helo command rejected: Access denied; from=<from@sample.net> to=<to@example.com> proto=SMTP helo=<localhost>
            #TD NOQUEUE: reject_warning: RCPT from sample.net[10.0.0.1]: 454 4.7.1 <localhost>: Helo command rejected: Access denied; from=<from@sample.net> to=<to@example.com> proto=SMTP helo=<localhost>
            $Totals{"${rej_action}Helo"}++;
            $Counts{"${rej_action}Helo"}{$reason}{formathost($hostip,$host)}{"$helo"}++;
        }
        
        elsif ( my ($from,$to) = ($p5 =~ /^Insufficient system storage; from=<([^>]*)> to=<([^>]+)>/o ) ){
            #TD NOQUEUE: reject: RCPT from example.com[192.168.0.1]: 452 Insufficient system storage; from=<from@example.com> to=<to@sample.net> 
            #TD NOQUEUE: reject_warning: RCPT from example.com[192.168.0.1]: 452 Insufficient system storage; from=<from@example.com> to=<to@sample.net> 
            $from = "<>"		if ($from =~ /^$/);
            $Totals{"${rej_action}InsufficientSpace"}++;
            $Counts{"${rej_action}InsufficientSpace"}{formathost($hostip,$host)}{$to}{$from}++;
            $Totals{'WarnInsufficientSpace'}++;    # to show in Warnings section
        }
        
        elsif ( my ($from,$to) = ($p5 =~ /^Server configuration (?:error|problem); from=<([^>]*)> to=<([^>]+)>/o ) ){
            #TD NOQUEUE: reject: RCPT from example.com[10.0.0.1]: 451 4.3.5 Server configuration error; from=<from@example.com> to=<user@sample.net> proto=ESMTP helo=<example.com>
            #TD NOQUEUE: reject_warning: RCPT from example.com[10.0.0.1]: 451 4.3.5 Server configuration error; from=<from@example.com> to=<user@sample.net> proto=ESMTP helo=<example.com>
            #TD NOQUEUE: reject: RCPT from sample.net[192.168.0.1]: 450 Server configuration problem; from=<from@sample.net> to=<to@example.com> proto=ESMTP helo=<sample.net>
            $from = "<>"		if ($from =~ /^$/);
            $Totals{"${rej_action}ConfigError"}++;
            $Counts{"${rej_action}ConfigError"}{formathost($hostip,$host)}{$to}{$from}++;
            $Totals{'WarnConfigError'}++;          # to show in Warnings section
            # This would capture all other rejects, but I think it might be more useful to add
            # additional capture sections based on user reports of uncapture lines.
            #
            #} elsif ( ($reason) = ($p5 =~ /^([^;]+);/o)) {
            #  $Totals{"${rej_action}Other"}++;
            #  $Counts{"${rej_action}Other"}{$reason}++;
        }
        
        else {
            inc_unmatched('rejectother', $OrigLine);
        }
    } # end of $re_QID: reject: RCPT from ...
    
    # $re_QID: reject: body ...
    # $re_QID: reject: header ...
    elsif ( ($reason,$host,$to,$reason2) = ($p3 =~ /^(?:header|body) (.*) from ([^;]+); from=<(?:[^ ]*)>(?: to=<([^>]*)>)?(?: proto=[^ ]* helo=<[^ ]*>)?: (.*)$/o ) ){
        #TD 9804DB31C2: reject: header To: <user@example.com> from sample.net[192.168.0.1]; from=<bogus@anywhere.com> to=<user@example.com> proto=ESMTP helo=<anywhere.com>: Any reason
        #TD 831C2C2E0D: reject: body Quality Replica watches!!! from example.com[192.168.0.1]; from=<user@example.com> to=<recip@sample.net> proto=SMTP helo=<example.com>: 5.7.1 Spam: Watches
        #TD 26B6AC2DB5: reject: body xx Subject: Cheapest Viagra and Cialis you can find! from local; from=<root@localhost>: 5.7.1 Spam: Drugs
        # Note: reject_warning does not seem to occur
        if ($host =~ /^local$/) {
            $hostip = '127.0.0.1';
        } elsif ($host =~ /([^[]+)\[($re_IP)\]/) {
            $host = $1; $hostip = $2;
        }
        $reason =~ s/\s+/ /g;
        if ($p3 =~ /^body/) {
            $Totals{'RejectBody'}++;
            $Counts{'RejectBody'}{$reason2}{$to}{formathost($hostip,$host)}{"$reason"}++;
        } else {
            #print "reason: \"$reason\", host: \"$host\", hostip: \"$hostip\", to: \"$to\", reason2: \"$reason2\"\n";
            $Totals{'RejectHeader'}++;
            $Counts{'RejectHeader'}{$reason2}{$to}{formathost($hostip,$host)}{"$reason"}++;
        }
    }
    
    # $re_QID: reject: MAIL from ...
    elsif ( my ($host,$hostip) = ($p3 =~ /^MAIL from ([^[]+)\[($re_IP)\]: $re_DSN Message size exceeds fixed limit; proto=[^ ]* helo=<[^>]+>$/o ) ){
        # Postfix responds with this message after a MAIL FROM:<...> SIZE=nnn  command, where postfix consider's nnn excessive
        # Note: similar code below: search RejectSize
        # Note: reject_warning does not seem to occur
        #TD NOQUEUE: reject: MAIL from localhost[127.0.0.2]: 552 Message size exceeds fixed limit; proto=ESMTP helo=<localhost> 
        #TD NOQUEUE: reject: MAIL from example.com[192.168.0.2]: 452 4.3.4 Message size exceeds fixed limit; proto=ESMTP helo=<example.com>
        $Totals{'RejectSize'}++;
        $Counts{'RejectSize'}{formathost($hostip,$host)}{'unknown'}++;
    }
    
    # $re_QID: reject: CONNECT from ...
    elsif ( my ($p4) = ($p3 =~ /^CONNECT from (.*)$/o ) ){
        if ( my ($host,$hostip,$dsn,$reason) = ($p4 =~ /([^[]+)\[($re_IP)\]: ($re_DSN) <.*>: Client host rejected: ([^;]*);/o ) ){
            #TD NOQUEUE: reject: CONNECT from unknown[192.168.0.1]: 503 5.5.0 <unknown[192.168.0.1]>: Client host rejected: Improper use of SMTP command pipelining; proto=SMTP
            $rej_action = "Temp$rej_action" if ($dsn =~ /^4/);
            $Totals{"${rej_action}Client"}++;
            $Counts{"${rej_action}Client"}{"\u$reason"}{formathost($hostip,$host)}{""}++;    # XXX currently need to keep same key depth - add CONNECT key to do so
        } else {
            inc_unmatched('connfrom', $OrigLine);
        }
    }
    
    # $re_QID: reject: VRFY from ...
    elsif ( my ($p4) = ($p3 =~ /^VRFY from (.*)$/o ) ){
        #TD NOQUEUE: reject: VRFY from example.com[10.0.0.1]: 550 5.1.1 <:>: Recipient address rejected: User unknown in local recipient table; to=<:> proto=SMTP helo=<192.168.0.1>
        #TD NOQUEUE: reject_warning: VRFY from example.com[10.0.0.1]: 450 4.1.2 <<D0-1C7-1F41F6@BS>>: Recipient address rejected: Domain not found; to=<<D0-1C7-1F41F6@BS>> proto=SMTP helo=<friend>
        #TD NOQUEUE: reject: VRFY from example.com[10.0.0.1]: 450 4.1.8 <to@example.com>: Sender address rejected: Domain not found; from=<to@example.com> to=<to> proto=SMTP 
        #TD NOQUEUE: reject: VRFY from example.com[10.0.0.1]: 554 5.7.1 Service unavailable; Client host [10.0.0.1] blocked using zen.spamhaus.org; http://www.spamhaus.org/query/bl?ip=10.0.0.1; to=<u> proto=SMTP
        if ( my ($host,$hostip,$dsn,$reason) = ($p4 =~ /([^[]+)\[($re_IP)\]: ($re_DSN) (?:<.*>: )?([^;]*);/o ) ){
            $rej_action = "Temp$rej_action" if ($dsn =~ /^4/);
            $Totals{"${rej_action}Verify"}++;
            $Counts{"${rej_action}Verify"}{"\u$reason"}{formathost($hostip,$host)}++;
        } else {
            inc_unmatched('vrfyfrom', $OrigLine);
        }
    }
    
    else {
        inc_unmatched('rejectlast', $OrigLine);
    }
}

sub handle_QID_sfbdu { # sent, forwarded, bounced, softbounce, deferred, (un)deliverable
    my ($self, $line, $to, $origto, $relay, $DDD, $status, $reason) = @_;
    
    #TD 552B6C20E: to=<to@sample.com>, relay=mail.example.net[10.0.0.1]:25, delay=1021, delays=1020/0.04/0.56/0.78, dsn=2.0.0, status=sent (250 Ok: queued as 6EAC4719EB)
    #TD DD925BBE2: to=<to@example.net>, orig_to=<to-ext@example.net>, relay=mail.example.net[2001:dead:beef::1], delay=2, status=sent (250 Ok: queued as 5221227246)
    
    $reason =~ s/\((.*)\)/$1/;    # Makes capturing nested parens easier
    $to     = lc $to;
    $origto = lc $origto;
    my ($localpart, $domainpart) = split ('@', $to);
    
    # If recipient_delimiter is set, break localpart into user + extension
    # and save localpart in origto if origto is empty
    if ($Opts{'recipient_delimiter'} and $localpart =~ /\Q$Opts{'recipient_delimiter'}\E/o) {
        # special cases: never split mailer-daemon or double-bounce
        # or owner- or -request if delim is "-" (dash).
        unless (
        ($localpart =~ /^(?:mailer-daemon|double-bounce)$/i) or
        ($Opts{'recipient_delimiter'} eq '-' and $localpart =~ /^owner-.|.-request$/i) ){
            my ($user,$extension) = split (/$Opts{'recipient_delimiter'}/o, $localpart, 2);
            $origto = $localpart    if ($origto =~ /^$/);
            $localpart = $user;
        }
    }
    
    my $dsn;
    unless ( ($dsn) = ($DDD =~ /dsn=(\d\.\d\.\d)/) ){
        $dsn = "X.X.X (DSN unavailable)";
        #$dsn = "";
    }
    
    ### sent
    if ($status =~ /^sent$/) {
        if ($reason =~ /forwarded as /) {
            $Totals{'MsgsForwarded'}++;
            $Counts{'MsgsForwarded'}{$domainpart}{$localpart}{$origto}++;
        }else {
            if ($postfix_svc =~ /^lmtp$/) {
                $Totals{'MsgsSentLmtp'}++;
                $Counts{'MsgsSentLmtp'}{$domainpart}{$localpart}{$origto}++;
            } elsif ($postfix_svc =~ /^smtp$/) {
                $Totals{'MsgsSent'}++;
                $Counts{'MsgsSent'}{$domainpart}{$localpart}{$origto}++;
            } else { # virtual, command, ...
                $Totals{'MsgsDelivered'}++;
                $Counts{'MsgsDelivered'}{$domainpart}{$localpart}{$origto}++;
            }
        }
        if ( exists $Qids{$qid} and exists $Qids{$qid}{'size'} ){
            $Totals{'BytesDelivered'} += $Qids{$qid}{'size'};
        }
    }
    
    ### bounced
    elsif ($status =~ /^(?:bounced|SOFTBOUNCE)$/) {
        #TD 76EB0D13: to=<user@example.com>, relay=none, delay=1, status=bounced (mail for mail.example.com loops back to myself)
        #TD C8103B94: to=<user@example.com>, relay=none, delay=0, status=bounced (Host or domain name not found. Name service error for name=unknown.com type=A: Host not found)
        #TD C76431E2: to=<login@sample.net>, relay=local, delay=2, status=SOFTBOUNCE (host sample.net[192.168.0.1] said: 450 <login@sample.com>: User unknown in local recipient table (in reply to RCPT TO command))
        #TD EB0B8770: to=<to@example.com>, orig_to=<postmaster>, relay=none, delay=1, status=bounced (User unknown in virtual alias table) 
        #TD EB0B8770: to=<to@example.com>, orig_to=<postmaster>, relay=sample.net[192.168.0.1], delay=1.1, status=bounced (User unknown in relay recipient table) 
        #TD D8962E54: to=<anyone@example.com>, relay=local, conn_use=2 delay=0.21, delays=0.05/0.02/0/0.14, dsn=4.1.1, status=SOFTBOUNCE (unknown user: "to")
        #TD F031C832: to=<to@sample.net>, orig_to=<alias@sample.net>, relay=local, delay=0.17, delays=0.13/0.01/0/0.03, dsn=5.1.1, status=bounced (unknown user: "to")
        #TD 04B0702E: to=<anyone@example.com>, relay=example.com[10.0.0.1]:25, delay=12, delays=6.5/0.01/0.03/5.1, dsn=5.1.1, status=bounced (host example.com[10.0.0.1] said: 550 5.1.1 User unknown (in reply to RCPT TO command))
        #TD 9DAC8B2D: to=<to@example.com>, relay=example.com[10.0.0.1]:25, delay=1.4, delays=0.04/0/0.27/1.1, dsn=5.0.0, status=bounced (host example.com[10.0.0.1] said: 511 sorry, no mailbox here by that name (#5.1.1 - chkuser) (in reply to RCPT TO command))
        #TD 79CB702D: to=<to@example.com>, relay=example.com[10.0.0.1]:25, delay=0.3, delays=0.04/0/0.61/0.8, dsn=5.0.0, status=bounced (host example.com[10.0.0.1] said: 550 <to@example.com>, Recipient unknown (in reply to RCPT TO command))
        #TD 88B7A079: to=<to@example.com>, relay=example.com[10.0.0.1]:25, delay=45, delays=0.03/0/5.1/40, dsn=5.0.0, status=bounced (host example.com[10.0.0.1] said: 550-"The recipient cannot be verified.  Please check all recipients of this 550 message to verify they are valid." (in reply to RCPT TO command))
        #TD 47B7B074: to=<to@example.com>, relay=example.com[10.0.0.1]:25, delay=6.6, delays=6.5/0/0/0.11, dsn=5.1.1, status=bounced (host example.com[10.0.0.1] said: 550 5.1.1 <to@example.com> User unknown; rejecting (in reply to RCPT TO command))
        
        ### local bounce
        # XXX local v. remote bounce seems iffy, relative
        if ($relay =~ /^(?:none|local|virtual|avcheck|maildrop|127\.0\.0\.1)/) {
            $Totals{'BounceLocal'}++;
            $Counts{'BounceLocal'}{get_dsn_msg($dsn)}{$to}{"\u$reason"}++;
        }
        ### remote bounce
        else {
            my ($reply,$fmtdhost) = cleanhostreply($reason,$relay,$to,$domainpart);
            $Totals{'BounceRemote'}++;
            $Counts{'BounceRemote'}{get_dsn_msg($dsn)}{$domainpart}{$localpart}{$fmtdhost}{$reply}++;
        }
    }
    
    elsif ($status =~ /deferred/) {
        #TD DD4F2AC4D3: to=<to@example.com>, relay=none, delay=27077, delays=27077/0/0.57/0, dsn=4.4.3, status=deferred (Host or domain name not found. Name service error for name=example.com type=MX: Host not found, try again)
        #TD E52A1F1B52: to=<to@example.com>, relay=none, delay=141602, status=deferred (connect to mx1.example.com[10.0.0.1]: Connection refused)
        #TD E52A1F1B52: to=<to@example.com>, relay=none, delay=141602, status=deferred (delivery temporarily suspended: connect to example.com[192.168.0.1]: Connection refused)
        #TD DB775D7035: to=<to@example.com>, relay=none, delay=306142, delays=306142/0.04/0.18/0, dsn=4.4.1, status=deferred (connect to example.com[10.0.0.1]: Connection refused)
        #TD EEDC1F1AA6: to=<to@example.org>, relay=example.org[10.0.0.1], delay=48779, status=deferred (lost connection with mail.example.org[10.0.0.1] while sending MAIL FROM)
        #TD 8E7A0575C3: to=<to@sample.net>, relay=sample.net, delay=26541, status=deferred (conversation with mail.example.com timed out while sending end of data -- message may be sent more than once) 
        #TD 7CF61B7030: to=<to@sample.net>, relay=sample.net[10.0.0.1]:25, delay=322, delays=0.04/0/322/0, dsn=4.4.2, status=deferred (conversation with example.com[10.0.0.01] timed out while receiving the initial server greeting)
        #TD B8BF0AE331: to=<to@localhost>, orig_to=<toalias@localhost>, relay=none, delay=238024, status=deferred (delivery temporarily suspended: transport is unavailable) 
        # XXX postfix reports dsn=5.0.0, host's reply may contain its own dsn's such as 511 and #5.1.1
        # XXX should these be used instead?
        #TD 232EAC2E55: to=<to@sample.net>, relay=sample.net[10.0.0.1]:25, delay=5.7, delays=0.05/0.02/5.3/0.3, dsn=4.7.1, status=deferred (host sample.net[10.0.0.1] said: 450 4.7.1 <to@sample.net>: Recipient address rejected: Greylisted (in reply to RCPT TO command))
        #TD 11677B700D: to=<to@example.com>, relay=example.com[10.0.0.1]:25, delay=79799, delays=79797/0.02/0.4/1.3, dsn=4.0.0, status=deferred (host example.com[10.0.0.1] said: 450 <to@example.com>: User unknown in local recipient table (in reply to RCPT TO command))
        #TD 0DA72B7035: to=<to@example.com>, relay=example.com[10.0.0.1]:25, delay=97, delays=0.03/0/87/10, dsn=4.0.0, status=deferred (host example.com[10.0.0.1] said: 450 <to@example.com>: Recipient address rejected: undeliverable address: User unknown in virtual alias table (in reply to RCPT TO command))
        my ($reply,$fmtdhost) = cleanhostreply($reason,$relay,$to,$domainpart);
        
        if ( $DeferredByQid{$qid}++ == 0 ){
            $Totals{'MsgsDeferred'}++;
        }
        $Totals{'Deferrals'}++;
        $Counts{'Deferrals'}{get_dsn_msg($dsn)}{$reply}{$domainpart}{$localpart}{$fmtdhost}++;
    }
    
    elsif ($status =~ /^undeliverable$/) {
        #TD B54D220BFC: to=<u@example.com>, relay=sample.com[10.0.0.1], delay=0, dsn=5.0.0, status=undeliverable (host sample.com[10.0.0.1] refused to talk to me: 554 5.7.1 example.com Connection not authorized) 
        #TD 8F699C2EA6: to=<u@example.com>, relay=virtual, delay=0.14, delays=0.06/0/0/0.08, dsn=5.1.1, status=undeliverable (unknown user: "u@example.com")
        $Totals{'Undeliverable'}++;
        $Counts{'Undeliverable'}{$reason}{$origto ? "$to ($origto)" : "$to"}++;
    }
    
    elsif ($status =~ /^deliverable$/) {
        # sendmail -bv style deliverable reports
        #TD ED862C2EA6: to=<u@example.com>, relay=virtual, delay=0.09, delays=0.03/0/0/0.06, dsn=2.0.0, status=deliverable (delivers to maildir)
        $Totals{'Deliverable'}++;
        $Counts{'Deliverable'}{$reason}{$origto ? "$to ($origto)" : "$to"}++;
    }
    
    else {
        # keep this as the last condition in this else clause
        inc_unmatched('unknownstatus', $OrigLine);
    }
}

1;
