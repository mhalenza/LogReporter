package LogReporter::Service::Postfix;
use Moose;
use namespace::autoclean;
extends 'LogReporter::Service';

has 'template_name' => (
    is => 'ro',
    isa => 'Str',
    required => 1,
    default => sub { 'postfix'; },
);
with 'LogReporter::Templated';

my $re_DSN    =  '(?:\d{3}(?: \d\.\d\.\d)?)';
my $re_MsgID  =  '[a-zA-Z\d]+';

has data => (
    is => 'rw',
    isa => 'HashRef',
    default => sub { {}; },
);

override process_line => sub {
    my ($self, $line, $meta) = @_;
    
    if (
        ( $line =~ m/^$re_MsgID: client=([^ ]*\[[^ ]*\])\s*$/ ) or
        ( $line =~ m/^$re_MsgID: message-id/ ) or
        ( $line =~ m/^$re_MsgID: skipped, still being delivered/ ) or
        ( $line =~ m/^$re_MsgID: to=\<.*>, relay=.*, delay=[\d.]+,(?: delays=[\d\/.]+, dsn=[\d.]+,)? status=(?:sent|deferred)/ ) or
        ( $line =~ m/^$re_MsgID: host [^ ]*\[[^ ]*\] said: 4[0-9][0-9]/ ) or
        ( $line =~ m/^$re_MsgID: host [^ ]*\[[^ ]*\] refused to talk to me: 4[0-9][0-9]/ ) or
        ( $line =~ m/^$re_MsgID: sender non-delivery notification: $re_MsgID/ ) or
        ( $line =~ m/^Deleted: \d message$/ ) or
        ( $line =~ m/^Peer certficate could not be verified$/ ) or #postfix typo
        ( $line =~ m/^Peer certificate could not be verified$/ ) or
        ( $line =~ m/^Peer verification:/ ) or
        ( $line =~ m/^SSL_accept error from/ ) or
        ( $line =~ m/^Verified: / ) or
        ( $line =~ m/^cert has expired/ ) or
        ( $line =~ m/^connect/ ) or
        ( $line =~ m/^daemon started$/ ) or
        ( $line =~ m/^daemon started -- version / ) or
        ( $line =~ m/^dict_eval_action:/ ) or
        ( $line =~ m/^disconnect/ ) or
        ( $line =~ m/^mynetworks:/ ) or
        ( $line =~ m/^name_mask:/ ) or
        ( $line =~ m/^reload(?: -- version [\d.]+,)? configuration/ ) or
        ( $line =~ m/^setting up TLS connection (from|to)/ ) or
        ( $line =~ m/^starting TLS engine$/ ) or
        ( $line =~ m/^terminating on signal 15$/ ) or
        ( $line =~ m/^warning: $re_MsgID: skipping further client input$/ ) or
        ( $line =~ m/^warning: (?:smtpd_peer_init: )?[\.0-9]+: address not listed for hostname/ ) or
        ( $line =~ m/^warning: (?:smtpd_peer_init: )?[\.0-9]+: hostname .* verification failed: Host not found/ ) or
        ( $line =~ m/^warning: (?:smtpd_peer_init: )?[\.0-9]+: hostname .* verification failed: Name or service not known/ ) or
        ( $line =~ m/^warning: (?:smtpd_peer_init: )?[\.0-9]+: hostname .* verification failed: Temporary failure in name resolution/ ) or
        ( $line =~ m/^warning: Mail system is down -- accessing queue directly$/ ) or
        ( $line =~ m/^warning: SASL authentication failure: Password verification failed$/ ) or
        ( $line =~ m/^warning: SASL authentication failure: no secret in database$/ ) or
        ( $line =~ m/^warning: no MX host for .* has a valid A record$/ ) or
        ( $line =~ m/^warning: numeric domain name in resource data of MX record for .*$/ ) or
        ( $line =~ m/^warning: premature end-of-input from cleanup socket while reading input attribute name$/ ) or
        ( $line =~ m/^warning: uid=\d: Broken pipe$/ ) or
        ( $line =~ m/^verify error:num=/ ) or
        ( $line =~ m/hold: header / ) or
        ( $line =~ m/^statistics: max / ) or
        ( $line =~ m/^statistics: start interval / ) or
        ( $line =~ m/^statistics: (address|domain) lookup / ) or
        ( $line =~ m/: replace: header / ) or
        ( $line =~ m/: Greylisted for / ) or                          # Greylisting has it's own statistics tool
        ( $line =~ m/certificate verification failed for/o ) or       # Perhaps a candidate for extended statistics
        ( $line =~ m/Server certificate could not be verified/o ) or  # Perhaps a candidate for extended statistics
        ( $line =~ m/certificate peer name verification failed/o ) or # Perhaps a candidate for extended statistics
        ( $line =~ m/sender non-delivery notification:/o )            # Perhaps a candidate for extended statistics
    ){
        return; # skip these
    } elsif ( my ($Bytes) = ($line =~ /^$re_MsgID: from=[^,]+, size=(\d+), .*$/o) ){
        #fixme count
        $self->data->{MsgsQueue}++;
        $self->data->{BytesTransferred} += $Bytes;
    } elsif ( my ($User) = ($line =~ /^$re_MsgID: to=\<([^ ]*)>,(?: orig_to=\<(?:[^ ]*)>,)? relay=local, delay=-?\d+, status=bounced \((?:unknown user|user unknown)/)) {
        # unknown user
        $self->data->{UnknownUsers}{$User}++;
    } elsif ( my ($User) = ($line =~ /^$re_MsgID: reject: RCPT from (?:[^ ]*): $re_DSN <([^ ]*)>:(?:[^:]+: )?User unknown in(?: \w+)+ table/)) {
        # unknown local mailbox, alias, virtual user
        $self->data->{UnknownUsers}{$User}++;
    } elsif ( my ($User) = ($line =~ /^$re_MsgID: to=\<([^ ]*)>,(?: orig_to=\<(?:[^ ]*)>,)? .*, status=bounced .*: User unknown in virtual (alias|mailbox) table/)) {
        # another unknown user probably could combine with local unknown but again my perl is weak
        $self->data->{UnknownUsers}{$User}++;
    } elsif ( my ($Dest, $Relay, $Msg) = ($line =~ /^$re_MsgID: to=\<([^ ]*)>,(?: orig_to=\<(?:[^ ]*)>,)? relay=([^ ]*).*, delay=-?[\d.]+(?:, delays=[\d\/.]+, dsn=[\d.]+)?, status=bounced \(([^)]*)/ )) {
        # unknown user
        # $Msg = " hello "
        # print "bounce message from " . $Dest . " msg : " . $Relay . "\n";
        if ($Relay =~ m/^(none|local|avcheck|127\.0\.0\.1)/) {
            my $Temp = "To " . $Dest . " Msg=\"" . $Msg . "\"";
            $self->data->{LocalBounce}{$Temp}++;
        } else {
            my $Temp = "To " . $Dest . " Msg=\"" . $Msg . "\"";
            $self->data->{ForeignBounce}{$Temp}++;
        }
    } elsif ( my ($Relay,$Dest) = ($line =~ m/reject: RCPT from ([^ ]*): $re_DSN <([^ ]*)>.* Relay access denied.* to=([^ ]*)/) ) {
        # print "reject: " . $line . "\n";
        # print "Relay :" . $Relay . " to " . $Dest . "\n";
        my $Temp = "From " . $Relay . " to " . $Dest;
        $self->data->{RelayDenied}{$Temp}++;
    } elsif ( my ($User,$From) = ($line =~ /^$re_MsgID: uid=([^ ]*) from=\<([^ ]*)>/)) {
        #Messages sent by user
        my $Temp = $From . " (uid=" . $User . "): ";
        $self->data->{SentBy}{$Temp}++;
    } elsif ( my ($From) = ($line =~ /^$re_MsgID: from=<([^ ]*)>, status=expired, returned to sender$/)) {
        $self->data->{ReturnedToSender}++;
    } elsif ( (undef) = ($line =~ /^$re_MsgID: resent-message-id=<([^ ]*)>$/)) {
        $self->data->{ResentMessages}++;
    } elsif (
      my ($Command,$Host) = ($line =~ /lost connection after (.*) from ([^ ]*)$/) or
      my ($Host,$Command) = ($line =~ /^$re_MsgID: lost connection with ([^ ]*) while (.*)$/)
    ) {
        # Make some better summary with hosts
        $self->data->{ConnectionLost}{$Command}++;
    } elsif (
      my ($Command,$Host) = ($line =~ /timeout after (.*) from ([^ ]*)$/) or
      my ($Host,$Command) = ($line =~ /^$re_MsgID: conversation with ([^ ]*) timed out while (.*)$/)
    ) {
        # Make some better summary with hosts
        $self->data->{ConnectionLost}{$Command}++;
    } elsif ( my ($Rejected,undef,undef,undef,$Reason) = ($line =~ /^$re_MsgID: reject: header (.*); from=<([^ ]*)> to=<([^ ]*)>( proto=[^ ]* helo=<[^ ]*>)?: (.*)$/)) {
        $self->data->{HeaderReject}{$Reason}{$Rejected}++;
    } elsif ( my ($Warning,undef,undef,undef,$Reason) = ($line =~ /^$re_MsgID: warning: header (.*); from=<([^ ]*)> to=<([^ ]*)>( proto=[^ ]* helo=<[^ ]*>)?: (.*)$/)) {
        $self->data->{HeaderWarning}{$Reason}{$Warning}++;
    } elsif ( my ($Warning,undef,undef,undef) = ($line =~ /^$re_MsgID: warning: header (.*); from=<([^ ]*)> to=<([^ ]*)>( proto=[^ ]* helo=<[^ ]*>)?$/)) {
        $self->data->{HeaderWarning}{"Unknown Reason"}{$Warning}++;
    } elsif ( my ($Rejected,undef,undef,undef,$Reason) = ($line =~ /^$re_MsgID: reject: body (.*); from=<([^ ]*)> to=<([^ ]*)>( proto=[^ ]* helo=<[^ ]*>)?: (.*)$/)) {
        $self->data->{BodyReject}{$Reason}{$Rejected}++;
    } elsif ( my (undef,undef,undef,$Reason) = ($line =~ /^$re_MsgID: to=<([^ ]*)>,( orig_to=<[^ ]*>,)? relay=([^ ]*), delay=\d+, status=undeliverable \((.*)\)$/)) {
        $self->data->{Undeliverable}++;
        $self->data->{UndeliverableMsg}{$Reason}++;
    } elsif ( my (undef,undef,undef,undef) = ($line =~ /^$re_MsgID: to=<([^ ]*)>,( orig_to=<[^ ]*>,)? relay=([^ ]*), delay=\d+, status=deliverable \((.*)\)$/)) {
        $self->data->{Deliverable}++;
    } elsif ( my ($Host,$Sender,$Reason) = ($line =~ /reject: RCPT from ([^ ]*\[[^ ]*\]): $re_DSN <(.*)>: Sender address rejected: (.*);/)) {
        $self->data->{RejectSender}{$Reason}{$Host}{$Sender}++;
        $self->data->{RejectSenderHost}{$Reason}{$Host}++;
        $self->data->{RejectSenderReason}{$Reason}++;
    } elsif ( my ($Host,$Reason,$Sender,$Recip) = ($line =~ /reject: RCPT from ([^ ]*\[[^ ]*\]): $re_DSN <[^ ]*\[[^ ]*\]>: Client host rejected: (.*); from=<(.*)> to=<(.*)> proto=/)) {
        $self->data->{RejectClient}{$Reason}{$Host}{$Sender}{$Recip}++;
        $self->data->{RejectClientHost}{$Reason}{$Host}++;
        $self->data->{RejectClientReason}{$Reason}++;
    } elsif ( my ($Host,$Sender,$Recip,$Helo) = ($line =~ /reject: RCPT from [^ ]*\[([^ ]*)\]: $re_DSN Client host rejected: cannot find your hostname, \[\d+\.\d+\.\d+\.\d+\]; from=<(.*?)> to=<(.*?)> proto=\S+ helo=<(.*)>/)) {
        $self->data->{RejectUnknownClient}{$Host}{$Helo}{$Sender}{$Recip}++;
        $self->data->{RejectUnknownClientHost}{"$Host	helo=<$Helo>"}++;
        $self->data->{RejectUnknownClients}++;
    } elsif ( my ($Host,$Recip,$Reason) = ($line =~ /reject: RCPT from ([^ ]*\[[^ ]*\]): $re_DSN <(.*)>: Recipient address rejected: (.*);/)) {
        my $Temp = "$Host : $Reason";
        $self->data->{RejectRecip}{$Recip}{$Temp}++;
    } elsif ( my ($Host,undef) = ($line =~ /reject: RCPT from ([^ ]*\[[^ ]*\]): $re_DSN <(.*)>: Sender address rejected: Access denied;/)) {
        $self->data->{RejectAddress}{$Host}++;
    } elsif ( my ($Host,$Site,$Reason) = ($line =~ /reject: RCPT from ([^ ]*\[[^ ]*\]): $re_DSN Service unavailable; (?:Client host )?\[[^ ]*\] blocked using ([^ ]*), reason: (.*);/)) {
        my $Temp = "$Host : $Reason";
        $self->data->{RejectRBL}{$Site}{$Temp}++;
        $self->data->{RejectedRBL}++;
    } elsif ( my ($Host,$Site) = ($line =~ /reject: RCPT from ([^ ]*\[[^ ]*\]): $re_DSN Service unavailable; (?:Sender address |Client host )?\[[^ ]*\] blocked using ([^ ]*);/)) {
        $self->data->{RejectRBL}{$Site}{$Host}++;
        $self->data->{RejectedRBL}++;
    } elsif ( my ($Host,$Site,$Reason) = ($line =~ /warning: ([^ ]*): RBL lookup error: Name service error for \d+\.\d+\.\d+\.\d+\.([^ ]*): (.*)$/)) {
        my $Temp = "$Host : $Reason";
        $self->data->{RBLError}{$Site}{$Temp}++;
        $self->data->{ErrorRBL}++;
    } elsif ( my ($Host,$Site,$Reason) = ($line =~ /discard: RCPT from ([^ ]*\[[^ ]*\]): ([^ ]*): ([^;]*);/)) {
        $self->data->{Discarded}{$Site}{$Reason}++;
    } elsif ( my (undef,undef,$Error) = ($line =~ /warning: ([^ ]*): hostname ([^ ]*) verification failed: (.*)$/)) {
        $self->data->{HostnameVerification}{$Error}++;
    } elsif ( $line =~ /^$re_MsgID: removed\s*$/) {
        $self->data->{RemovedFromQueue}++;
        #TD 2F38EE3341: enabling PIX <CRLF>.<CRLF> workaround for host.name[111.222.333.444]
        #TD 2A34C1123BC4: enabling PIX workarounds: disable_esmtp delay_dotcrlf for host.name[111.222.333.444]:25
    } elsif ( my ($Host) = ($line =~ /^$re_MsgID: enabling PIX (?:<CRLF>\.<CRLF> )?workaround(?:s: [a-z_, -]+)? for ([^ ]*\[[^ ]*\])(?::\d+)?$/)) {
        $self->data->{PixWorkaround}{$Host}++;
    } elsif ( my ($Message) = ($line =~ /warning: valid_hostname: (.*)$/)) {
        $self->data->{ValidHostname}{$Message}++;
    } elsif ( my ($Host,$Error) = ($line =~ /warning: host ([^ ]*\[[^ ]*\]) (greeted me with my own hostname [^ ]*)$/)) {
        $self->data->{HeloError}{$Error}{$Host}++;
    } elsif ( my ($Host,$Error) = ($line =~ /warning: host ([^ ]*\[[^ ]*\]) (replied to HELO\/EHLO with my own hostname [^ ]*)$/)) {
        $self->data->{HeloError}{$Error}{$Host}++;
    } elsif ( my ($Host,$Error) = ($line =~ /reject: RCPT from ([^ ]*\[[^ ]*\]): $re_DSN <.*>: (Helo command rejected: .*);/)) {
        $self->data->{HeloError}{$Error}{$Host}++;
    } elsif ( my ($Error,$Host) = ($line =~ /(bad size limit "\([^ ]*\)" in EHLO reply) from ([^ ]*\[[^ ]*\])$/)) {
        $self->data->{HeloError}{$Error}{$Host}++;
    } elsif ( my ($Host,$Command) = ($line =~ /warning: Illegal address syntax from ([^ ]*\[[^ ]*\]) in ([^ ]*) command:/)) {
        $self->data->{IllegalAddressSyntax}{$Command}{$Host}++;
    } elsif ( my ($Command,$Host) = ($line =~ /^improper command pipelining after ([^ ]*) from ([^ ]*\[[^ ]*\])/ )) {
        $self->data->{UnauthPipeline}{$Command}{$Host}++;
    } elsif ( my ($Error) = ($line =~ /warning: mailer loop: (.*)$/)) {
        $self->data->{MailerLoop}{$Error}++;
    } elsif ( my ($Host) = ($line =~ /warning: ([^ ]*\[[^ ]*\]): SASL .* authentication failed/)) {
        $self->data->{SaslAuthenticationFail}{$Host}++;
    } elsif (
      my ($Host,$User) = ($line =~ /^$re_MsgID: client=([^ ]*\[[^ ]*\]), .* sasl_username=([^ ]*)$/) or
      my ($Host,$User) = ($line =~ /^$re_MsgID: client=([^ ]*\[[^ ]*\]), sasl_sender=([^ ]*)$/) or
      my ($Host,$User) = ($line =~ /^$re_MsgID: client=([^ ]*\[[^ ]*\]), .* sasl_username=([^ ]*), sasl_sender=[^ ]*$/)
    ) {
        chomp($User);
        $self->data->{SaslAuth}{$Host}{$User}++;
    } elsif ( my ($Host) = ($line =~ /TLS connection established from ([^ ]*\[[^ ]*\]):/)) {
        $self->data->{TLSconnectFrom}{$Host}++;
    } elsif ( my ($Host) = ($line =~ /TLS connection established to ([^ ]*):/)) {
        $self->data->{TLSconnectTo}{$Host}++;
    } elsif ( my ($Cert) = ($line =~ /^Unverified: (.*)/)) {
        $self->data->{TLSunverified}{$Cert}++;
    } elsif ( my ($Domain) = ($line =~ /warning: malformed domain name in resource data of MX record (.*)$/)) {
        $self->data->{MxError}{$Domain}++;
    } elsif ( my ($Host,$Command) = ($line =~ /warning: ([^ ]*\[[^ ]*\]) sent .* header instead of ([^ ]*) command: /)) {
        my $Error = "Sent message header instead of $Command command";
        $self->data->{SmtpConversationError}{$Error}{$Host}++;
    } elsif (
      ($line =~ m/warning: smtp_connect_addr: socket: Address family not supported by protocol/) or
      ($line =~ m/warning: smtp_addr_one: unknown address family \d for [^ ]*/)
    ) {
        $self->data->{UnsupportedFamily}++;
    } elsif (
      ($line =~ m/(lookup |)table has changed -- exiting$/) or
      ($line =~ m/table ([^ ]*) has changed -- restarting$/)
    ) {
        $self->data->{TableChanged}++;
    } elsif (
      ($line =~ m/^fatal: [^ ]*\(\d+\): Message file too big$/) or
      ($line =~ m/^warning: $re_MsgID: queue file size limit exceeded$/) or
      ($line =~ m/^warning: uid=\d+: File too large$/)
    ) {
        $self->data->{QueueSizeExceeded}++;
    } elsif ( my ($Command,$Host) = ($line =~ /too many errors after ([^ ]*) from ([^ ]*\[[^ ]*\])$/)) {
        $self->data->{TooManyErrors}{$Command}{$Host}++;
    } elsif ( my (undef,undef,$To) = ($line =~ /^reject: RCPT from ([^ ]*\[[^ ]*\]): 552 Message size exceeds fixed limit; from=<([^ ]*)> to=<([^ ]*)>$/)) {
        $self->data->{SizeLimit}{"$From -> $To"}++;
    } elsif ( my ($Server) = ($line =~ /^NOQUEUE: reject: MAIL from ([^ ]*\[[^ ]*\]): 552 Message size exceeds fixed limit; proto=[^ ]* helo=<[^ ]*>$/)) {
        $self->data->{SizeLimit}{"MAIL from $Server"}++;
    } elsif ( my (undef,$Source) = ($line =~ /^warning: database ([^ ]*) is older than source file ([\w\/.-]+)$/)) {
        $self->data->{DatabaseGeneration}{$Source}++;
    } elsif ( my ($Reason) = ($line =~ /^warning: $re_MsgID: write queue file: (.*)$/)) {
        $self->data->{QueueWriteError}{$Reason}++;
    } elsif ( my ($Reason) = ($line =~ /^warning: open active $re_MsgID: (.*)$/)) {
        $self->data->{QueueWriteError}{"open active: $Reason"}++;
    } elsif ( my ($Reason) = ($line =~ /^warning: qmgr_active_corrupt: save corrupt file queue active id $re_MsgID: (.*)$/)) {
        $self->data->{QueueWriteError}{"active corrupt: $Reason"}++;
    } elsif ( my ($Reason) = ($line =~ /^warning: qmgr_active_done_3_generic: remove $re_MsgID: (.*)$/)) {
        $self->data->{QueueWriteError}{"remove active: $Reason"}++;
    } elsif ( my ($Reason) = ($line =~ /^warning: [^ ]*\/$re_MsgID: (Error writing message file)$/)) {
        $self->data->{MessageWriteError}{$Reason}++;
    } elsif ( $line =~ /reject: RCPT from [^ ]*\[[^ ]*\]: \d+ Insufficient system storage; from=<.*> to=<.*>/) {
        $self->data->{NoFreeSpace}++;
    } elsif ( my ($Process,$Status) = ($line =~ /^warning: process ([^ ]*) pid \d+ exit status (\d+)$/)) {
        $self->data->{ProcessExit}{$Status}{$Process}++;
    } elsif ( my ($Option,$Reason) = ($line =~ /^fatal: config variable ([^ ]*): (.*)$/)) {
        $self->data->{ConfigError}{$Option}{$Reason}++;
    } elsif ( my ($db,$Reason) = ($line =~ /fatal: open database (\S*): (.*)/) ) {
        $self->data->{Databases}{$db}{$Reason}++;
    } elsif ( my ($Warn) = ($line =~ /^warning: (.*)/)) {
        # keep this as the next to last condition
        $self->data->{UnknownWarnings}{$Warn}++;
    } else {
        push @{ $self->data->{OtherList} },$line;
    }
};

override 'get_output' => sub {
    my ($self) = @_;
    my $output = $self->process($self->data);
    return $output;
};

1;
