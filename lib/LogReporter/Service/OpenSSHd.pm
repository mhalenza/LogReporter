package LogReporter::Service::OpenSSHd;
use Moose;
extends 'LogReporter::Service';
no warnings 'misc';
use LogReporter::Util qw/SortIP LookupIP schwartz schwartzn/;

override init => sub {
    my ($self) = @_;
    super();
    $self->data->{UNMATCHED} = {};
};

override process_line => sub {
    my ($self, $line, $meta) = @_;
    my $data = $self->data;
    
    return if (
        ($line =~ /^pam_succeed_if: requirement "uid < 100" (not|was) met by user /) or
        ($line =~ m/^(log: )?$/ ) or
        ($line =~ m/^(log: )?\^\[\[60G/ ) or
        ($line =~ m/^(log: )? succeeded$/ ) or
        ($line =~ m/^(log: )?Closing connection to/) or
        ($line =~ m/^(log: )?Starting sshd:/ ) or
        ($line =~ m/^(log: )?sshd \-TERM succeeded/ ) or
        ($line =~ m/^Bad protocol version identification .*:? [\d.]+/ ) or
        ($line =~ m/^Bad protocol version identification.*Big-Brother-Monitor/ ) or
        ($line =~ m/^Connection closed by/) or
        ($line =~ m/^Disconnecting: Command terminated on signal \d+/) or
        ($line =~ m/^Disconnecting: server_input_channel_req: unknown channel -?\d+/) or
        ($line =~ m/^connect from \d+\.\d+\.\d+\.\d+/) or
        ($line =~ m/^fatal: Timeout before authentication/ ) or
        ($line =~ m/Connection from .* port /) or
        ($line =~ m/Postponed (keyboard-interactive|publickey) for [^ ]+ from [^ ]+/) or
        ($line =~ m/Read from socket failed/) or
        ($line =~ m/sshd startup\s+succeeded/) or
        ($line =~ m/sshd shutdown\s+succeeded/) or
        ($line =~ m/^Found matching [DR]SA key: /) or
        ($line =~ m/^error: key_read: type mismatch: encoding error/) or
        ($line =~ m/^channel_lookup: -?\d+: bad id/) or
        ($line =~ m/^error: channel \d+: chan_read_failed for istate/) or
        # Result of setting PermitRootLogin to forced-commands-only
        ($line =~ m/^Root login accepted for forced command.$/) or
        # usually followed by a session opened for user
        ($line =~ m/^pam_krb5\[\d+\]: authentication succeeds for /) or
        ($line =~ m/^nss_ldap: reconnect/) or
        ($line =~ m/^pam_ldap: error trying to bind as user "[^"]+" \(Invalid credentials\)/) or
        ($line =~ m/^pam_ldap: ldap_starttls_s: Can't contact LDAP server/) or
        ($line =~ m/^\(pam_unix\) .*/) or
        ($line =~ m/^pam_unix\(.*:.*\)/) or
        ($line =~ m/^pam_unix_auth:/) or
        ($line =~ /pam_krb5: authentication succeeds for `([^ ]*)'/) or
        ($line =~ /pam_succeed_if\(.*:.*\): error retrieving information about user [a-zA-Z]*/ ) or
        ($line =~ /pam_winbind\(sshd:account\): user .* granted access/) or
        ($line =~ /pam_winbind\(sshd:account\): user .* OK/) or
        ($line =~ /PAM \d+ more authentication failures?;/) or
        ($line =~ /^Failed keyboard-interactive for <invalid username> from/ ) or
        ($line =~ /^Keyboard-interactive \(PAM\) userauth failed/ ) or
        ($line =~ /^debug1: /) or
        ($line =~ /Nasty PTR record .* is set up for [\da-fA-F.:]+, ignoring/) or 
        ($line =~ /^(log: )?Generating .* \w+ key\./) or
        ($line =~ m/^packet_set_maxsize: /) or 
        ($line =~ m/^(log: )?\w+ key generation complete\./)
    );
    

    if ( my ($Method,$User,$Host,$Port) = ($line =~ /^Accepted (\S+) for (\S+) from ([\d\.:a-f]+) port (\d+)/) ){
        #if ($Detail >= 20) {
            $data->{Users}{$User}{$Host}{$Method}++;
        #} else {
        #    if ( $Host !~ /$IgnoreHost/ ) {
        #        $data->{Users}{$User}{$Host}{"(all)"}++;
        #    }
        #}
    }
    elsif ( my ($Method,$User,$Host,$Port) = ($line =~ m/^Failed (\S+) for (?:illegal|invalid) user (.*) from ([^ ]+) port (\d+)/) ){
        $data->{IllegalUsers}{$Host}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /Disconnecting: Too many authentication failures for ([^ ]+)/) ){
        $data->{TooManyFailures}{$User}++;
    }
    elsif ( $line =~ m/^(fatal: )?Did not receive ident(ification)? string from (.+)/ ){
        my $name = LookupIP($3);
        $data->{NoIdent}{$name}++;
    }
    elsif ( my ($Host) = ($line =~ /Could not write ident string to ([^ ]+)$/ ) ){
        my $name = LookupIP($Host);
        $data->{NoIdent}{$name}++;
    }
    elsif (
    ($line =~ m/^fatal: Connection closed by remote host\./ ) or
    ($line =~ m/^(|fatal: )Read error from remote host(| [^ ]+): Connection reset by peer/ ) or
    ($line =~ m/^Read error from remote host [^ ]+: (Connection timed out|No route to host)/ ) or
    ($line =~ m/^fatal: Read from socket failed: No route to host/) or
    ($line =~ m/^fatal: Write failed: Network is unreachable/ ) or
    ($line =~ m/^fatal: Write failed: Broken pipe/) or
    ($line =~ m/^channel \d+: open failed: (?:connect failed: Channel open failed\.|administratively prohibited: open failed)/) or
    ($line =~ m/^session_input_channel_req: no session \d+ req window-change/) or
    ($line =~ m/^error: chan_shutdown_read failed for .+/)
    ){
        $data->{NetworkErrors}++;
    }
    elsif ( $line =~ m/^(log: )?Received (signal 15|SIG...); (terminating|restarting)\./ ){
        $data->{Kills}++;
    }
    elsif ( $line =~ m/^(log: )?Server listening on( [^ ]+)? port \d+/ ){
        $data->{Starts}++;
    }
    elsif ( my ($Port,$Address,$Reason) = ($line =~ /^error: Bind to port ([^ ]+) on ([^ ]+) failed: (.+).$/ ) ){
        my $Temp = "$Address port $Port ($Reason)";
        # Failed to bind on 0.0.0.0 likely due to configured "ListenAddress"
        # on both IPv4 and IPv6
        unless ($Address =~ /^0.0.0.0$/) {
            $data->{BindFailed}{$Temp}++;
        }
    }
    
    elsif ( my ($Method,$User,$Host,$Port) = ( $line =~ m/^Failed (\S+) for (\S+) from ([^ ]+) port (\d+)/ ) ){
        $data->{BadLogins}{$Host}{"$User/$Method"}++;
    }
    elsif ( $line =~ s/^(log: )?Could not reverse map address ([^ ]*).*$/$2/ ){
        $data->{NoRevMap}{$line}++;
    }
    elsif ( my ($Address) = ($line =~ /^reverse mapping checking getaddrinfo for (\S+( \[\S+\])?) failed - POSSIBLE BREAK-IN ATTEMPT!/) ){
        $data->{NoRevMap}{$Address}++;
    }
    elsif ( my ($IP,$Address) = ($line =~ /^Address ([^ ]*) maps to ([^ ]*), but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!/) ){
        $data->{NoRevMap}{"$Address($IP)"}++;
    }
    elsif ( my ($Address) = ($line =~ /^warning: (?:[^ ]*), line \d+: can't verify hostname: getaddrinfo\(([^ ]*), AF_INET\) failed$/) ){
        $data->{NoRevMap}{$Address}++;
    }
    elsif ( my ($Addresses) = ($line =~ /^warning: (?:[^ ]*), line \d+: host [^ ]* mismatch: (.*)$/) ){
        $data->{MisMatch}{$Addresses}++;
    }
    elsif ( $line =~ m/subsystem request for sftp/ ){
        $data->{sftpRequests}++;
    }
    elsif ( $line =~ m/refused connect from (.*)$/ ){
        $data->{RefusedConnections}{$1}++;
    }
    elsif ( my ($Reason) = ($line =~ /^Authentication refused: (.*)$/ ) ){
        $data->{RefusedAuthentication}{$Reason}++;
    }
    elsif ( my ($Host,$Reason) = ($line =~ /^Received disconnect from ([^ ]*): (.*)$/) ){
        $data->{DisconnectReceived}{$Reason}{$Host}++;
    }
    elsif ( my ($Host) = ($line =~ /^ROOT LOGIN REFUSED FROM ([^ ]*)$/) ){
        $data->{RootLogin}{$Host}++;
    }
    elsif ( my ($Error) = ($line =~ /^Cannot release PAM authentication\[\d\]: (.*)$/) ){
        $data->{PamReleaseFail}{$Error}++;
    }
    elsif ( my ($Error) = ( $line =~ m/^error: PAM: (.*)$/) ){
        $data->{PamError}{$Error}++;
    }
    elsif ( my ($Reason) = ( $line =~ m/pam_chroot\(.+\):\s+([^:])/) ){
        $data->{PamChroot}{$Reason}++;
    }
    elsif ( my ($Error) = ( $line =~ m/^error: Could not get shadow information for (.*)$/) ){
        $data->{ShadowInfo}{$Error}++;
    }
    elsif ( my ($Reason) = ($line =~ /^Setting tty modes failed: (.*)$/) ){
        $data->{TTYModesFail}{$Reason}++;
    }
    elsif ( my ($User,) = ($line =~ /^User ([^ ]*) not allowed because (?:[^ ]*) exists$/) ){
        $data->{LoginLock}{$User}++;
    }
    elsif ( my ($Method,$InvaUser,$IlegUser,$EmptyUser,$User,$Host) = ($line =~ /^Postponed ([^ ]*) for ((invalid user) [^ ]*|(illegal user) [^ ]*|([^ ]*)) from ([^ ]*) port \d+ ssh/) ){
        $data->{PostPonedAuth}{"$User/$Method"}{$Host}++;
        if ($IlegUser =~ /illegal user/) {
            $data->{IllegalUsers}{$Host}{$User}++;
        }
    }
    elsif ( my ($User) = ($line =~ /^User ([^ ]*) not allowed because account is locked/ ) ){
        $data->{LockedAccount}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User ([^ ]*) from (?:[^ ]*) not allowed because not listed in AllowUsers/) ){
        $data->{AllowUsers}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User ([^ ]*)( from [0-9.]*)? not allowed because listed in DenyUsers/) ){
        $data->{DenyUsers}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User ([^ ]*)( from [0-9.]*)? not allowed because not in any group/) ){
        $data->{NoGroups}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User ([^ ]*)( from [^ ]*)? not allowed because a group is listed in DenyGroups/) ){
        $data->{DenyGroups}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User ([^ ]*) from ([^ ]*) not allowed because none of user's groups are listed in AllowGroups/) ){
        $data->{AllowGroups}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User ([^ ]*) not allowed because shell (\S+) does not exist/) ){
        $data->{NoShellUsers}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User ([^ ]*) not allowed because shell (\S+) is not executable/) ){
        $data->{ShellNotExecutableUsers}{$User}++;
    }
    elsif ( my ($IP) = ($line =~ /^scanned from ([^ ]*)/) ){
        push @{ $data->{Scanned} }, $IP;
    }
    elsif ( my ($Line,$Option) = ($line =~ /^rexec line (\d+): Deprecated option (.*)$/) ){
        $data->{DeprecatedOption}{"$Option - line $Line"}++;
    }
    elsif ( my ($Pom1,$Pom2,$User) = ($line =~ /pam_krb5(\[\d*\])?: authentication fails for (`|')([^ ]*)'/) ){
        $data->{KrbAutFail}{$User}++;
    }
    elsif ( my ($Error) = ($line =~ /pam_krb5: authenticate error: (.*)$/) ){
        $data->{KrbAutErr}{$Error}++;
    }
    elsif ( $line =~ /pam_krb5: unable to determine uid\/gid for user$/ ){
        $data->{KrbAutErr}{"unable to determine uid/gid for user"}++;
    }
    elsif ( my ($Error) = ($line =~ /pam_krb5: error removing file (.*)$/) ){
        $data->{KrbErr}{"error removing file " . $Error}++;
    }
    elsif ( my ($Pom,$Error) = ($line =~ /pam_krb5(\[\d*\]): error resolving user name '[^ ]*' to uid\/gid pai/) ){
        $data->{KrbErr}{"error resolving user name '$Error' to uid\/gid pai"}++;
    }
    elsif ( my ($User,$Host) = ($line =~ m/^(?:Illegal|Invalid) user (.*) from ([^ ]+)/ ) ){
        $data->{PotentialIllegalUsers}{$Host}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^input_userauth_request: (?:illegal|invalid) user (.*)$/ ) ){
        $data->{PotentialIllegalUsers}{"undef"}{$User}++;
    }
    elsif ( my ($File,$Perm,$Why) = ($line =~ /error: chmod (.*) (.*) failed: (.*)/) ){
        $data->{ChmodErr}{"$File,$Perm,$Why"}++;
    }
    elsif ( my ($File,$From,$To,$Why) = ($line =~ /error: chown (.*) (.*) (.*) failed: (.*)/) ){
        $data->{ChownErr}{"$File,$From,$To,$Why"}++;
    }
    elsif ( my ($user,$relm) = ($line =~ /Authorized to ([^ ]+), krb5 principal \1@([^ ]+) \(krb5_kuserok\)/) ){
        $data->{Krb_relm}{$relm}{$user}++;  
    }
    else {
        unless ($line =~ /fwd X11 connect/) {
            $data->{UNMATCHED}{$line}++;
        }
    }
};

override finalize => sub {
    my ($self) = @_;
    super();
    #foreach my $Host (keys %PotentialIllegalUsers) {
    #    foreach my $User (keys %{$PotentialIllegalUsers{$Host}}) {
    #        while ($IllegalUsers{$Host}{$User} < $PotentialIllegalUsers{$Host}{$User}) {
    #            $IllegalUsers{$Host}{$User}++;
    #        }
    #    }
    #}
};

override get_output => sub {
    my ($self) = @_;
    my $d = $self->data;
    
    if ($d->{NetworkErrors}) {
       print "*Network Read Write Errors: " . $d->{NetworkErrors} . "\n";
    }
    if ($d->{Kills}) {
       print "*SSHD Killed: " . $d->{Kills} . " Time(s)\n";
    }
    if ($d->{Starts}) {
       print "*SSHD Started: " . $d->{Starts} . " Time(s)\n";
    }
    
    if ( keys %{ $d->{DeprecatedOption} } ) {
        print "*Deprecated options in SSH config:\n";
        foreach my $Option (sort {$a cmp $b} keys %{ $d->{DeprecatedOption} }) {
            print "    $Option\n";
        }
    }
    
    p1($d,'RootLogin',"\nWARNING!!!\nRefused ROOT login attempt from");
    p1($d,'BindFailed',"Failed to bind");
    p1($d,'NoRevMap',"Couldn't resolve these IPs");
    p1($d,'NoIdent',"Didn't receive an ident from these IPs");
    p1($d,'MisMatch',"Mismatched host names and/or IPs");
    
    #if ($#BadRSA >= 0) {
    #    print "\nReceived a bad response to RSA challenge from:\n";
    #    foreach my $ThisOne (@BadRSA) {
    #        print "   $ThisOne\n";
    #    }
    #}
    
    p1($d,'TooManyFailures',"Disconnecting after too many authentication failures for user");
    
    if (keys %{ $d->{BadLogins} }) {
        print "\nFailed logins from:\n";
        foreach my $ip (sort SortIP keys %{ $d->{BadLogins} }) {
            my $name = LookupIP($ip);
            my $totcount = 0;
            foreach my $user (keys %{ $d->{BadLogins}{$ip} }) {
                $totcount += $d->{BadLogins}{$ip}{$user};
            }
            printf "    %s : %d time(s)\n", $name, $totcount;
            #if ($Detail >= 5) {
                foreach my $user (reverse schwarzn { $d->{BadLogins}{$_} } keys %{ $d->{BadLogins}{$ip} } ){
                    printf "        %s : %d time(s)\n", $user, $d->{BadLogins}{$ip}{$user};
                }
            #}
        }
    }
    
#    if (keys %IllegalUsers) {
#        print "\nIllegal users from:\n";
#        foreach my $ip (sort SortIP keys %IllegalUsers) {
#            my $name = LookupIP($ip);
#            my $totcount = 0;
#            foreach my $user (keys %{$IllegalUsers{$ip}}) {
#                $totcount += $IllegalUsers{$ip}{$user};
#            }
#            my $plural = ($totcount > 1) ? "s" : "";
#            print "   $name: $totcount time$plural\n";
#            if ($Detail >= 5) {
#                my $sort = CountOrder(%{$IllegalUsers{$ip}});
#                foreach my $user (sort $sort keys %{$IllegalUsers{$ip}}) {
#                    my $val = $IllegalUsers{$ip}{$user};
#                    my $plural = ($val > 1) ? "s" : "";
#                    print "      $user: $val time$plural\n";
#                }
#            }
#        }
#    }
    
    p1($d,'LockedAccount',"Locked account login attempts");
    p1($d,'AllowUsers',"Login attempted when not in AllowUsers list");
    p1($d,'DenyUsers',"Login attempted when in DenyUsers list");
    p1($d,'AllowGroups',"Login attempted when not in AllowGroups list");
    p1($d,'DenyGroups',"Login attempted when in DenyGroups list");
    p1($d,'NoGroups',"Login attempted when user is in no group");
    p1($d,'NoShellUsers',"Login attempted when shell does not exist");
    p1($d,'ShellNotExecutableUsers',"Login attempted when shell is not executable");
    p1($d,'LoginLock',"User login attempt when nologin was set");
    
#    if (keys %PostPonedAuth) {
#        print "\nPostponed authentication:\n";
#        foreach my $User (sort {$a cmp $b} keys %PostPonedAuth) {
#            print "   $User:\n";
#            foreach my $Host (sort {$a cmp $b} keys %{$PostPonedAuth{$User}}) {
#                print "      $Host: $PostPonedAuth{$User}{$Host} Time(s)\n";
#            }
#        }
#    }
    
    if (keys %{ $d->{Users} }) {
        print "\nUsers logging in through sshd:\n";
        foreach my $user (sort {$a cmp $b} keys %{ $d->{Users} }) {
            print "  $user:\n";
            foreach my $ip (reverse schwartzn { my $t; $t += $d->{Users}{$user}{$_} for keys %{ $d->{Users}{$user}}; $t } keys %{ $d->{Users}{$user} } ){
            # That's just a really long way to mean sort $d->{Users}{$user} by the total number of logins for that user.
                my $name = LookupIP($ip);
                #if ($Detail >= 20) {
                    print "    $name:\n";
                    foreach my $method ( reverse schwartzn { $d->{Users}{$user}{$ip}{$_} } keys %{ $d->{Users}{$user}{$ip} } ){
                        my $val = $d->{Users}{$user}{$ip}{$method};
                        printf "      %s: %d time(s)\n",$method, $val;
                    }
                #} else {
                #    my $val = (values %{ $d->{Users}{$user}{$ip}})[0];
                #    printf "      %s: $d\n", $name, $val;
                #}
            }
        }
    }
    
    p1($d,'RefusedAuthentication',"Authentication refused");
    p1($d,'KrbAutFail',"Failed pam_krb5 authentication");
    p1($d,'KrbAutErr',"pam_krb5 authentication errors");
    p1($d,'KrbErr',"pam_krb5 errors");
    
    
    if (keys %{ $d->{DisconnectReceived} }) {
        print "\nReceived disconnect:\n";
        foreach my $Reason (sort {$a cmp $b} keys %{ $d->{DisconnectReceived} }) {
            my $Total = 0;
            print "  $Reason\n";
            foreach my $Host (sort {$a cmp $b} keys %{ $d->{DisconnectReceived}{$Reason} }) {
                $Total += $d->{DisconnectReceived}{$Reason}{$Host};
                #if( $Detail > 0 ) {
                    printf "%s%s: $d Time(s)\n", " "x2, $Host, $d->{DisconnectReceived}{$Reason}{$Host}
                #}
            }
            #if( $Detail > 0 ) {
                print "\n";
            #} else {
            #    print " : $Total Time(s)\n";
            #}
        }
    }
    
#    if ($#Scanned >= 0) {
#        print "\nScanned from:\n";
#        foreach my $ThisOne (sort SortIP @Scanned) {
#            print "   " . LookupIP($ThisOne) . "\n";
#        }
#    }
    
#    if (keys %{ $d->{RefusedConnections} }) {
#        my $output;
#        foreach my $badguy (sort {$a cmp $b} keys %{ $d->{RefusedConnections} }) {
#            if ($RefusedConnectionsThreshold == 0 ||
#                $Detail > 5 ||
#                $d->{RefusedConnections}{$badguy} >= $RefusedConnectionsThreshold
#            ){
#                $output .= "      $badguy: " . $RefusedConnections{$badguy} . " Time(s)\n";
#            }
#        }
#        if ($output ne '') {
#            print "\nRefused incoming connections:\n";
#            print $output;
#        }
#    }
    
    p1($d,'PamReleaseFail',"Cannot release PAM authentication");
    p1($d,'ShadowInfo',"Could not get shadow information for");
    p1($d,'PamError',"Error in PAM authentication");
    p1($d,'PamChroot',"PAM chroot");
    p1($d,'TTYModesFail',"Setting tty modes failed");
    p1($d,'',"");
    
#    if ($sftpRequests > 0) {
#        print "\nSFTP subsystem requests: $sftpRequests Time(s)\n";
#    }
    
    if (keys %{ $d->{ChmodErr} }) {
        print "Chmod errors:\n";
        foreach (keys %{ $d->{ChmodErr} }) {
            my ($File,$Perm,$Why)= split ",";
            printf "  %s %s failed(%s): %s Time(s)\n", $File,$Perm,$Why, $d->{ChmodErr}{"$File,$Perm,$Why"};
        }
    }
    
    if (keys %{ $d->{ChownErr} }) {
        print "Chmod errors:\n";
        foreach (keys %{ $d->{ChownErr} }) {
            my ($File,$Perm,$Why)= split ",";
            printf "  %s %s failed(%s): %s Time(s)\n", $File,$Perm,$Why, $d->{ChownErr}{"$File,$Perm,$Why"};
        }
    }
    
#    if ( ($Detail == 7 && keys %Krb_relm > 1) || ($Detail > 8 && keys %Krb_relm) ){
#        print "\nSucessfull Kerberos Authentication from ",(scalar keys %Krb_relm)," relm:\n";
#        foreach my $relm (keys %Krb_relm) { 
#            if($Detail > 9){
#                print "   ",$relm,":\n";
#                foreach my $user(keys %{$Krb_relm{$relm}}){
#                    print "     ",$user,": ". $Krb_relm{$relm}{$user} . " Times(s)\n";
#                }
#            } else {
#                print "   ",$relm,": ". (scalar keys %{$Krb_relm{$relm}}) . " User(s)\n";
#            }
#        }
#    }
    
    p1($d,'UNMATCHED',"\n**Unmatched Entries**");
};

sub p1 {
    my ($d,$key,$header) = @_;
    return unless exists $d->{$key};
    return unless ref($d->{$key}) eq 'HASH';
    print "\n$header:\n";
    foreach my $ThisOne (sort keys %{ $d->{$key} }) {
        printf "  %s : %d Time(s)\n", $ThisOne, $d->{$key}{$ThisOne};
    }
}


__PACKAGE__->meta->make_immutable;
1;
