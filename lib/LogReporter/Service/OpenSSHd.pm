package LogReporter::Service::OpenSSHd;
use Moose;
extends 'LogReporter::Service';
no warnings 'misc';
use LogReporter::Util qw/LookupIP SortIP/;

has 'logins_detail'  => ( is => 'rw', isa => 'Int', required => 1, default => sub { 2; }, );
has 'illegal_detail' => ( is => 'rw', isa => 'Int', required => 1, default => sub { 1; }, );
has 'failed_detail'  => ( is => 'rw', isa => 'Int', required => 1, default => sub { 3; }, );


override init => sub {
    my ($self) = @_;
    super();
    $self->data->{UNMATCHED} = {};
};

override process_line => sub {
    my ($self, $line, $meta) = @_;
    my $d = $self->data;
    return unless super();
    
    return if (
        ($line =~ /Disconnecting: Too many authentication failures for (\S+)/) or
        ($line =~ /fwd X11 connect/) or
        ($line =~ /Connection closed by (.+)(?: \[preauth\])?/) or
        ($line =~ /Received disconnect from (.+): (.+)(?: \[preauth\])?/) or
        ($line =~ /Invalid verification code/) or
        ($line =~ /\QTrying to reuse a previously used time-based code. Retry again in \E\d+\Q seconds. Warning! This might mean, you are currently subject to a man-in-the-middle attack.\E/)
    );
    
    if (
    ($line =~ m/^fatal: Connection closed by remote host\./) or
    ($line =~ m/^(|fatal: )Read error from remote host(| [^ ]+): Connection reset by peer/) or
    ($line =~ m/^Read error from remote host [^ ]+: (Connection timed out|No route to host)/) or
    ($line =~ m/^fatal: Read from socket failed: No route to host/) or
    ($line =~ m/^fatal: Read from socket failed: Connection reset by peer(?: \[preauth\])?/) or
    ($line =~ m/^fatal: Write failed: Network is unreachable/) or
    ($line =~ m/^fatal: Write failed: Broken pipe/) or
    ($line =~ m/^channel \d+: open failed: (?:connect failed: Channel open failed\.|administratively prohibited: open failed)/) or
    ($line =~ m/^session_input_channel_req: no session \d+ req window-change/) or
    ($line =~ m/^error: chan_shutdown_read failed for .+/) or
    ($line =~ m/^error: ssh_msg_send: .+/) or
    ($line =~ m/^pam_unix\(.*:.*\)/) or
    ($line =~ m/^pam_unix_session\(.*:.*\)/) 
    ){
        $d->{NetworkErrors}++;
    }
    elsif ( ($line =~ m/^(log: )?Received (signal 15|SIG...); (terminating|restarting)\./) ){
        $d->{Kills}++;
    }
    elsif ( ($line =~ m/^(log: )?Server listening on( [^ ]+)? port \d+/) ){
        $d->{Starts}++;
    }
    elsif ( my ($Port,$Address,$Reason) = ($line =~ /^error: Bind to port ([^ ]+) on ([^ ]+) failed: (.+).$/) ){
        my $Temp = "$Address port $Port ($Reason)";
        # Failed to bind on 0.0.0.0 likely due to configured "ListenAddress"
        # on both IPv4 and IPv6
        unless ($Address =~ /^0.0.0.0$/) {
            $d->{BindFailed}{$Temp}++;
        }
    }
    
    elsif ( my ($Method,$User,$Host,$Port) = ($line =~ /^Accepted (\S+) for (\S+) from ([\d\.:a-f]+) port (\d+)/) ){
            $d->{Users}{$User}{$Host}{$Method}++;
            $d->{Users}{$User}{$Host}{XXX}++;
            $d->{Users}{$User}{XXX}++;
    }
    elsif ( my ($Method,$User,$Host,$Port) = ($line =~ /^Failed (\S+) for (?:illegal|invalid) user (.*) from ([^ ]+) port (\d+)/) ){
            $d->{IllegalUsers}{$Host}{$User}{$Method}++;
            $d->{IllegalUsers}{$Host}{$User}{XXX}++;
            $d->{IllegalUsers}{$Host}{XXX}++;
    }
    elsif ( 
    ($line =~ /^Invalid user (.*) from (.+)/) or
    ($line =~ /^input_userauth_request: invalid user (.*) \[preauth\]/) or
    ($line =~ /^error: PAM: Authentication failure for illegal user (.*) from (.+)/) or
    ($line =~ /^Postponed (.+) for invalid user (.*) from (.+) port (\d+) ssh2 \[preauth\]/) or
    ($line =~ /^error: PAM: User not known to the underlying authentication module for illegal user (.*) from (.+)/)
    ){
        # Ignore these since the invalid login will be caught by the previous elsif block
    }
    
    elsif( my ($Method,$User,$Host,$Port) = ($line =~ /Failed (.+) for (.+) from (.+) port (\d+) ssh2/) ){
        $d->{FailedLogins}{$User}{$Host}{$Method}++;
        $d->{FailedLogins}{$User}{$Host}{XXX}++;
        $d->{FailedLogins}{$User}{XXX}++;
    }
    elsif(
    ($line =~ /error: PAM: Authentication failure for (.+) from (.+)/) or
    ($line =~ /Postponed (.+) for (.+) from (.+) port (\d+) ssh2 \[preauth\]/)
    ){
        # Ignore these since the failed login will be caught by the previous elsif block
    }
    
    elsif ( my ($User) = ($line =~ /^User (\S*) from (\S*) not allowed because not listed in AllowUsers/) ){
        $d->{AllowUsers}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User (\S*) from (\S*) not allowed because listed in DenyUsers/) ){
        $d->{DenyUsers}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User (\S*) from (\S*) not allowed because not in any group/) ){
        $d->{NoGroups}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User (\S*) from (\S*) not allowed because a group is listed in DenyGroups/) ){
        $d->{DenyGroups}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User (\S*) from (\S*) not allowed because none of user's groups are listed in AllowGroups/) ){
        $d->{AllowGroups}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User (\S*) not allowed because shell (\S+) does not exist/) ){
        $d->{NoShellUsers}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User (\S*) not allowed because shell (\S+) is not executable/) ){
        $d->{ShellNotExecutableUsers}{$User}++;
    }
    
    elsif ( ($line =~ /^(fatal: )?Did not receive ident(ification)? string from (.+)/) ){
        my $name = LookupIP($3);
        $d->{NoIdent}{$name}++;
    }
    elsif ( my ($Host) = ($line =~ /Could not write ident string to ([^ ]+)$/) ){
        my $name = LookupIP($Host);
        $d->{NoIdent}{$name}++;
    }
    
    elsif( ($line =~ /^Address (?<i>.+) maps to (?<h>.+), but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!/) or 
           ($line =~ /^reverse mapping checking getaddrinfo for (?<h>.+) \[(?<i>.+)\] failed - POSSIBLE BREAK-IN ATTEMPT!/)
    ){
        my ($fw,$rv) = @+{'i','h'};
        $d->{FwRevCheck}{$fw}{$rv}++;
    }
    
    else {
        $d->{UNMATCHED}{$line}++;
    }
};

override finalize => sub {
    my ($self) = @_;
    super();
};

override get_output => sub {
    my ($self) = @_;
    my $d = $self->data;
    
    p1($d,'Starts','* SSHd started:');
    p1($d,'Kills','* SSHd killed:');
    p1($d,'NetworkErrors','* Network I/O errors:');
    p1($d,'BindFailed','* Bind Failed:');
    
    print "\nUsers logging in through ssh:\n";
    foreach my $user ( sort grep { !/^XXX/ } keys %{ $d->{Users} } ){
        my $user_v = $d->{Users}{$user};
        printf "  %3d  %s\n", $user_v->{XXX}, $user;
        next unless $self->logins_detail > 1;
        foreach my $host ( grep { !/^XXX/ } keys %$user_v ){
            my $host_v = $d->{Users}{$user}{$host};
            printf "  %3d    %s\n", $host_v->{XXX}, $host;
            next unless $self->logins_detail > 2;
            foreach my $method ( sort grep { !/^XXX/ } keys %$host_v ){
                printf "  %3d      %s\n", $host_v->{$method}, $method;
            }
        }
    }
    
    print "\nIllegal users from:\n";
    foreach my $host ( grep { !/^XXX/ } keys %{ $d->{IllegalUsers} } ){
        my $host_v = $d->{IllegalUsers}{$host};
        printf "  %3d  %s\n", $host_v->{XXX}, $host;
        next unless $self->illegal_detail > 1;
        foreach my $user ( sort SortIP grep { !/^XXX/ } keys %$host_v ){
            my $user_v = $d->{IllegalUsers}{$host}{$user};
            printf "  %3d    %s\n", $user_v->{XXX}, $user;
            next unless $self->illegal_detail > 2;
            foreach my $method ( grep { !/^XXX/ } keys %$user_v ){
                printf "  %3d      %s\n", $user_v->{$method}, $method;
            }
        }
    }
    
    print "\nFailed Logins through ssh:\n";
    foreach my $user ( sort grep { !/^XXX/ } keys %{ $d->{FailedLogins} } ){
        my $user_v = $d->{FailedLogins}{$user};
        printf "  %3d  %s\n", $user_v->{XXX}, $user;
        next unless $self->failed_detail > 1;
        foreach my $host ( sort SortIP grep { !/^XXX/ } keys %$user_v ){
            my $host_v = $d->{FailedLogins}{$user}{$host};
            printf "  %3d    %s\n", $host_v->{XXX}, $host;
            next unless $self->failed_detail > 2;
            foreach my $method ( sort grep { !/^XXX/ } keys %$host_v ){
                printf "  %3d      %s\n", $host_v->{$method}, $method;
            }
        }
    }
    
    p1($d,'AllowUsers','Login attempted when not in AllowUsers list');
    p1($d,'DenyUsers','Login attempted when in DenyUsers list');
    p1($d,'AllowGroups','Login attempted when not in AllowGroups list');
    p1($d,'DenyGroups','Login attempted when in DenyGroups list');
    p1($d,'NoGroups','Login attempted when user is in no group');
    p1($d,'NoShellUsers','Login attempted when shell does not exist');
    p1($d,'ShellNotExecutableUsers','Login attempted when shell is not executable');
    
    p1($d,'NoIdent','Didn\'t receive an ident from these IPs');
    
    
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
