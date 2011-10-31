package LogReporter::Service::OpenSSHd;
use Moose;
extends 'LogReporter::Service';
no warnings 'misc';
use LogReporter::Util qw/LookupIP/;

override init => sub {
    my ($self) = @_;
    super();
    $self->data->{UNMATCHED} = {};
};

override process_line => sub {
    my ($self, $line, $meta) = @_;
    my $d = $self->data;
    
    return if (
        ($line =~ /Disconnecting: Too many authentication failures for ([^ ]+)/)
    );
    
    if (
    ($line =~ m/^fatal: Connection closed by remote host\./ ) or
    ($line =~ m/^(|fatal: )Read error from remote host(| [^ ]+): Connection reset by peer/ ) or
    ($line =~ m/^Read error from remote host [^ ]+: (Connection timed out|No route to host)/ ) or
    ($line =~ m/^fatal: Read from socket failed: No route to host/) or
    ($line =~ m/^fatal: Write failed: Network is unreachable/ ) or
    ($line =~ m/^fatal: Write failed: Broken pipe/) or
    ($line =~ m/^channel \d+: open failed: (?:connect failed: Channel open failed\.|administratively prohibited: open failed)/) or
    ($line =~ m/^session_input_channel_req: no session \d+ req window-change/) or
    ($line =~ m/^error: chan_shutdown_read failed for .+/)
    ) {
        $d->{NetworkErrors}++;
    }
    elsif ( $line =~ m/^(log: )?Received (signal 15|SIG...); (terminating|restarting)\./) {
        $d->{Kills}++;
    }
    elsif ( $line =~ m/^(log: )?Server listening on( [^ ]+)? port \d+/ ) {
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
    
    elsif ( my ($Method,$User,$Host,$Port) = ($line =~ /^Accepted (\S+) for (\S+) from ([\d\.:a-f]+) port (\d+)/) ) {
        #if ($Detail >= 20) {
            $d->{Users}{$User}{$Host}{$Method}++;
        #} else {
        #    $d->{Users}{$User}{$Host}{"(all)"}++;
        #}
    }
    elsif ( my ($Method,$User,$Host,$Port) = ($line =~ /^Failed (\S+) for (?:illegal|invalid) user (.*) from ([^ ]+) port (\d+)/) ){
        #if ($Detail >= 20) {
            $d->{IllegalUsers}{$Host}{$User}{$Method}++;
        #} else {
        #    $d->{IllegalUsers}{$Host}{$User}{"(all)"}++;
        #}
    }
    
    elsif ( my ($User) = ($line =~ /^User ([^ ]*) from (?:[^ ]*) not allowed because not listed in AllowUsers/) ){
        $d->{AllowUsers}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User ([^ ]*)( from [0-9.]*)? not allowed because listed in DenyUsers/) ){
        $d->{DenyUsers}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User ([^ ]*)( from [0-9.]*)? not allowed because not in any group/) ){
        $d->{NoGroups}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User ([^ ]*)( from [^ ]*)? not allowed because a group is listed in DenyGroups/) ){
        $d->{DenyGroups}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User ([^ ]*) from ([^ ]*) not allowed because none of user's groups are listed in AllowGroups/) ){
        $d->{AllowGroups}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User ([^ ]*) not allowed because shell (\S+) does not exist/) ){
        $d->{NoShellUsers}{$User}++;
    }
    elsif ( my ($User) = ($line =~ /^User ([^ ]*) not allowed because shell (\S+) is not executable/) ){
        $d->{ShellNotExecutableUsers}{$User}++;
    }
    
    else {
        unless ($line =~ /fwd X11 connect/) {
            $d->{UNMATCHED}{$line}++;
        }
    }
};

override finalize => sub {
    my ($self) = @_;
    super();
};

override get_output => sub {
    my ($self) = @_;
    my $d = $self->data;
    
    printf "* SSHd starting %d times\n", $d->{Starts}
      if $d->{Starts};
    printf "* SSHd killed %d times\n", $d->{Kills}
      if $d->{Kills};
    printf "* SSHd network I/O errors %d times\n", $d->{NetworkErrors}
      if $d->{NetworkErrors};
    p1($d,'BindFailed','* Bind Failed:');
    
    print "\nUsers logging in through ssh:\n";
    my $USERS = $d->{Users};
    foreach my $user ( keys %$USERS ){
        my $user_v = $d->{Users}{$user};
        printf "  %s\n", $user;
        foreach my $host ( keys %$user_v ){
            my $host_v = $d->{Users}{$user}{$host};
            printf "    %s\n", $host;
            foreach my $method ( keys %$host_v ){
                printf "      %s : %d\n", $method, $host_v->{$method};
            }
        }
    }
    
    print "\nIllegal users from:\n";
    my $ILLEGAL_USERS = $d->{IllegalUsers};
    foreach my $host ( keys %$ILLEGAL_USERS ){
        my $host_v = $d->{IllegalUsers}{$host};
        printf "  %s\n", $host;
        foreach my $user ( keys %$host_v ){
            my $user_v = $d->{IllegalUsers}{$host}{$user};
            printf "    %s\n", $user;
            foreach my $method ( keys %$user_v ){
                printf "      %s : %d\n", $method, $user_v->{$method};
            }
        }
    }
    
    p1($d,'AllowUsers','Login attempted when not in AllowUsers list');
    p1($d,'DenyUsers','Login attempted when in DenyUsers list');
    p1($d,'AllowGroups','Login attempted when not in AllowGroups list');
    p1($d,'DenyGroups','Login attempted when in DenyGroups list');
    p1($d,'NoGroups','Login attempted when user is in no group');
    p1($d,'','Login attempted when shell does not exist');
    p1($d,'','Login attempted when shell is not executable');
    
    
    
    
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
