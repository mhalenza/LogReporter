package LogReporter::Service::Sudo;
use Moose;
extends 'LogReporter::Service';
use LogReporter::Util qw//;

has 'exec_detail'  => ( is => 'rw', isa => 'Int', required => 1, default => sub { 2; }, );

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
        ($line =~ /pam_unix\(sudo:session\): session (opened|closed) for user \S+/) or
        ($line =~ /\(command continued\)/)
    );
    
    if ( my ($from_user, $tty, $pwd, $to_user, $command) = ($line =~ /^(.+) : TTY=(.+) ; PWD=(.+) ; USER=(.+) ; COMMAND=(.+)$/) ){
        $d->{Exec}->{$from_user}{$to_user}{$command}++;
        $d->{Exec}->{$from_user}{$to_user}{XXX}++;
        $d->{Exec}->{$from_user}{XXX}++;
    }
    
    elsif ( my ($logname,$uid,$euid,$tty,$ruser,$rhost,$user) = ($line =~ /pam_unix\(sudo:auth\): authentication failure; logname=(\S*) uid=([0-9]*) euid=([0-9]*) tty=(\S*) ruser=(\S*) rhost=(\S*)  user=(\S*)/) ){
        $d->{AuthFail}->{"$user ($uid => $euid)"}++;
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
    
    printf "Sudo Invoked:\n";
    foreach my $from_user ( grep { !/^XXX/ } keys %{ $d->{Exec} } ){
        my $from_user_v = $d->{Exec}{$from_user};
        printf "  %3d  %s\n", $from_user_v->{XXX}, $from_user;
        
        next unless $self->exec_detail > 1;
        foreach my $to_user ( grep { !/^XXX/ } keys %$from_user_v ){
            my $to_user_v = $d->{Exec}{$from_user}{$to_user};
            printf "  %3d    %s\n", $to_user_v->{XXX}, $to_user;
            
            next unless $self->exec_detail > 2;
            foreach my $cmd ( grep { !/^XXX/ } keys %$to_user_v ){
                printf "  %3d      %s\n", $to_user_v->{$cmd}, $cmd;
            }
        }
    }
    
    p1($d,'AuthFail','Auth Failures');
    
    p1($d,'UNMATCHED',"\n**Unmatched Entries**");
};

sub p1 {
    my ($d,$key,$header) = @_;
    return unless exists $d->{$key};
    return unless ref($d->{$key}) eq 'HASH';
    return unless scalar(keys(%{$d->{$key}})) > 0;
    print "\n$header:\n";
    foreach my $ThisOne (sort keys %{ $d->{$key} }) {
        printf "  %3d  %s\n", $d->{$key}{$ThisOne}, $ThisOne;
    }
}


__PACKAGE__->meta->make_immutable;
1;
