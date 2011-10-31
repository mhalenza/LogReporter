package LogReporter::Service::NamedQuery;
use Moose;
extends 'LogReporter::Service';
no warnings 'misc';
use LogReporter::Util qw/SortIP/;

our $RE_IP = '(?:(?:::(?:ffff:|FFFF:)?)?(?:\d{1,3}\.){3}\d{1,3}|(?:[\da-fA-F]{0,4}:){2}(?:[\da-fA-F]{0,4}:){0,5}[\da-fA-F]{0,4})';

override init => sub {
    my ($self) = @_;
    super();
    my $data = $self->data;
    $data->{'UNMATCHED'} = {};
};

override process_line => sub {
    my ($self, $line, $meta) = @_;

#    return if (
#    );
    
    # client 93.152.160.50#51589: query: msk4.com IN MX - (66.228.55.174)
    # client 216.106.233.1#63784: query: crl.microsoft.com IN A + (66.228.55.174)
    # client 216.106.233.1#13038: query: crl.microsoft.com IN AAAA + (66.228.55.174)
    # client 221.130.32.164#39729: query: lI01.mSk4.cOm IN AAAA -ED (66.228.55.174)
#    if ( $line =~ /client ([^#]+)#(\d+): query: (.+) ([+-]\w*) \(([^)]+)\).*?$/ ){
    if ( $line =~ /client ([^#]+)#(\d+): query: (.+) IN (\w+) ([+-]\w*) \(([^)]+)\).*?$/ ){
        my ($client_ip, $client_port, $query_host, $query_type, $opts, $answer) = ($1,$2,$3,$4,$5);
        # ctq
        $self->data->{ctq}->{$client_ip}->{$query_type}->{$query_host}++;
        $self->data->{ctq}->{$client_ip}->{$query_type}->{XXX}++;
        $self->data->{ctq}->{$client_ip}->{XXX}++;
        # tqc
        $self->data->{tqc}->{$query_type}->{$query_host}->{$client_ip}++;
        $self->data->{tqc}->{$query_type}->{$query_host}->{XXX}++;
        $self->data->{tqc}->{$query_type}->{XXX}++;
        # qtc
        $self->data->{qtc}->{$query_host}->{$query_type}->{$client_ip}++;
        $self->data->{qtc}->{$query_host}->{$query_type}->{XXX}++;
        $self->data->{qtc}->{$query_host}->{XXX}++;
        # qct
        # cqt
        # tcq
    }
    else {
        $self->data->{'UNMATCHED'}->{$line}++;
    }
};

override get_output => sub {
    my ($self) = @_;
    $self->out_ctq();
};

sub out_ctq {
    my ($self) = @_;
    my $d = $self->data->{ctq};
    
    foreach my $client ( sort SortIP keys %{ $d } ){
        next if $client =~ /^XXX/;
        printf "  %6d  %s\n", $d->{$client}{XXX}, $client;
        foreach my $type ( sort keys %{ $d->{$client} } ){
            next if $type =~ /^XXX/;
            printf "  %6d    %s\n", $d->{$client}{$type}{XXX}, $type;
            foreach my $query ( sort keys %{ $d->{$client}{$type} } ){
                next if $query =~ /^XXX/;
                printf "  %6d      %s\n", $d->{$client}{$type}{$query}, $query;
            }
        }
    }
}


__PACKAGE__->meta->make_immutable;
1;
