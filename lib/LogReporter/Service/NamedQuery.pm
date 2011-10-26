package LogReporter::Service::NamedQuery;
use Moose;
use namespace::autoclean;
extends 'LogReporter::Service';
no warnings 'misc';

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
        $client_ip =~ s/\./,/g;
        $query_host =~ s/\./,/g;
        $query_host =~ s/^_/&/;
        $self->data->{ctq}->{$client_ip}->{$query_type}->{$query_host}++;
        $self->data->{ctq}->{$client_ip}->{$query_type}->{XXX}++;
        $self->data->{ctq}->{$client_ip}->{XXX}++;
        $self->data->{tqc}->{$query_type}->{$query_host}->{$client_ip}++;
        $self->data->{tqc}->{$query_type}->{$query_host}->{XXX}++;
        $self->data->{tqc}->{$query_type}->{XXX}++;
        $self->data->{qtc}->{$query_host}->{$query_type}->{$client_ip}++;
        $self->data->{qtc}->{$query_host}->{$query_type}->{XXX}++;
        $self->data->{qtc}->{$query_host}->{XXX}++;
    }
    else {
        $self->data->{'UNMATCHED'}->{$line}++;
    }
};

1;
