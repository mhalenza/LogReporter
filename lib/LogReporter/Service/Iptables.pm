package LogReporter::Service::Iptables;
use feature ':5.10';
use Moose;
use namespace::autoclean;
extends 'LogReporter::Service';

my $iptables_fmt = qr/^
    (?<prefix>.*?)
    \s*
    IN=(?<ifin>[\w\.]*)
    .*?
    OUT=(?<ifout>[\w\.]*)
    .*?
    SRC=(?<fromip>[\w\.:]+)
    .*?
    DST=(?<toip>[\w\.:]+)
    .*?
    PROTO=(?<proto>\w+)
    (?<rest>.*)
/x;

sub _lookupAction {
    my ($prefix) = @_;
    no warnings 'uninitialized';
    given ($prefix){
        when (/reject/i)    { return 'Rejected'; }
        when (/drop/i)      { return 'Dropped'; }
        when (/deny/i)      { return 'Denied'; }
        when (/denied/i)    { return 'Denied'; }
        when (/accept/i)    { return 'Accepted'; }
        default             { return 'Logged'; }
    }
}

sub _lookupService {
    my ($port, $proto) = @_;
    return getservbyport($port, lc$proto) || $port;
}

sub _lookupProtocol {
    my ($proto) = @_;
    return getprotobynumber($proto) || $proto;
}

override process_line => sub {
    my ($self, $line, $meta) = @_;
no warnings 'uninitialized';  
    if ( $line =~ $iptables_fmt ) {
        my ($prefix,$ifin,$ifout,$fromip,$toip,$proto,$rest) = @+{'prefix','ifin','ifout','fromip','toip','proto','rest'};
        my $interface;
        
        # determine the dominant interface
        if ($ifin  =~ /\w+/ && $ifout  =~ /\w+/) {
            $interface = $ifin;
        } elsif ($ifin =~ /\w+/) {
            $interface = $ifin;
            $ifout = "none";
        } else {
            $interface = $ifout;
            $ifin = "none";
        }
        
        # get a destination port number  (or icmp type) if there is one
        my $toport;
        unless ( ($toport) = ( $rest =~ /TYPE=(\w+)/ ) ) {
            unless ( ($toport) = ( $rest =~ /DPT=(\w+)/ ) ) {
                $toport = 0;
            }
        }
        
        my $actionType = _lookupAction($prefix);
        #$prefix = "(${prefix}) " if ($prefix ne "");

        # $ipt1->{$actionType}{$interface}{$fromip}{$toip}{$toport}{$proto}{$prefix}++;
        $self->data->{ipt1}->{$actionType}{$interface}{$fromip}{$toip}{$toport}{$proto}{$prefix}++;
        $self->data->{ipt1}->{$actionType}{$interface}{$fromip}{$toip}{$toport}{$proto}{XXX}++;
        $self->data->{ipt1}->{$actionType}{$interface}{$fromip}{$toip}{$toport}{$proto}{XXX_service} //= _lookupService($toport,$proto);
        $self->data->{ipt1}->{$actionType}{$interface}{$fromip}{$toip}{$toport}{XXX}++;
        $self->data->{ipt1}->{$actionType}{$interface}{$fromip}{$toip}{XXX}++;
        $self->data->{ipt1}->{$actionType}{$interface}{$fromip}{XXX}++;
        $self->data->{ipt1}->{$actionType}{$interface}{XXX}++;
        $self->data->{ipt1}->{$actionType}{XXX}++;
        
        # $ipt2->{$actionType}{$interface}{$toport}{$proto}{$fromip}{$toip}{$prefix}++;
        $self->data->{ipt2}->{$actionType}{$interface}{$toport}{$proto}{$fromip}{$toip}{$prefix}++;
        $self->data->{ipt2}->{$actionType}{$interface}{$toport}{$proto}{$fromip}{$toip}{XXX}++;
        $self->data->{ipt2}->{$actionType}{$interface}{$toport}{$proto}{$fromip}{XXX}++;
        $self->data->{ipt2}->{$actionType}{$interface}{$toport}{$proto}{XXX}++;
        $self->data->{ipt2}->{$actionType}{$interface}{$toport}{$proto}{XXX_service} //= _lookupService($toport,$proto);
        $self->data->{ipt2}->{$actionType}{$interface}{$toport}{XXX}++;
        $self->data->{ipt2}->{$actionType}{$interface}{XXX}++;
        $self->data->{ipt2}->{$actionType}{XXX}++;
    }
};

1;
