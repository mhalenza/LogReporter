package LogReporter::Service::Iptables;
use feature ':5.10';
use Moose;
use namespace::autoclean;
extends 'LogReporter::Service';

has 'proc' => (
    is => 'ro',
    isa => 'Subref',
    traits => ['Code'],
    required => 1,
    handles => {
        callproc => 'execute',
    },
    default => sub {
        return sub {
            my ($d, $actionType, $interface, $fromip, $toip, $toport, $svc, $proto, $prefix) = @_;
            # $ipt1->{$actionType}{$interface}{$fromip}{$toip}{$toport}{$proto}{$prefix}++;
            $d->{$actionType}{$interface}{$fromip}{$toip}{$toport}{$proto}{$prefix}++;
            $d->{$actionType}{$interface}{$fromip}{$toip}{$toport}{$proto}{XXX}++;
            $d->{$actionType}{$interface}{$fromip}{$toip}{$toport}{$proto}{XXX_service} //= $svc;
            $d->{$actionType}{$interface}{$fromip}{$toip}{$toport}{XXX}++;
            $d->{$actionType}{$interface}{$fromip}{$toip}{XXX}++;
            $d->{$actionType}{$interface}{$fromip}{XXX}++;
            $d->{$actionType}{$interface}{XXX}++;
            $d->{$actionType}{XXX}++;
        };
    },
);

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
        
        $self->callproc(
          $self->data, $actionType, $interface, $fromip, $toip, $toport, _lookupService($toport,$proto), $proto, $prefix
        );
    }
};

1;
