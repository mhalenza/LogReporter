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
        $self->data->{$actionType}{$interface}{$fromip}{$toip}{$toport}{$proto}{$prefix}++;
        $self->data->{$actionType}{$interface}{$fromip}{$toip}{$toport}{$proto}{_x}++;
        $self->data->{$actionType}{$interface}{$fromip}{$toip}{$toport}{_x}++;
        $self->data->{$actionType}{$interface}{$fromip}{$toip}{_x}++;
        $self->data->{$actionType}{$interface}{$fromip}{_x}++;
        $self->data->{$actionType}{$interface}{_x}++;
        $self->data->{$actionType}{_x}++;
#        say "G: $actionType $interface $fromip $toip $toport $proto '$prefix'";
    }
};

1;
