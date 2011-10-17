package LogReporter::Service::Iptables;
use Moose;
use namespace::autoclean;
extends 'LogReporter::Service';

my $iptables_fmt = /^
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

sub _lookup_action {
    my ($prefix) = @_;
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
    
    if ( $line =~ $iptables_fmt ) {
        my ($prefix,$ifin,$ifout,$fromip,$toip,$rest) = @+{'prefix','ifin','ifout','fromip','toip','rest'};
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
        
        my $actionType = lookupAction($prefix);
        
        $prefix = "(${prefix}) " if ($prefix ne "");
        
        $self->data->{$actionType}{$interface}{$fromip}{$toip}{$toport}{$proto}{$chain_info}++;
    }
};

1;
