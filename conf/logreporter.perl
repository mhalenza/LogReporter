require DateTime::Span;
require DateTime;
# Lets specify what time range we're interested in:
$Range = DateTime::Span->from_datetimes(
    start => DateTime->new(qw/year 2011 month 10 day 16 hour 0 minute 0 second 0/),
    end => DateTime->now(),
);

{
# First we setup the "sources" which are just logfiles.
    sources => {
=pod
The format of this hashref is:
<source_name> => {
    files => ARRAY_REF,  # all logfiles that are included in this source, *'s are expanded
    filters => [
        <filter_name> => $OPTIONS_HASH_REF,
        # LogReporter::Filter::<filter_name> will be loaded and passed %{ $OPTIONS }
        # The first two filters will almost always be  DATE (or ISO8601, Strptime, etc)
        # followed by DateRange:
        ISO8601 => { format => '^(\S+)\s+' },
        DateRange => { range => $Range },
    ],
}
=cut
        'maillog' => {
            files => [qw(
                /var/log/syslog/mail.log
                /var/log/archive/mail.log.*
                /var/log/archive/mail.log-*
            )],
            filters => [
                ISO8601 => { format => '^(\S+)\s+' },
                DateRange => { range => $Range },
                Syslog => { format => '^(?<h>\w+)\s+\[(?<l>[^\]]+)\]\s+', },
                Parser => { format => 'postfix/(?<sp>\w+)\(\d+\): ', },
            ],
        },
        'iptables' => {
            files => [qw(
                /var/log/syslog/iptables.log
                /var/log/archive/iptables.log.*
                /var/log/archive/iptables.log-*
            )],
            filters => [
                ISO8601 => { format => '^(\S+)\s+' },
                DateRange => { range => $Range },
                Syslog => { format => '^(?<h>\w+)\s+' },
            ],
        },
    },

# Now we can setup the services
    services => [
=pod
This is an arrayref, but it's basically a hash:
<service_name> => { #
    disabled => 0, # if 1, this service is skipped
    sources => ARRAY_REF, # an arrayref of strings: ['<source1_name>','<source2_name>',etc]
    filters => [
        #same as for sources, but you'll probably only ever use Meta or Parser here.
    ]
    %OPTIONS, # everything else is passed to new()
},
=cut
        Postfix => {
            disabled => 0,
            sources => ['maillog'],
            # the Postfix service has two options:
            print_summaries => 1,
            print_details => 0,
        },
        Iptables => {
            disabled => 0,
            sources => ['iptables'],
            # the Iptables has two options:
            
            # proc - a subref that is called for every matching line:
            proc => sub {
                my ($d, $actionType, $interface, $fromip, $toip, $toport, $svc, $proto, $prefix) = @_;
                $d->{$prefix}{$toport}{$proto}{$fromip}++;
                $d->{$prefix}{$toport}{$proto}{XXX}++;
                $d->{$prefix}{$toport}{$proto}{XXX_service} //= $svc;
                $d->{$prefix}{$toport}{XXX}++;
                $d->{$prefix}{XXX}++;
            },
            # report - a subref that is called when it's time to generate the report.  use print/printf to output the report
            report => sub {
                use LogReporter::Util qw/SortIP/;
                my ($data) = @_;
                foreach my $prefix ( grep { !/^XXX/ } keys %{ $data } ){
                    printf "%s\n", $prefix;
                    foreach my $toport ( grep { !/^XXX/ } keys %{ $data->{$prefix} } ){
                        foreach my $proto ( grep { !/^XXX/ } keys %{ $data->{$prefix}{$toport} } ){
                            printf "  % 4d  Service %s (%s/%s)\n",
                            $data->{$prefix}{$toport}{$proto}{XXX},
                            $data->{$prefix}{$toport}{$proto}{XXX_service},
                            $proto,
                            $toport;
                            foreach my $fromip ( sort SortIP grep { !/^XXX/ } keys %{ $data->{$prefix}{$toport}{$proto} } ){
                                printf "  % 4d    %s\n",
                                $data->{$prefix}{$toport}{$proto}{$fromip},
                                $fromip;
                            }
                        }
                    }
                }
            },
        },
        # And two fun little guys
        zz_disk_space => { dirs => ['/etc','/var/log','/opt'], },
        zz_uptime => { },
    ],
    
    # This is really only here so the report header can use it.
    Range => $Range,
}