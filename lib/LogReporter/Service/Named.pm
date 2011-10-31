package LogReporter::Service::Named;
use Moose;
extends 'LogReporter::Service';
no warnings 'misc';

override init => sub {
    my ($self) = @_;
    super();
    my $data = $self->data;
    $data->{'UNMATCHED'} = {};
    $data->{'CNAMEAndOther'} = [];
};

sub LookupIP { return "LookupIP($_[0]"; }


override process_line => sub {
    my ($self, $line, $meta) = @_;
    my $data = $self->data;

    return if (
        ($line =~ /RR negative cache entry/) or
        ($line =~ /ns_....: .* NS points to CNAME/) or
        ($line =~ /accept: connection reset by peer/) or
        ($line =~ /Connection reset by peer/) or
        # typo fixed in 2004 release
        ($line =~ /transfer(r)?ed serial/) or
        ($line =~ /There may be a name server already running/) or
        ($line =~ /exiting/) or
        ($line =~ /running/) or
        ($line =~ /NSTATS /) or
        ($line =~ /Cleaned cache of \d+ RRs/) or
        ($line =~ /USAGE \d+ \d+ CPU=\d+.*/) or
        ($line =~ /XSTATS /) or
        ($line =~ /Ready to answer queries/) or
        ($line =~ /Forwarding source address is/) or
        ($line =~ /bad referral/) or
        ($line =~ /prerequisite not satisfied/) or
        ($line =~ /(rcvd|Sent) NOTIFY/) or
        ($line =~ /ns_resp: TCP truncated/) or
        ($line =~ /No possible A RRs/) or
        ($line =~ /points to a CNAME/) or
        ($line =~ /dangling CNAME pointer/) or
        ($line =~ /listening on/) or
        ($line =~ /unrelated additional info/) or
        ($line =~ /Response from unexpected source/) or
        ($line =~ /No root nameservers for class IN/) or
        ($line =~ /recvfrom: No route to host/) or
        ($line =~ /(C|c)onnection refused/) or
        ($line =~ /lame server resolving/) or
        ($line =~ /transfer of/) or
        ($line =~ /using \d+ CPU/) or
        ($line =~ /loading configuration/) or
        ($line =~ /command channel listening/) or
        ($line =~ /no IPv6 interfaces found/) or
        ($line =~ /^running/) or
        ($line =~ /^exiting/) or
        ($line =~ /no longer listening/) or
        ($line =~ /the default for the .* option is now/) or
        ($line =~ /stopping command channel on \S+/) or
        ($line =~ /Malformed response from/) or
        ($line =~ /client .* response from Internet for .*/) or
        ($line =~ /client .+ query \(cache\) '.*' denied/) or
        ($line =~ /client .+#\d+: query:/) or
        # Do we really want to ignore these?
        #($line =~ /unknown logging category/) or
        ($line =~ /could not open entropy source/) or
        ($line =~ /\/etc\/rndc.key: file not found/) or
        ($line =~ /sending notifies/) or
        # file syntax error get reported twice and are already caught below
        ($line =~ /loading master file/) or
        ($line =~ /^ succeeded$/) or
        ($line =~ /\*\*\* POKED TIMER \*\*\*/) or
        # The message about the end of transfer is the interesting one
        ($line =~ /: Transfer started./) or
        ($line =~ /D-BUS service (disabled|enabled)./) or
        ($line =~ /D-BUS dhcdbd subscription disabled./) or
        ($line =~ /automatic empty zone/) or
        ($line =~ /binding TCP socket: address in use/) or
        ($line =~ /dbus_mgr initialization failed. D-BUS service is disabled./) or
        ($line =~ /dbus_svc_add_filter failed/) or
        ($line =~ /isc_log_open 'named.run' failed: permission denied/) or
        ($line =~ /weak RSASHA1 \(5\) key found \(exponent=3\)/) or
        ($line =~ /Bad file descriptor/) or
        ($line =~ /open: .*: file not found/) or
        ($line =~ /queries: client [\.0-9a-fA-F#:]* view localhost_resolver: query: .* IN .*/) or
        ($line =~ /zone .*: NS '.*' is a CNAME \(illegal\)/) or
        ($line =~ /zone .*: zone serial unchanged. zone may fail to transfer to slaves/) or
        ($line =~ /zone .*: loading from master file .* failed/) or
        ($line =~ /zone .*: NS '.*' has no address records/) or
        ($line =~ /.*: not a valid number$/) or
        ($line =~ /.*: unexpected end of input/) or
        ($line =~ /too many timeouts resolving '.*' .*: disabling EDNS/) or
        ($line =~ /too many timeouts resolving '.*' .*: reducing the advertised EDNS UDP packet size to .* octets/) or
        ($line =~ /reloading zones succeeded/) or
        ($line =~ /success resolving '.*' \(in '.*'?\) after disabling EDNS/) or
        ($line =~ /success resolving '.*' \(in '.*'?\) after reducing the advertised EDNS UDP packet size to 512 octets/) or
        ($line =~ /the working directory is not writable/) or
        ($line =~ /using default UDP\/IPv[46] port range: \[[0-9]*, [0-9]*\]/) or
        ($line =~ /adjusted limit on open files from [0-9]* to [0-9]*/) or
        ($line =~ /using up to [0-9]* sockets/) or
        ($line =~ /built with/) or
        ($line =~ /TTL differs in rdataset, adjusting [0-9]* -> [0-9]*/) or
        ($line =~ /max open files \([0-9]*\) is smaller than max sockets \([0-9]*\)/) or
        ($line =~ /clients-per-query (?:de|in)creased to .*/) or
        ($line =~ /^must-be-secure resolving '.*': .*/) or
        ($line =~ /^(error \()?no valid (DS|KEY|RRSIG)\)? resolving '.*': .*/) or
        ($line =~ /^not insecure resolving '.*': .*/) or
        ($line =~ /^validating \@0x[[:xdigit:]]+: .* DS: must be secure failure/) or
        ($line =~ /^(error \()?broken trust chain\)? resolving '.*': .*/) or
        ($line =~ /journal file [^ ]* does not exist, creating it/) or
        ($line =~ /serial number \(\d+\) received from master/) or
        ($line =~ /zone is up to date/) or
        ($line =~ /refresh in progress, refresh check queued/) or
        ($line =~ /refresh: NODATA response from master/) or
        ($line =~ /update with no effect/) or
        # ignore this line because the following line describes the error
        ($line =~ /unexpected error/)
    );
    
    if (
      ($line =~ /starting\..*named/) or
      ($line =~ /starting BIND/) or
        ($line =~ /named startup succeeded/) ){
        $data->{'StartNamed'}++;
    } elsif ( $line =~ /(reloading nameserver|named reload succeeded)/ ) {
        $data->{'ReloadNamed'}++;
    } elsif (
      ($line =~ /shutting down/) or
      ($line =~ /named shutting down/ ) or
        ($line =~ /named shutdown succeeded/ ) ){
        $data->{'ShutdownNamed'}++;
    } elsif ( $line =~ /named shutdown failed/ ) {
        $data->{'ShutdownNamedFail'}++;
    }
    
    elsif ( my ($Host, $Zone) = ( $line =~ /client ([^\#]+)#[^\:]+: zone transfer '(.+)' denied/ ) ){
        $data->{'DeniedZoneTransfers'}{$Host}{$Zone}++;
    } elsif ( my ($Zone) = ( $line =~ /zone (.+) zone transfer deferred due to quota/ ) ){
        $data->{'DeferredZoneTransfers'}{$Zone}++;
    } elsif ( my ($Zone) = ( $line =~ /cache zone \"(.*)\" loaded/ ) ){
        $data->{'ZoneLoaded'}{"cache $Zone"}++;
    } elsif ( my ($Zone) = ( $line =~ /cache zone \"(.*)\" .* loaded/ ) ){
        $data->{'ZoneLoaded'}{"cache $Zone"}++;
    } elsif ( my ($Zone) = ( $line =~ /automatic empty zone: (.*)/ ) ){
        $data->{'ZoneLoaded'}{"automatic empty zone $Zone"}++;
    } elsif ( my ($Zone) = ( $line =~ /primary zone \"(.+)\" loaded/ ) ){
        $data->{'ZoneLoaded'}{$Zone}++;
    } elsif ( my ($Zone) = ( $line =~ /master zone \"(.+)\" .* loaded/ ) ){
        $data->{'ZoneLoaded'}{$Zone}++;
    } elsif ( my ($Zone) = ( $line =~ /secondary zone \"(.+)\" loaded/ ) ){
        $data->{'ZoneLoaded'}{"secondary $Zone"}++;
    } elsif ( my ($Zone) = ( $line =~ /slave zone \"(.+)\" .* loaded/ ) ){
        $data->{'ZoneLoaded'}{"secondary $Zone"}++;
    } elsif ( my ($Zone) = ( $line =~ /zone (.+)\: loaded serial/ ) ){
        $data->{'ZoneLoaded'}{$Zone}++;
    }
    
    elsif ( my ($Addr,$Server) = ( $line =~ /ame server (?:on|resolving) '(.+)' \(?:in .+\):\s+(\[.+\]\.\d+)?\s*'?(.+)'?:?/ ) ){
        $data->{'LameServer'}{"$Addr ($Server)"}++;
    } elsif ( my ($Zone) = ( $line =~ /Zone \"(.+)\" was removed/ ) ){
        $data->{'ZoneRemoved'}{$Zone}++;
    } elsif ( my ($Zone) = ( $line =~ /received notify for zone '(.*)'/ ) ){
        $data->{'ZoneReceivedNotify'}{$Zone}++;
    } elsif ( my ($Zone) = ( $line =~ /zone (.*): notify from .* up to date/ ) ){
        $data->{'ZoneReceivedNotify'}{$Zone}++;
    } elsif ( my ($Zone) = ( $line =~ /zone (.*): notify from .* up to date/ ) ){
        $data->{'ZoneReceivedNotify'}{$Zone}++;
    } elsif ( my ($Zone) = ( $line =~ /zone (.+)\/IN: refused notify from non-master/ ) ){
        $data->{'ZoneRefusedNotify'}{$Zone}++;
    }
    
    elsif ( my ($Rhost,$Ldom,$Reason) = ( $line =~ /client ([\.0-9a-fA-F:]+)#\d+: bad zone transfer request: '(.+)\/IN': (.+)/ ) ){
        $data->{'BadZone'}{$Reason}{"$Rhost ($Ldom)"}++;
    } elsif ( my ($Host) = ( $line =~ /([^ ]+) has CNAME and other data \(invalid\)/ ) ){
        push @{ $data->{'CNAMEAndOther'} }, $Host;
    } elsif ( my ($File,$Line,$Entry,$Error) = ( $line =~ /dns_master_load: ([^:]+):(\d+): ([^ ]+): (.+)$/ ) ){
        $data->{'ZoneFileErrors'}{$File}{"$Entry: $Error"}++;
    } elsif ( my ($File,$Line,$Entry,$Error) = ( $line =~ /warning: ([^:]+):(\d+): (.+)$/ ) ){
        $data->{'ZoneFileErrors'}{$File}{"file does not end with newline: $Error"}++;
    } elsif ( my ($Way,$Host) = ( $line =~ /([^ ]+): sendto\(\[([^ ]+)\].+\): Network is unreachable/ ) ){
        my $FullHost = LookupIP ($Host);
        $data->{'NetworkUnreachable'}{$Way}{$FullHost}++;
    } elsif ( my ($Zone,$Message) = ( $line =~ /client [^\#]+#[^\:]+: (?:view \w+: )?updating zone '([^\:]+)': (.*)$/ ) ){
        $data->{'ZoneUpdates'}{$Zone}{$Message}++;
    } elsif ( my ($Host,$Zone) = ( $line =~ /approved AXFR from \[(.+)\]\..+ for \"(.+)\"/ ) ){
        my $FullHost = LookupIP ($Host);
        $data->{'AXFR'}{$Zone}{$FullHost}++;
    } elsif ( my ($Client) = ( $line =~ /warning: client (.*) no more TCP clients/ ) ){
        my $FullClient = LookupIP ($Client);
        $data->{'DeniedTCPClient'}{$FullClient}++;
    }
    
    elsif ( my ($Client) = ( $line =~ /client (.*)#\d+: query \(cache\) denied/ ) ){
        my $FullClient = LookupIP($Client);
        $data->{'DeniedQuery'}{$FullClient}++;
    } elsif ( my ($Client) = ( $line =~ /client (.*)#\d+: query '.*\/IN' denied/ ) ){
        my $FullClient = LookupIP($Client);
        $data->{'DeniedQueryNoCache'}{$FullClient}++;
    } elsif ( my ($Rhost, $ViewName, $Ldom) = ($line =~ /client ([\.0-9a-fA-F:]+)#\d+:(?: view ([^ ]+):)? update '(.*)' denied/) ){
        my $ViewName = ($ViewName ? "/$ViewName" : "");
        $data->{'UpdateDenied'}{"$Rhost ($Ldom$ViewName)"}++;
    } elsif ( my ($Rhost, $Ldom) = ($line =~ /client ([\d\.]+)#\d+: update forwarding '(.*)' denied/) ){
        $data->{'UpdateForwardingDenied'}{"$Rhost ($Ldom)"}++;
    }
    
    elsif ( my ($Zone) = ($line =~ /zone '([0-9a-zA-Z.-]+)' allows updates by IP address, which is insecure/) ){
        $data->{'InsecUpdate'}{$Zone}++;
    } elsif ( my ($Zone) = ($line =~ /zone ([0-9a-zA-Z.\/-]+): journal rollforward failed: journal out of sync with zone/) ){
        $data->{'JournalFail'}{$Zone}++;
    } elsif ( my ($Channel,$Reason) = ($line =~ /couldn't add command channel (.+#\d+): (.*)$/) ){
        $data->{'ChannelAddFail'}{$Channel}{$Reason}++;
    } elsif ( my ($Zone,$Host,$Reason) = ($line =~ /zone ([^ ]*)\/IN: refresh: failure trying master ([^ ]*)#\d+: (.*)/) ){
        $data->{'MasterFailure'}{"$Zone from $Host"}{$Reason}++;
    } elsif ( my ($Zone,$Reason,$Host) = ($line =~ /zone ([^ ]*)\/IN: refresh: unexpected rcode \((.*)\) from master ([^ ]*)#\d+/) ){
        $data->{'MasterFailure'}{"$Zone from $Host"}{$Reason}++;
    } elsif ( my ($Zone) = ($line =~ /zone ([^\/]+)\/.+: refresh: non-authoritative answer from master/) ){
        $data->{'NonAuthoritative'}{$Zone}++;
    } elsif ( my ($Zone) = ($line =~ /zone ([^\/]+)\/.+: refresh: retry limit for master \S+ exceeded/) ){
        $data->{'RetryLimit'}{$Zone}++;
    }
    
    elsif ( ($line =~ /(?:error \()?unexpected RCODE\)? \(?(.*?)\)? resolving/) ){
        $data->{'UnexpRCODE'}{$1}++;
    }
    elsif ( ($line =~ /found [0-9]* CPU(s)?, using [0-9]* worker thread(s)?/) ){
        $data->{'StartLog'}{$line}++;
    }

    #elsif (
    #  ($line =~ /(?:error \()?FORMERR\)? resolving '[^ ]+: [.0-9a-fA-F:#]+/) or
    #  ($line =~ /DNS format error from [^ ]+ resolving [^ ]+( for client [^ ]+)?: .*/) ){
    #    $data->{'FormErr'}{$line}++;
    #}
    #DNS format error from 204.8.173.5#53 resolving www.businesswire.com/AAAA for client 216.106.233.1#9468: invalid response
    elsif ( my ($remote,$query,$client,$why) = ($line =~ /DNS format error from ([^ ]+) resolving ([^ ]+)(?: for client ([^ ]+))?: (.*)/) ){
        $data->{'FormErr'}->{$remote}->{$query}->{$why}++;
    }
    elsif (
      ($line =~ /\/etc\/(rndc.key|named.conf):([0-9]+): (unknown option '[^ ]*')/) or
      ($line =~ /\/etc\/(rndc.key|named.conf):([0-9]+): ('[^ ]' expected near end of file)/) or
      ($line =~ /\/etc\/(named.*.conf):([0-9]+): (.*)/) or
      ($line =~ /()()(could not configure root hints from '.*': file not found)/) ){
        my ($File,$Line,$Problem) = ($1,$2,$3);
        $data->{'ConfProb'}{$File}{"$Line,$Problem"}++;
    }
    
    elsif (
      ($line =~ /^(RUNTIME_CHECK.*)/) or
      ($line =~ /^(.* REQUIRE.* failed.*)$/) or
      ($line =~ /(.*: fatal error)/) ){
        my ($ErrorText) = ($1);
        $data->{'NError'}{$ErrorText}++;
    }
    elsif (
      ($line =~ /^(internal_accept: fcntl\(\) failed: Too many open files)/) or
      ($line =~ /^(socket: too many open file descriptors)/) ){
        my ($ErrorText) = ($1);
        $data->{'ErrOpenFiles'}{$ErrorText}++;
    }
    elsif ( my ($From,$Log) = ($line =~ /invalid command from ([\.0-9a-fA-F:]*)#[0-9]*: (.*)/) ){
        $data->{'CCMessages'}{"$From,$Log"}++;
    }
    elsif (
      ($line =~ /(freezing .*zone.*)/) or
      ($line =~ /(thawing .*zone.*)/) ){
        my ($Log) = ($1);
        $data->{'CCMessages2'}{$Log}++;
    }
    
    elsif ( my ($CCC) = ($line =~ /unknown control channel command '(.*)'/) ){
        $data->{'UnknownCCCommands'}{$CCC}++;
    } elsif ( my ($CCC) = ($line =~ /received control channel command '(.*)'/) ){
        $data->{'CCCommands'}{$CCC}++;
    } elsif ( my ($Name,$Address) = ($line =~ /(?:error \()?network unreachable\)? resolving '(.*)': (.*)/) ){
        $data->{'NUR'}{$Name}{$Address}++;
    } elsif ( my ($Name,$Address) = ($line =~ /(?:error \()?host unreachable\)? resolving '(.*)': (.*)/) ){
        $data->{'HUR'}{$Name}{$Address}++;
    } elsif ( my ($Client) = ($line =~ /client ([\da-fA-F.:]+)(?:#\d*:)? notify question section contains no SOA/) ){
        $data->{'NoSOA'}{$Client}++;
    } elsif ( my ($Hint) = ($line =~ /checkhints: (.*)/) ){
        $data->{'Hints'}{$Hint}++;
    }
    
    else {
        $data->{'UNMATCHED'}->{$line}++;
    }
};


__PACKAGE__->meta->make_immutable;
1;
