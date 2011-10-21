package LogReporter::Service::Postfix;
use strict;
use warnings;

my $re_IP      = '(?:(?:::(?:ffff:|FFFF:)?)?(?:\d{1,3}\.){3}\d{1,3}|(?:[\da-fA-F]{0,4}:){2}(?:[\da-fA-F]{0,4}:){0,5}[\da-fA-F]{0,4})';
my $re_DSN     = '(?:(?:\d{3})?(?: ?\d\.\d\.\d)?)';
my $re_QID     = '[A-Z\d]+';
my $re_DDD     = '(?:(?:conn_use=\d+ )?delay=-?[\d.]+(?:, delays=[\d\/.]+)?(?:, dsn=[\d.]+)?)';

# RFC 3463 DSN Codes
# http://www.faqs.org/rfcs/rfc3463.html
my %dsn_codes = (
    class => {
        "2" => "Success",
        "4" => "Persistent Transient Failure",
        "5" => "Permanent Failure",
    },
    
    subject => {
        "0" => "Other or Undefined Status",
        "1" => "Addressing Status",
        "2" => "Mailbox Status",
        "3" => "Mail System Status",
        "4" => "Network & Routing Status",
        "5" => "Mail Delivery Protocol Status",
        "6" => "Message Content or Media Status",
        "7" => "Security or Policy Status",
    },
    
    detail => {
        "0.0" => "Other undefined status",
        "1.0" => "Other address status",
        "1.1" => "Bad destination mailbox address",
        "1.2" => "Bad destination system address",
        "1.3" => "Bad destination mailbox address syntax",
        "1.4" => "Destination mailbox address ambiguous",
        "1.5" => "Destination mailbox address valid",
        "1.6" => "Mailbox has moved",
        "1.7" => "Bad sender's mailbox address syntax",
        "1.8" => "Bad sender's system address",
        
        "2.0" => "Other or undefined mailbox status",
        "2.1" => "Mailbox disabled, not accepting messages",
        "2.2" => "Mailbox full",
        "2.3" => "Message length exceeds administrative limit.",
        "2.4" => "Mailing list expansion problem",
        
        "3.0" => "Other or undefined mail system status",
        "3.1" => "Mail system full",
        "3.2" => "System not accepting network messages",
        "3.3" => "System not capable of selected features",
        "3.4" => "Message too big for system",
        
        "4.0" => "Other or undefined network or routing status",
        "4.1" => "No answer from host",
        "4.2" => "Bad connection",
        "4.3" => "Routing server failure",
        "4.4" => "Unable to route",
        "4.5" => "Network congestion",
        "4.6" => "Routing loop detected",
        "4.7" => "Delivery time expired",
        
        "5.0" => "Other or undefined protocol status",
        "5.1" => "Invalid command",
        "5.2" => "Syntax error",
        "5.3" => "Too many recipients",
        "5.4" => "Invalid command arguments",
        "5.5" => "Wrong protocol version",
        
        "6.0" => "Other or undefined media error",
        "6.1" => "Media not supported",
        "6.2" => "Conversion required & prohibited",
        "6.3" => "Conversion required but not supported",
        "6.4" => "Conversion with loss performed",
        "6.5" => "Conversion failed",
        
        "7.0" => "Other or undefined security status",
        "7.1" => "Delivery not authorized, message refused",
        "7.2" => "Mailing list expansion prohibited",
        "7.3" => "Security conversion required but not possible",
        "7.4" => "Security features not supported",
        "7.5" => "Cryptographic failure",
        "7.6" => "Cryptographic algorithm not supported",
        "7.7" => "Message integrity failure",
    },
);


1;
