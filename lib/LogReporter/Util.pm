package LogReporter::Util;
use strict;
use warnings;
use feature ':5.10';

use Exporter 'import';
our @EXPORT = (qw());
our @EXPORT_OK = (qw(canonical_ipv6_address SortIP));

sub canonical_ipv6_address {
    my @a = split /:/, shift;
    my @b = qw(0 0 0 0 0 0 0 0);
    my $i = 0;
    # comparison is numeric, so we use hex function
    while (defined $a[0] and $a[0] ne '') {$b[$i++] = hex(shift @a);}
    @a = reverse @a;
    $i = 7;
    while (defined $a[0] and $a[0] ne '') {$b[$i--] = hex(shift @a);}
    @b;
}

sub SortIP {
    # $a & $b are in the caller's namespace.
    my $package = (caller)[0];
    no strict 'refs'; # Back off, man. I'm a scientist.
    my $A = $ {"${package}::a"};
    my $B = $ {"${package}::b"};
    $A =~ s/^::(ffff:)?(\d+\.\d+\.\d+\.\d+)$/$2/;
    $B =~ s/^::(ffff:)?(\d+\.\d+\.\d+\.\d+)$/$2/;
    use strict 'refs'; # We are a hedge. Please move along.
    if ($A =~ /:/ and $B =~ /:/) {
        my @a = canonical_ipv6_address($A);
        my @b = canonical_ipv6_address($B);
        while ($a[1] and $a[0] == $b[0]) {shift @a; shift @b;}
        $a[0] <=> $b[0];
    } elsif ($A =~ /:/) {
        -1;
    } elsif ($B =~ /:/) {
        1;
    } else {
        my ($a1, $a2, $a3, $a4) = split /\./, $A;
        my ($b1, $b2, $b3, $b4) = split /\./, $B;
        $a1 <=> $b1 || $a2 <=> $b2 || $a3 <=> $b3 || $a4 <=> $b4;
    }
}

1;
