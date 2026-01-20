#!/usr/bin/perl
use strict;
use warnings;
use JSON;

# Configuration
my $log_file = "/var/log/suricata/eve.json";
my $refresh_rate = 15;
my $box_width = 62; # The total width of the inner box content

# ANSI Color Codes
my $R  = "\e[1;31m"; # Red
my $G  = "\e[1;32m"; # Green
my $Y  = "\e[1;33m"; # Yellow
my $B  = "\e[1;34m"; # Blue
my $C  = "\e[1;36m"; # Cyan
my $W  = "\e[1;37m"; # White
my $RS = "\e[0m";    # Reset

# Helper to calculate visual length (ignoring ANSI codes)
sub get_width {
    my $str = shift;
    $str =~ s/\e\[[\d;]*m//g; # Strip ANSI codes
    return length($str);
}

# Helper to print a centered line inside the box
sub print_box_line {
    my $text = shift;
    my $visual_len = get_width($text);
    my $padding = $box_width - $visual_len;
    my $left_pad = int($padding / 2);
    my $right_pad = $padding - $left_pad;
    
    print "${B}│${RS}" . (" " x $left_pad) . $text . (" " x $right_pad) . "${B}│${RS}\n";
}

while (1) {
    my %stats = ( drops => 0, alerts => 0, total => 0 );
    my %ips;
    my %sigs;

    if (-e $log_file) {
        open(my $fh, '<', $log_file) or die "Can't open log: $!";
        while (my $line = <$fh>) {
            next unless $line =~ /^\{/;
            my $evt = eval { decode_json($line) };
            next unless $evt;
            $stats{total}++;
            if ($evt->{event_type} eq 'drop' || $evt->{event_type} eq 'alert') {
                my $type = $evt->{event_type};
                $stats{$type . "s"}++;
                my $src = $evt->{src_ip} // "Unknown";
                $ips{$src}++;
                if ($evt->{$type} && $evt->{$type}{signature}) {
                    $sigs{$evt->{$type}{signature}}++;
                }
            }
        }
        close($fh);
    }

    system("clear");

    # Header with Fixed Box Alignment
    print "${B}┌" . ("─" x $box_width) . "┐${RS}\n";
    print_box_line("${W}SURICATA IPS MONITOR${RS}");
    print_box_line("${C}Refreshing every ${refresh_rate}s${RS}");
    print "${B}└" . ("─" x $box_width) . "┘${RS}\n";

    # Summary Stats
    print "\n${G}[ SYSTEM SUMMARY ]${RS}\n";
    printf("${W} Total Events:     ${C}%-10d${RS}\n", $stats{total});
    printf("${W} Active Blocks:    ${R}%-10d${RS}\n", $stats{drops});
    printf("${W} Alerts Logged:    ${Y}%-10d${RS}\n", $stats{alerts});
    print "${B}" . ("─" x ($box_width+2)) . "${RS}\n";

    # Top Attacking IPs
    print "\n${G}[ TOP THREAT SOURCES ]${RS}\n";
    printf("${W}%-20s %-10s %-30s${RS}\n", "Source IP", "Hits", "Intensity");
    print "${B}" . ("-" x ($box_width+2)) . "${RS}\n";

    my @sorted_ips = sort { $ips{$b} <=> $ips{$a} } keys %ips;
    my $max_hits = ($ips{$sorted_ips[0]} || 1);

    my $count = 0;
    foreach my $ip (@sorted_ips) {
        last if $count++ >= 10;
        my $bar_size = int(($ips{$ip} / $max_hits) * 20);
        $bar_size = 1 if $bar_size < 1;
        my $bar = ("█" x $bar_size);
        printf("${C}%-20s ${W}%-10d ${R}%-20s${RS}\n", $ip, $ips{$ip}, $bar);
    }

    # Top Signatures
    print "\n${G}[ TOP SIGNATURES / REASONS ]${RS}\n";
    print "${B}" . ("-" x ($box_width+2)) . "${RS}\n";
    my @sorted_sigs = sort { $sigs{$b} <=> $sigs{$a} } keys %sigs;

    my $s_count = 0;
    foreach my $s (@sorted_sigs) {
        last if $s_count++ >= 5;
        my $display_sig = length($s) > 50 ? substr($s, 0, 47) . "..." : $s;
        printf("${Y}» ${W}%-52s ${R}(%d)${RS}\n", $display_sig, $sigs{$s});
    }

    print "\n${W}Press ${R}Ctrl+C${W} to exit.  |  Last Update: " . localtime() . "${RS}\n";
    sleep($refresh_rate);
}
