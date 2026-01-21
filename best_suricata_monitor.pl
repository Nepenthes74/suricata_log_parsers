#!/usr/bin/perl
use strict;
use warnings;
use JSON;

# --- Configuration ---
my $log_file     = "/var/log/suricata/eve.json";
my $refresh_rate = 15;
my $box_width    = 110; 

my %whois_cache;
my $last_total = 0;

# --- ANSI Color Codes ---
my $R = "\e[1;31m"; my $G = "\e[1;32m"; my $Y = "\e[1;33m";
my $B = "\e[1;34m"; my $C = "\e[1;36m"; my $W = "\e[1;37m";
my $D = "\e[2m";    my $RS = "\e[0m";

sub get_width {
    my $str = shift // "";
    $str =~ s/\e\[[\d;]*m//g; 
    return length($str);
}

sub print_box_line {
    my $text = shift // "";
    my $v_len = get_width($text);
    my $pad = $box_width - $v_len;
    $pad = 0 if $pad < 0;
    my $l_pad = int($pad / 2);
    my $r_pad = $pad - $l_pad;
    print "${B}│${RS}" . (" " x $l_pad) . $text . (" " x $r_pad) . "${B}│${RS}\n";
}

sub get_ip_owner {
    my $ip = shift;
    return "Local Network" if $ip =~ /^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/;
    return $whois_cache{$ip} if exists $whois_cache{$ip};
    my $owner = `whois $ip | grep -Ei '^(orgname|organization|descr|owner):' | head -1 | awk -F: '{print \$2}'` // "";
    $owner =~ s/^\s+|\s+$//g; 
    $whois_cache{$ip} = $owner || "Unknown ISP";
    return $whois_cache{$ip};
}

sub get_sys_stats {
    open(my $load_fh, '<', '/proc/loadavg') or return "N/A";
    my $load = <$load_fh>; close($load_fh);
    $load = (split(/ /, $load))[0];

    open(my $mem_fh, '<', '/proc/meminfo') or return "Load: $load";
    my ($total, $avail) = (0, 0);
    while (<$mem_fh>) {
        $total = $1 / 1024 if /^MemTotal:\s+(\d+)/;
        $avail = $1 / 1024 if /^MemAvailable:\s+(\d+)/;
    }
    close($mem_fh);
    my $used = $total - $avail;
    my $perc = int(($used / $total) * 100);
    return sprintf("CPU Load: %s  |  RAM: %dMB / %dMB (%d%%)", $load, $used, $total, $perc);
}

while (1) {
    my %stats = ( drops => 0, alerts => 0, total => 0 );
    my (%ips, %sigs);

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

    my $delta = $stats{total} - $last_total;
    $last_total = $stats{total};
    system("clear");

    # --- TOP BOX ---
    print "${B}┌" . ("─" x $box_width) . "┐${RS}\n";
    print_box_line("${W}S U R I C A T A   I P S   I N T E L L I G E N C E${RS}");
    print_box_line("${D}Security Monitor - Interval: ${refresh_rate}s${RS}");
    print "${B}├" . ("─" x $box_width) . "┤${RS}\n";
    
    my $stats_row = sprintf("${W}EVENTS: ${C}%-7d  ${W}BLOCKS: ${R}%-7d  ${W}ALERTS: ${Y}%-7d  ${W}NEW: ${G}+%-d${RS}", 
                    $stats{total}, $stats{drops}, $stats{alerts}, ($delta < 0 ? 0 : $delta));
    print_box_line($stats_row);
    print "${B}└" . ("─" x $box_width) . "┘${RS}\n";

    # --- DATA TABLE ---
    print "\n${G}  [ TOP THREAT SOURCES ]${RS}\n";
    printf("  ${W}%-20s %-10s %-30s %-40s${RS}\n", "SOURCE IP", "STRIKES", "INTENSITY", "ORGANIZATION/ISP");
    print "  " . ("${D}─${RS}" x ($box_width - 4)) . "\n";
    
    my @sorted_ips = sort { $ips{$b} <=> $ips{$a} } keys %ips;
    my $max_h = ($ips{$sorted_ips[0]} || 1);
    
    for (my $i=0; $i<10; $i++) {
        my $ip = $sorted_ips[$i];
        last unless $ip;
        my $b_max = 28;
        my $b_count = int(($ips{$ip} / $max_h) * $b_max);
        $b_count = 1 if $b_count < 1;
        my $formatted_bar = "${R}" . ("█" x $b_count) . "${RS}" . (" " x (30 - $b_count));
        my $owner = get_ip_owner($ip);
        if (length($owner) > 37) { $owner = substr($owner, 0, 37) . "..."; }
        printf("  ${C}%-20s ${W}%-10d %-s ${Y}%-40s${RS}\n", $ip, $ips{$ip}, $formatted_bar, $owner);
    }

    # --- SIGNATURES ---
    print "\n${G}  [ TOP SIGNATURES ]${RS}\n";
    print "  " . ("${D}─${RS}" x ($box_width - 4)) . "\n";
    my @sorted_sigs = sort { $sigs{$b} <=> $sigs{$a} } keys %sigs;
    for (my $i=0; $i<5; $i++) {
        my $s = $sorted_sigs[$i];
        last unless $s;
        my $disp = length($s) > ($box_width - 15) ? substr($s, 0, ($box_width - 18)) . "..." : $s;
        printf("  ${Y}» ${W}%-s ${R}(%d)${RS}\n", $disp, $sigs{$s});
    }

    # --- SYSTEM FOOTER ---
    print "\n${B}┌" . ("─" x $box_width) . "┐${RS}\n";
    print_box_line("${W}" . get_sys_stats() . "${RS}");
    print "${B}└" . ("─" x $box_width) . "┘${RS}\n";
    print "  ${D}Last Check: " . localtime() . " | WHOIS Cache: " . scalar(keys %whois_cache) . " entries${RS}\n";
    
    sleep($refresh_rate);
}
