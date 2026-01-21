#!/usr/bin/perl
use strict;
use warnings;
use JSON;
use Socket;

# --- Configuration ---
my $log_file     = "/var/log/suricata/eve.json";
my $refresh_rate = 15;
my $box_width    = 110; 

# --- Whitelist (IPs to ignore in threat tables) ---
my %whitelist = (
    '95.216.195.133' => 1, # Arch Linux Connectivity Check
);

my %whois_cache;
my %arp_cache;
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

# Updates local hostname cache using modern 'ip neigh'
sub update_arp_cache {
    %arp_cache = ();
    my @ip_output = `ip -4 neigh show`;
    foreach my $line (@ip_output) {
        if ($line =~ /^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+(\S+)/) {
            my ($ip, $mac) = ($1, $2);
            my $iaddr = inet_aton($ip);
            my $hostname = gethostbyaddr($iaddr, AF_INET); #
            $arp_cache{$ip} = $hostname // "Device [$mac]";
        }
    }
}

sub get_ip_owner {
    my $ip = shift;
    if ($ip =~ /^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/) {
        return $arp_cache{$ip} // "Local Network";
    }
    return $whois_cache{$ip} if exists $whois_cache{$ip};
    
    my $owner = `whois $ip | grep -Ei '^(orgname|organization|descr|owner):' | head -1 | awk -F: '{print \$2}'` // "";
    $owner =~ s/^\s+|\s+$//g; 
    $whois_cache{$ip} = $owner || "Unknown ISP";
    return $whois_cache{$ip};
}

# Logarithmic scaling for better visualization of intensity
sub get_bar {
    my ($count, $max, $color) = @_;
    return " " x 28 if $count <= 0;
    my $width = $max > 1 ? int((log($count) / log($max)) * 28) : 28;
    $width = 1 if $width < 1;
    return $color . ("█" x $width) . $RS . (" " x (28 - $width));
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
    my $perc = $total > 0 ? int(($used / $total) * 100) : 0;
    return sprintf("CPU Load: %s  |  RAM: %dMB / %dMB (%d%%)", $load, $used, $total, $perc);
}

while (1) {
    update_arp_cache();
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
                my $src = $evt->{src_ip} // "Unknown";
                next if $whitelist{$src}; # Apply whitelist filter
                
                my $type = $evt->{event_type};
                $stats{$type . "s"}++;
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

    # --- HEADER ---
    print "${B}┌" . ("─" x $box_width) . "┐${RS}\n";
    print_box_line("${W}S U R I C A T A   I P S   I N T E L L I G E N C E${RS}");
    print "${B}├" . ("─" x $box_width) . "┤${RS}\n";
    my $stats_row = sprintf("${W}EVENTS: ${C}%-7d  ${W}BLOCKS: ${R}%-7d  ${W}ALERTS: ${Y}%-7d  ${W}NEW: ${G}+%-d${RS}", 
                    $stats{total}, $stats{drops}, $stats{alerts}, ($delta < 0 ? 0 : $delta));
    print_box_line($stats_row);
    print "${B}└" . ("─" x $box_width) . "┘${RS}\n";

    my @sorted_ips = sort { $ips{$b} <=> $ips{$a} } keys %ips;
    my $max_val = $ips{$sorted_ips[0]} || 1;

    # --- EXTERNAL THREATS (Set to 13 hosts) ---
    print "\n${G}  [ TOP EXTERNAL THREAT SOURCES ]${RS}\n";
    printf("  ${W}%-20s %-10s %-30s %-40s${RS}\n", "SOURCE IP", "STRIKES", "INTENSITY", "ORGANIZATION/ISP");
    print "  " . ("${D}─${RS}" x ($box_width - 4)) . "\n";
    
    my $ext_count = 0;
    foreach my $ip (@sorted_ips) {
        last if $ext_count >= 13; # Display limit
        next if $ip =~ /^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/;

        $ext_count++;
        my $owner = get_ip_owner($ip);
        my $bar = get_bar($ips{$ip}, $max_val, $R);
        my $disp_owner = length($owner) > 37 ? substr($owner, 0, 37) . "..." : $owner;
        printf("  ${C}%-20s ${W}%-10d %-s ${Y}%-40s${RS}\n", $ip, $ips{$ip}, $bar, $disp_owner);
    }

    # --- LOCAL THREATS ---
    print "\n${G}  [ TOP LOCAL THREATS ]${RS}\n";
    printf("  ${W}%-20s %-10s %-30s %-40s${RS}\n", "SOURCE IP", "STRIKES", "INTENSITY", "HOSTNAME (IP NEIGH)");
    print "  " . ("${D}─${RS}" x ($box_width - 4)) . "\n";

    my $loc_count = 0;
    foreach my $ip (@sorted_ips) {
        last if $loc_count >= 5;
        next unless $ip =~ /^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/;

        $loc_count++;
        my $hostname = get_ip_owner($ip);
        my $bar = get_bar($ips{$ip}, $max_val, $B);
        printf("  ${C}%-20s ${W}%-10d %-s ${B}%-40s${RS}\n", $ip, $ips{$ip}, $bar, $hostname);
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

    # --- FOOTER ---
    print "\n${B}┌" . ("─" x $box_width) . "┐${RS}\n";
    print_box_line("${W}" . get_sys_stats() . "${RS}");
    print "${B}└" . ("─" x $box_width) . "┘${RS}\n";
    print "  ${D}Last Check: " . localtime() . " | WHOIS Cache: " . scalar(keys %whois_cache) . " entries${RS}\n";
    
    sleep($refresh_rate);
}
