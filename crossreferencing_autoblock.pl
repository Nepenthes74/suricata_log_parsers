#!/usr/bin/perl

#
# This script continuously cross-references active network connections with
# Suricata alert logs, providing a compact, color-coded output
# for each IP that has generated an alert.
#
# Features:
# - Runs in a continuous loop with a 10-second pause.
# - Finds established foreign IPs using the 'ss' command.
# - Searches for those IPs in the Suricata eve.json log.
# - ONLY prints information for IPs that are found in the logs with an alert.
# - Resolves IP addresses to hostnames.
# - Provides a color-coded output for each alerting IP.
# - MODIFIED: Script now only sets default DROP policies on INPUT, FORWARD, and OUTPUT chains,
#             without adding specific source IP-based DROP rules.
# - MODIFIED: IPTables flush now occurs *only* when an IP triggers an alert and is about to trigger policy changes,
#             ensuring a clean slate before new DROP policies are applied.
# - FIXED: Corrected array dereferencing issue in add_iptables_block_rule (though no longer used for adding rules).
# - NEW: Script now stops after successfully setting default policies and prints the iptables -vnL output.
# - NEW: Policies are now applied only when an alert with priority 1 or 2 is detected for an IP.
# - NEW: Enhanced final output to include details of the alert that triggered the policy change.
# - NEW: Improved readability of the "skipping policy change" message by breaking it into multiple lines.
# - NEW: Signatures are now printed on a new line for better readability in the alert report.
# - UPDATED: "Skipping policy change" message formatted into two lines, with the last line in green.
#

use strict;
use warnings;
use JSON;
use Time::HiRes qw(sleep);
use Socket; # For inet_aton and gethostbyaddr
use Term::ANSIColor;

# Enable UTF-8 for standard input/output to prevent "Wide character" warnings.
use open ':std', ':encoding(UTF-8)';

# --- Configuration ---
my $eve_json_path = '/var/log/suricata/eve.json';
my $check_interval = 15; # Seconds to wait between checks

# IPTABLES AUTO-BLOCKING CONFIGURATION (!!! DANGER ZONE !!!)
my $enable_auto_blocking = 1; # Set to 1 to enable automatic iptables blocking
                              # !!! STRONGLY RECOMMENDED TO KEEP THIS AS 0 FOR TESTING !!!
                              # !!! ONLY SET TO 1 IF YOU FULLY UNDERSTAND THE RISKS !!!

my $BLOCKING_THRESHOLD = 1;   # Number of alerts from an IP before it's blocked.
                              # Set to 1 to trigger policy changes on first alert.

# A hash to keep track of IPs that have already triggered policy changes by this script
# to avoid re-applying policies and spamming logs.
my %policy_applied_ips;

# Flag to indicate if policy changes have occurred in the current run
my $policy_changed_occurred = 0;

# Variables to store details of the alert that triggered the policy change
my $triggered_ip = '';
my $triggered_total_alerts = 0;
my $triggered_has_high_priority_alert = 0;
my $triggered_signatures = '';


# --- Color Definitions ---
my $color_reset    = color('reset');
my $color_red      = color('bold red');
my $color_yellow   = color('bold yellow');
my $color_cyan     = color('bold cyan');
my $color_blue     = color('bold blue');
my $color_white    = color('bold white');
my $color_green    = color('bold green'); # Added for success messages

# --- Main Execution Loop ---
while (1) {
    system('clear');
    print $color_cyan . "--- Suricata Live Alert Monitor | Running check at: " . localtime() . " ---\n" . $color_reset;
    print $color_cyan . "--- Auto-Blocking (Policy Drop): " . ($enable_auto_blocking ? $color_red."ENABLED (Threshold: $BLOCKING_THRESHOLD, Priority 1/2)" : $color_green."DISABLED"). " ---" . $color_reset . "\n\n";

    # Get currently connected foreign IPs
    my $foreign_ips = get_foreign_ips();

    if (!%$foreign_ips) {
        print $color_yellow . "No established foreign IP addresses found at this time.\n" . $color_reset;
    } else {
        # Find alerts associated with those IPs
        my $alert_data = process_suricata_logs($eve_json_path, $foreign_ips);

        # Print the compact, one-line report and potentially apply policies
        apply_policies_and_report($alert_data);
    }

    # Check if a policy change action occurred during this cycle
    if ($policy_changed_occurred) {
        print "\n" . $color_red . "Default DROP policies applied. Script stopping.\n" . $color_reset;
        print $color_red . "Triggering Alert Details:\n" . $color_reset;
        print $color_red . "  Foreign Host: $triggered_ip\n" . $color_reset;
        print $color_red . "  Total Alerts: $triggered_total_alerts\n" . $color_reset;
        print $color_red . "  High Priority Alert (1 or 2) Detected: " . ($triggered_has_high_priority_alert ? "Yes" : "No") . "\n" . $color_reset;
        print $color_red . "  Signatures: $triggered_signatures\n" . $color_reset;

        print $color_blue . "--- Current IPTables Rules (sudo /usr/sbin/iptables -vnL) ---\n" . $color_reset;
        system('sudo /usr/sbin/iptables -vnL');
        print $color_blue . "--- End IPTables Rules ---\n" . $color_reset;
        exit 0; # Exit the script after applying policies and displaying rules
    }

    print "\n" . $color_cyan . "--- Waiting for $check_interval seconds... (Press Ctrl+C to exit) ---\n" . $color_reset;
    sleep($check_interval);
}

# --- Subroutines ---

sub get_foreign_ips {
    my %unique_ips;
    my $ss_cmd = "ss -ntu state established";

    open(my $ss_pipe, '-|', $ss_cmd) or die "Can't run '$ss_cmd': $!";
    while (my $line = <$ss_pipe>) {
        next if $line =~ /^Netid/;
        my @columns = split /\s+/, $line;
        my $peer_address_port = $columns[-1];
        if ($peer_address_port && $peer_address_port =~ /^(?:\[)?([0-9a-f:.]+)(?:\])?:[0-9]+$/) {
            my $ip = $1;
            # Filter out local, loopback, and private network addresses
            unless ($ip =~ /^(127\.|10\.|192\.(168)\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|::1|fe80:|fc00:)/) {
                $unique_ips{$ip} = 1;
            }
        }
    }
    close $ss_pipe;
    return \%unique_ips;
}

sub resolve_ip {
    my ($ip) = @_;
    my $packed_ip = inet_aton($ip);
    my $hostname = gethostbyaddr($packed_ip, AF_INET);
    return $hostname ? $hostname : "[non-resolvable]";
}

sub process_suricata_logs {
    my ($log_file, $ips_to_check) = @_;
    my %alerts_by_ip;

    # This opens the log file for reading. For a continuous monitor,
    # you might want to consider using `tail -F` or tracking file offsets
    # to only process new lines, especially on very busy logs.
    # For simplicity, this re-reads the whole file each time, which can be
    # inefficient for large logs.
    open(my $log_fh, '<', $log_file) or die "Could not open '$log_file': $!";
    while (my $line = <$log_fh>) {
        my $event;
        eval { $event = decode_json($line); };
        next if $@; # Skip if JSON parsing failed

        if ($event->{event_type} && $event->{event_type} eq 'alert') {
            my $src_ip = $event->{src_ip};
            my $dest_ip = $event->{dest_ip};
            my $alerting_ip;

            # Check if src_ip or dest_ip exist and are non-empty AND are in our foreign_ips list
            if (defined $src_ip && exists $ips_to_check->{$src_ip}) {
                $alerting_ip = $src_ip;
            } elsif (defined $dest_ip && exists $ips_to_check->{$dest_ip}) {
                # If dest_ip is a foreign IP AND it's the one we're tracking, use it.
                # This handles cases where our machine is the source of an alert *to* a foreign IP
                # or if an alert identifies a foreign destination as the "alerting" party.
                $alerting_ip = $dest_ip;
            } else {
                next; # Skip if alert not related to a currently connected foreign IP
            }

            my $signature = $event->{alert}->{signature} || 'No signature';
            my $action = $event->{alert}->{action} || 'unknown';
            my $priority = $event->{alert}->{priority} || 0; # Get alert priority

            # Aggregate data for the IP
            $alerts_by_ip{$alerting_ip}{total_alerts}++;
            $alerts_by_ip{$alerting_ip}{signatures}{$signature} = 1; # Use a hash to store unique signatures

            # Check if this alert has priority 1 or 2
            if ($priority == 1 || $priority == 2) {
                $alerts_by_ip{$alerting_ip}{has_high_priority_alert} = 1;
            }

            # If any alert action is 'blocked' or 'dropped', mark the IP as such
            if ($action eq 'blocked' || $action eq 'dropped') {
                $alerts_by_ip{$alerting_ip}{is_suricata_blocked} = 1; # Renamed to avoid confusion with iptables block
            }
        }
    }
    close $log_fh;
    return \%alerts_by_ip;
}

sub apply_policies_and_report {
    my ($alert_data) = @_;
    my $local_policy_changed_occurred = 0; # Local flag for this function call

    if (!keys %$alert_data) {
        print $color_yellow . "No alerts found for any currently connected foreign IPs.\n" . $color_reset;
        return;
    }

    print $color_white . "--- Alerting Connections: ---\n" . $color_reset;

    foreach my $ip (sort keys %$alert_data) {
        my $data = $alert_data->{$ip};
        my $hostname = resolve_ip($ip);

        # Determine status and color based on Suricata's action
        my ($status_tag, $status_color) = $data->{is_suricata_blocked}
            ? ('[SURICATA BLOCKED]', $color_red)
            : ('[SURICATA ALERT]', $color_yellow);

        my $total = $data->{total_alerts};
        my $signatures_str = join(" | ", sort keys %{$data->{signatures}});

        # Print the formatted lines for each alerting connection
        print $status_color . $status_tag . $color_reset . " "
            . $color_red . $ip . $color_reset . " "
            . $color_blue . "($hostname) " . $color_reset
            . $color_white . "Count: $total\n" . $color_reset
            . $color_yellow . "Signatures: $signatures_str\n" . $color_reset;

        # --- IPTABLES AUTO-POLICY CHANGE LOGIC ---
        if ($enable_auto_blocking) {
            # Check if IP has met the threshold AND policies haven't been applied by us yet
            # AND if a high-priority alert (1 or 2) has been detected for this IP
            if ($total >= $BLOCKING_THRESHOLD && !$policy_applied_ips{$ip} && $data->{has_high_priority_alert}) {
                print $color_red . ">>> POLICY CHANGE: IP $ip exceeded alert threshold ($total alerts) and has high-priority alert <<<\n" . $color_reset;

                # --- IPTABLES FLUSH AND DELETE CHAINS (DANGER ZONE!) ---
                # This will clear ALL existing iptables rules in the filter, nat, and mangle tables.
                # ONLY USE THIS IF YOU ARE CERTAIN NO OTHER SERVICES RELY ON PERSISTENT IPTABLES RULES.
                # This block has been moved here to ensure flushing happens right before applying new policies.
                print $color_yellow . "Flushing existing iptables rules for a clean slate before applying new policies...\n" . $color_reset;
                run_iptables_command('-F');
                run_iptables_command('-X');
                run_iptables_command('-t', 'nat', '-F');
                run_iptables_command('-t', 'nat', '-X');
                run_iptables_command('-t', 'mangle', '-F');
                run_iptables_command('-t', 'mangle', '-X');
                print $color_green . "IPTables flushed.\n" . $color_reset;
                # --- END IPTABLES FLUSH ---

                # Set default policies to DROP for INPUT, FORWARD, and OUTPUT chains
                print $color_yellow . "Setting default policies to DROP for INPUT, FORWARD, and OUTPUT chains...\n" . $color_reset;
                run_iptables_command('-P', 'INPUT', 'DROP');
                run_iptables_command('-P', 'FORWARD', 'DROP');
                run_iptables_command('-P', 'OUTPUT', 'DROP');
                print $color_green . "Default policies set to DROP.\n" . $color_reset;

                # Mark as policy applied by this script
                $policy_applied_ips{$ip} = 1;
                $local_policy_changed_occurred = 1; # Set local flag

                # Store details for final output
                $triggered_ip = $ip;
                $triggered_total_alerts = $total;
                $triggered_has_high_priority_alert = $data->{has_high_priority_alert};
                $triggered_signatures = $signatures_str;

                print $color_red . "    Default DROP policies applied.\n" . $color_reset;

            } elsif ($policy_applied_ips{$ip}) {
                print $color_white . "    Default policies already applied by script.\n" . $color_reset;
            } elsif ($total >= $BLOCKING_THRESHOLD && !$data->{has_high_priority_alert}) {
                # Formatted into two lines, with the last line in green
                print $color_yellow . "    IP $ip met alert threshold ($total alerts). No high-priority (1 or 2) alert detected.\n" . $color_reset;
                print $color_green . "    Skipping policy change.\n" . $color_reset;
            }
        }
    }
    # Update the global flag if policy changes occurred in this report cycle
    $policy_changed_occurred = 1 if $local_policy_changed_occurred;
}


# --- IPTABLES Management Subroutines ---
# !!! DANGER DANGER DANGER !!!
# These functions directly manipulate iptables.
# Misuse can lock you out of your system or disable network connectivity.
# ONLY run this if you understand iptables thoroughly and have a recovery plan.
# For a desktop, consider UFW or manual iptables configuration.
# !!! DANGER DANGER DANGER !!!

# Function to execute iptables command
# This helper function is generic for any iptables command.
sub run_iptables_command {
    my @cmd = @_;
    print $color_blue . "Executing: sudo /usr/sbin/iptables " . join(" ", @cmd) . $color_reset . "\n"; # Added full path
    my $output = `sudo /usr/sbin/iptables @cmd 2>&1`; # Capture stdout and stderr, added full path
    my $exit_code = $?;

    if ($exit_code == 0) {
        print $color_green . "Command successful." . $color_reset . "\n";
    } else {
        # Don't print "Command successful" if it's just a check for existing rule and it didn't find one.
        # This part is a bit tricky, the `iptables -C` check returns non-zero if rule doesn't exist.
        # For flush commands, a non-zero exit code IS a failure.
        # We need more nuanced error reporting here.
        # For now, let's assume any non-zero from run_iptables_command is a failure unless specified.
        print $color_red . "Command failed with exit code " . ($exit_code >> 8) . ":" . $color_reset . "\n";
        print $color_red . "Error Output: $output" . $color_reset . "\n";
        return 0; # Indicate failure
    }
    return 1; # Indicate success
}

# This function is no longer used for adding specific IP-based rules,
# but kept for completeness if future modifications re-introduce it.
sub add_iptables_block_rule {
    my ($ip, $chain, $action, $comment) = @_;

    # Input validation (basic)
    unless ($ip =~ /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/ || $ip =~ /^[0-9a-fA-F:]+$/) {
        warn $color_red . "Invalid IP address format for iptables: $ip\n" . $color_reset;
        return 0;
    }
    unless (grep { $_ eq $chain } qw(INPUT OUTPUT FORWARD)) {
        warn $color_red . "Invalid chain for iptables: $chain. Must be INPUT, OUTPUT, or FORWARD.\n" . $color_reset;
        return 0;
    }
    unless (grep { $_ eq $action } qw(ACCEPT DROP REJECT)) {
        warn $color_red . "Invalid action for iptables: $action. Must be ACCEPT, DROP, or REJECT.\n" . $color_reset;
        return 0;
    }

    # Check if a similar rule already exists to avoid duplicates
    # CORRECTED: Use array reference [] and dereference with @$
    my $check_cmd_array = ['-C', $chain, '-s', $ip, '-j', $action];
    my $check_output = `sudo /usr/sbin/iptables @$check_cmd_array 2>&1`; # Using @$ for array dereferencing
    if ($? == 0) { # Command succeeded, meaning the rule exists
        print $color_white . "    Rule already exists for $ip in $chain chain. Skipping.\n" . $color_reset;
        return 1; # Consider it a success if the rule is already there
    }

    print $color_yellow . "Attempting to add rule to $action packets from $ip in $chain chain...\n" . $color_reset;

    # The actual iptables command to add the rule
    if (run_iptables_command(
        '-A', $chain,         # Append to the specified chain
        '-s', $ip,            # Source IP address
        '-j', $action          # Jump to the specified action (e.g., DROP)
    )) {
        return 1;
    } else {
        return 0;
    }
}
