#!/usr/bin/perl

# ip_alert_summary.pl: A Perl script that parses a Suricata eve.json file
# to provide a summary of alerts grouped by the source IP address.
# It filters out already-disabled SIDs and interactively asks the user
# if they want to add new SIDs to a clean, de-duplicated disable.conf file.
#
# Usage:
# 1. Make the script executable: chmod +x ip_alert_summary.pl
# 2. Run with sudo to have permission to write to disable.conf:
#    sudo ./ip_alert_summary.pl
#
# Dependencies:
# You need to install the JSON and Term::ANSIColor modules from CPAN.
# Run the following commands on Arch Linux:
#   sudo cpanm JSON
#   sudo cpanm Term::ANSIColor

use strict;
use warnings;
use JSON;
use Term::ANSIColor;

# Set STDOUT to handle UTF-8 characters to prevent "Wide character in print" warnings.
binmode STDOUT, ":encoding(UTF-8)";

# --- Configuration ---
my $eve_json_path = '/var/log/suricata/eve.json';
my $disable_conf_path = '/etc/suricata/disable.conf';
# --- End Configuration ---

# Check if the log file exists and is readable.
-f $eve_json_path && -r _ or die "Error: Cannot find or read '$eve_json_path'.\nPlease check the path and permissions.\n";

# Create a new JSON decoder object.
my $json = JSON->new;

# Define colors
my $color_ip     = 'bold yellow';
my $color_desc   = 'cyan';
my $color_sid    = 'bold red';
my $color_sep    = 'white';
my $color_prompt = 'bold green';
my $color_error  = 'bold red';
my $color_info   = 'bold blue';

# Hash to store unique alerts per host IP.
my %host_alerts;

# --- Main Logic ---

# 1. Get currently disabled SIDs
my %disabled_sids = get_disabled_sids();

# 2. Parse the log file, filtering out disabled alerts
parse_log_file(\%disabled_sids);

# 3. Generate the interactive report and handle adding new SIDs
generate_interactive_report(\%disabled_sids);

# --- Subroutines ---

sub get_disabled_sids {
    my %sids;
    # Return empty hash if file doesn't exist, not an error.
    return %sids unless -f $disable_conf_path;

    open(my $fh, '<', $disable_conf_path) or do {
        print colored("Warning: Could not read '$disable_conf_path'. Assuming no SIDs are disabled.\n", $color_error);
        return %sids;
    };

    while (my $line = <$fh>) {
        chomp $line;
        # Remove comments and whitespace
        $line =~ s/#.*//;
        $line =~ s/\s+//g;
        # Add to hash if it's a number
        if ($line =~ /^\d+$/) {
            $sids{$line} = 1;
        }
    }
    close $fh;
    return %sids;
}

sub parse_log_file {
    my ($disabled_sids_ref) = @_;

    open(my $fh, '<:encoding(UTF-8)', $eve_json_path)
      or die "Could not open file '$eve_json_path' $!";
    print "Parsing '$eve_json_path' for alerts (ignoring already disabled SIDs)...\n\n";

    while (my $line = <$fh>) {
        my $data;
        eval {
            # The eval block now *only* wraps the JSON decoding, which is the only part that can fail.
            $data = $json->decode($line);
        };
        if ($@) {
            # warn "Could not parse line as JSON: $line";
            next; # Skip to next line if JSON is invalid
        }

        # The rest of the logic is now outside the eval block.
        if ($data->{event_type} && $data->{event_type} eq 'alert') {
            my $src_ip      = $data->{src_ip} || 'N/A';
            my $description = $data->{alert}->{signature} || 'No Description';
            my $sid         = $data->{alert}->{signature_id} || 'No SID';

            # Skip this alert if the SID is already in our disabled list.
            # This no longer triggers the "Exiting eval via next" message.
            next if exists $disabled_sids_ref->{$sid};
            
            $host_alerts{$src_ip}{$description} = $sid;
        }
    }
    close $fh;
}

sub generate_interactive_report {
    my ($disabled_sids_ref) = @_;
    
    unless (%host_alerts) {
        print "No new, enabled alerts found in the log file.\n";
        exit;
    }

    # Make a copy of the disabled SIDs hash to modify during this session.
    my %all_sids_to_disable = %$disabled_sids_ref;
    my $sids_added_this_session = 0;

    foreach my $ip (sort keys %host_alerts) {
        print colored("Host IP: ", $color_sep);
        print colored($ip, $color_ip);
        print "\n";

        my $alerts = $host_alerts{$ip};
        foreach my $desc (sort keys %$alerts) {
            my $sid = $alerts->{$desc};
            print colored("  - ", $color_sep);
            print colored($desc, $color_desc);
            print colored(" [SID: ", $color_sep);
            print colored($sid, $color_sid);
            print colored("]\n", $color_sep);
        }

        # --- Interactive Part ---
        print colored("\nDisable SIDs for this host? (enter one or more SIDs separated by spaces, or press Enter to skip): ", $color_prompt);
        my $input_line = <STDIN>;
        chomp $input_line;

        my @sids_to_disable_input = split /\s+/, $input_line;

        foreach my $sid (@sids_to_disable_input) {
            if ($sid && $sid =~ /^\d+$/) {
                if (exists $all_sids_to_disable{$sid}) {
                    print colored("Info: SID $sid is already marked for disabling.\n", $color_info);
                } else {
                    $all_sids_to_disable{$sid} = 1;
                    $sids_added_this_session = 1;
                    print colored("Successfully queued SID $sid to be added to '$disable_conf_path'.\n", $color_info);
                }
            }
        }
        print "\n"; # Add a blank line for readability
    }

    if ($sids_added_this_session) {
        print colored("Writing updated list to '$disable_conf_path'...\n", $color_info);
        if (write_disabled_sids(\%all_sids_to_disable)) {
            print colored("Successfully updated '$disable_conf_path'.\n", $color_info);
            print colored("="x50 . "\n", $color_info);
            print colored("IMPORTANT: ", $color_error);
            print colored("New SIDs were added to '$disable_conf_path'.\n", $color_info);
            print colored("Run the following command to apply the changes:\n", $color_info);
            print colored("sudo suricata-update && sudo systemctl restart suricata\n", 'bold white');
            print colored("="x50 . "\n", $color_info);
        }
    }
}

sub write_disabled_sids {
    my ($sids_ref) = @_;
    
    open(my $fh, '>', $disable_conf_path) or do {
        print colored("Error: Could not open '$disable_conf_path' for writing.\n", $color_error);
        print colored("Please make sure you are running this script with 'sudo'.\n", $color_error);
        return 0;
    };

    # Write SIDs sorted numerically for a clean and de-duplicated file.
    foreach my $sid (sort { $a <=> $b } keys %$sids_ref) {
        print $fh "$sid\n";
    }
    close $fh;
    return 1;
}
