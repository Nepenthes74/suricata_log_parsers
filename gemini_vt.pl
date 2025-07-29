#!/usr/bin/perl
#
# vt.pl - Refactored
#
# This script monitors a Suricata filestore directory, uploads new files to
# VirusTotal for analysis, and handles the results. Malicious files are
# copied to an 'infected' directory, and all processed files are removed
# from the filestore to prevent re-analysis.

use strict;
use warnings;
use utf8;
use open ':std', ':encoding(UTF-8)'; # This line fixes the "Wide character" warning

# Core Modules
use File::Find;
use File::Copy;
use File::Remove qw(remove);
use Socket;

# CPAN Modules
use LWP::UserAgent;
use JSON::MaybeXS;
use List::Util qw(uniqstr);
use Term::ANSIColor qw(:constants);

# --- CONFIGURATION ---
my %config = (
    api_key       => 'ee6e69074a21711e1125bbe678b595e40b2cc82ff3f82cd923a9100f7d50e77b',
    filestore_dir => '/var/log/suricata/filestore/',
    infected_dir  => '/home/vile/log/suricata/infected/',
    sent_log_file => '/home/vile/log/suricata/sent_files.txt',
    vt_api_upload => 'https://www.virustotal.com/vtapi/v2/file/scan',
    vt_api_report => 'https://www.virustotal.com/vtapi/v2/file/report',
);

# --- MAIN EXECUTION ---
main();

sub main {
    print_banner();

    my @new_files = find_new_files();
    my $file_count = scalar(@new_files);

    # If no files are found, print a pretty "all clear" message and exit.
    if (!$file_count) {
        # Set width to match the ASCII art banner
        my $banner_width = 71; 
        my $line = GREEN . ('~' x $banner_width) . RESET;
        my $message = "No new files found to process. All clear! ✔";
        
        # Center the message inside the box
        my $msg_len = length($message) - 2; # Account for wide checkmark char
        my $total_width = $banner_width - 2; # Width inside the | |
        my $padding_total = $total_width - $msg_len;
        my $padding_left = ' ' x int($padding_total / 2);
        my $padding_right = ' ' x ($padding_total - int($padding_total / 2));

        print "\n$line\n";
        print GREEN, "|", $padding_left, BOLD YELLOW, $message, RESET, $padding_right, GREEN, "|\n", RESET;
        print "$line\n\n";
        return;
    }

    print_status(0, 'Discovered', "$file_count new file(s) to analyze.", BOLD);

    foreach my $file_path (@new_files) {
        my ($sha256) = $file_path =~ /([a-f0-9]{64})$/i;
        next unless $sha256;

        print_section("START", $sha256);
        
        my $upload_results = upload_file($file_path);
        next unless $upload_results && $upload_results->{sha256};
        
        my $report = get_report($upload_results->{sha256});
        next unless $report;
        
        process_report($file_path, $report);

        log_processed_file($sha256);

        print_section("DONE", $sha256);
    }
    print BOLD GREEN, "Script finished.\n", RESET;
}

# --- SUBROUTINES ---

##
# Finds files in the filestore that have not been processed yet.
#
sub find_new_files {
    print_status(0, 'Action', "Searching in $config{filestore_dir}", CYAN);
    my @all_files;

    my $wanted = sub {
        return unless -f $_ && /[a-f0-9]{64}$/i;
        push @all_files, $File::Find::name;
    };

    find({ wanted => $wanted, no_chdir => 1 }, $config{filestore_dir});
    my %sent_hashes = get_sent_hashes();

    my @new_files;
    for my $file (@all_files) {
        my ($sha256) = $file =~ /([a-f0-9]{64})$/i;
        push @new_files, $file if $sha256 && !exists $sent_hashes{$sha256};
    }
    return @new_files;
}

##
# Reads the log of sent files into a hash for quick lookups.
#
sub get_sent_hashes {
    my %sent;
    if (open my $fh, '<', $config{sent_log_file}) {
        while (my $line = <$fh>) {
            chomp $line;
            $sent{$line} = 1 if $line;
        }
        close $fh;
    }
    return %sent;
}


##
# Uploads a single file to VirusTotal for scanning.
#
sub upload_file {
    my ($file_path) = @_;
    print_status(1, 'Action', 'Uploading file', YELLOW);
    
    my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 1 });
    my $response = $ua->post( $config{vt_api_upload}, Content_Type => 'form-data',
        Content => [ apikey => $config{api_key}, file => [$file_path], ],
    );

    unless ($response->is_success) {
        print_status(2, 'Error', "Upload failed: " . $response->status_line, RED);
        return;
    }
    
    my $decoded_json = eval { decode_json($response->content) };
    if ($@) {
        print_status(2, 'Error', "Could not decode JSON response.", RED);
        return;
    }
    
    unless ($decoded_json && $decoded_json->{sha256}) {
        print_status(2, 'Error', $decoded_json->{verbose_msg} || 'Invalid API response', RED);
        return;
    }
    
    print_status(2, 'Result', 'Scan successfully queued.', GREEN);
    return $decoded_json;
}

##
# Retrieves the scan report for a given SHA256 hash.
#
sub get_report {
    my ($sha256) = @_;
    print_status(1, 'Action', 'Retrieving report', YELLOW);

    my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 1 });
    my $attempts = 0;

    while ($attempts < 5) {
        my $response = $ua->post( $config{vt_api_report},
            [ apikey => $config{api_key}, resource => $sha256, ]
        );

        unless ($response->is_success) {
            print_status(2, 'Error', "Report request failed: " . $response->status_line, RED);
            return;
        }

        my $report = eval { decode_json($response->content) };
        if ($@) {
             print_status(2, 'Error', "Failed to decode JSON response.", RED);
             return;
        }

        if ($report && $report->{response_code} == 1) {
            print_status(2, 'Result', 'Report received.', GREEN);
            return $report;
        }

        print_status(2, 'Status', 'Report not ready, waiting 60s...', YELLOW);
        countdown(60);
        $attempts++;
    }
    
    print_status(2, 'Error', "Failed to retrieve report after multiple attempts.", RED);
    return;
}

##
# Processes the final report, copies infected files, and cleans up.
#
sub process_report {
    my ($file_path, $report) = @_;

    my $positives = $report->{positives} || 0;
    my $total     = $report->{total}     || 0;
    
    print_status(1, 'Scan Date', $report->{scan_date} || 'N/A', BOLD);
    my $detection_color = $positives > 0 ? BOLD RED : GREEN;
    print_status(1, 'Detection', "$positives / $total", $detection_color);

    if ($positives > 0) {
        copy_infected_file($file_path);
    } else {
        print_status(2, 'Result', 'File is clean.', GREEN);
    }
    
    cleanup_file($file_path);
}

##
# Copies a malicious file to the infected directory.
#
sub copy_infected_file {
    my ($file_path) = @_;
    print_status(1, 'Action', 'Copying malicious file', RED);
    
    eval {
        copy($file_path, $config{infected_dir});
        print_status(2, 'Result', "Copied to $config{infected_dir}", GREEN);
    } or do {
        print_status(2, 'Error', "Failed to copy file: $@", RED);
    };
}

##
# Removes a file from the filestore.
#
sub cleanup_file {
    my ($file_path) = @_;
    print_status(1, 'Action', 'Cleaning up original file', YELLOW);
    remove($file_path);
}

##
# Appends a successfully processed SHA256 to the log file.
#
sub log_processed_file {
    my ($sha256) = @_;
    open my $fh, '>>', $config{sent_log_file} or do {
        print_status(0, 'CRITICAL', "Could not write to log file: $!", BOLD RED);
        return;
    };
    print $fh "$sha256\n";
    close $fh;
}

# --- HELPER SUBROUTINES ---

##
# Prints the script's startup banner.
#
sub print_banner {
    print BOLD, GREEN, q{
 /$$    /$$ /$$$$$$$$       /$$$$$$   /$$$$$$   /$$$$$$  /$$   /$$
| $$   | $$|__  $$__/      /$$__  $$ /$$__  $$ /$$__  $$| $$$ | $$
| $$   | $$   | $$        | $$  \__/| $$  \__/| $$  \ $$| $$$$| $$
|  $$ / $$/   | $$ /$$$$$$|  $$$$$$ | $$      | $$$$$$$$| $$ $$ $$
 \  $$ $$/    | $$|______/ \____  $$| $$      | $$__  $$| $$  $$$$
  \  $$$/     | $$         /$$  \ $$| $$    $$| $$  | $$| $$\  $$$
   \  $/      | $$        |  $$$$$$/|  $$$$$$/| $$  | $$| $$ \  $$
    \_/       |__/         \______/  \______/ |__/  |__/|__/  \__/
}, RESET, "\n";
}

##
# A helper for printing consistently formatted status lines.
#
sub print_status {
    my ($level, $label, $value, $color) = @_;
    my $indent = '  ' x $level;
    $color ||= RESET;

    printf "%s%-18s: %s%s%s\n",
        $indent,
        $label,
        $color,
        $value,
        RESET;
}

##
# Utility to display a countdown timer in the console.
#
sub countdown {
    my ($duration) = @_;
    my $end_time = time + $duration;
    
    my $indent = '  ' x 2; 
    print "$indent               : ";

    while (my $remaining = $end_time - time) {
        last if $remaining < 0;
        my $mins = int($remaining / 60);
        my $secs = $remaining % 60;
        printf("\r%s               : %sWaiting %02d:%02d%s", $indent, YELLOW, $mins, $secs, RESET);
        sleep 1;
    }
    print "\r" . " " x 50 . "\r";
}

##
# Utility to print a formatted section header.
#
sub print_section {
    my ($title, $sha256) = @_;
    my $color = ($title eq 'START') ? BOLD RED : BOLD GREEN;
    my $line = GREEN . "~" x 28 . RESET;
    print "\n$line| $color$title", RESET, " |$line\n";
    print_status(0, 'Processing SHA256', $sha256, BOLD YELLOW);
}
