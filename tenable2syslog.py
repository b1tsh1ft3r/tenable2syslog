################################################################################
# Tenable.SC Scan export to Syslog
#
# Ensure you pass a string with the name of the scan when calling the script
# and hours to look backward from now. This will grab all data and output it
# into a syslog format and post it to a syslog host.
# 
# Usage: python3 tenable2syslog.py "my scan" --hours 72
################################################################################
 
from tenable.sc import TenableSC
from datetime import datetime, timedelta
import argparse
import base64
import syslog
import socket
import sys
import json
 
SC_HOST = 'tenableserver.com'
SC_USERNAME = 'tenable_user'
SC_PASSWORD = base64.b64decode('base64-encoded-password-here').decode('utf-8')
SYSLOG_SERVER = 'syslog.com'
SYSLOG_PORT   = 514
SCAN_ID = None
 
# Parse command-line arguments
parser = argparse.ArgumentParser(description='Search for a scan by name.')
parser.add_argument('search_string', help='The string to search for in scan names.')
parser.add_argument('--hours', type=int, default=48, help='Number of hours to go back in time from now to search for a scan (default: 48).')
args = parser.parse_args()
 
try:
    #---------------------------------------------------------------------------
    sc = TenableSC(SC_HOST)                     # Create a Tenable.sc object
    sc.login(SC_USERNAME, SC_PASSWORD)          # Attempt to log in
    print("Logged in...")
    #---------------------------------------------------------------------------
    # Set start and end time.
    current_time = datetime.now()
    start_time = current_time - timedelta(hours=args.hours)
    end_time = current_time
    #---------------------------------------------------------------------------
    # Convert to epoch timestamps
    start_time = int(start_time.timestamp())
    end_time = int(end_time.timestamp())
    #---------------------------------------------------------------------------
    # Get a list of all scans available
    scan_instances = sc.scan_instances.list(fields=['id', 'name'], start_time=start_time, end_time=end_time)
    #---------------------------------------------------------------------------
    # sift through the scan instances and search for the specified name we supplied
    for scan in scan_instances['usable']:
        if args.search_string in scan['name']:
            SCAN_ID = scan['id']
            break  # Found the desired scan, so exit the search loop
    #---------------------------------------------------------------------------
    # If SCAN_ID is still None, exit with error and info
    if SCAN_ID is None:
        print(f"Scan '{args.search_string}' not found! If this scan exists, try changing number of hours to look backward from now using --hours argument.")
        sys.exit(1)
    #---------------------------------------------------------------------------
    # Define query filters.
    query_filters = (
        ('severity', '=', '4,3,2'),  # Only Critical, High, Medium severity
        #('exploitAvailable', '=', 'true'),  # Enabling this reduces the number of valid findings.
    )
    #---------------------------------------------------------------------------
    # Retrieve results based on our above query filters
    vuln_list = sc.analysis.scan(SCAN_ID, *query_filters)
    #---------------------------------------------------------------------------
    if vuln_list:
        syslog_messages = []  # Make an array to store syslog messages into
        #-----------------------------------------------------------------------
        for vuln in vuln_list:
        #-----------------------------------------------------------------------
            severity = vuln.get('severity', {}).get('name', 'N/A')
            ip = vuln.get('ip', 'N/A')
            port = vuln.get('port', 'N/A')
            protocol = vuln.get('protocol', 'N/A')
            pluginName = vuln.get('pluginName', 'N/A')
            operatingSystem = vuln.get('operatingSystem', 'N/A')
            cvss_v3_base_score = vuln.get('cvssV3BaseScore', 'N/A')
            dnsName = vuln.get('dnsName', 'N/A')
            #-------------------------------------------------------------------
            # Convert firstSeen and lastSeen from epoch to month/day/year format
            first_seen_epoch = vuln.get('firstSeen', 'N/A')
            last_seen_epoch = vuln.get('lastSeen', 'N/A')
            try:
                first_seen = datetime.fromtimestamp(int(first_seen_epoch)).strftime('%m/%d/%Y')
                last_seen = datetime.fromtimestamp(int(last_seen_epoch)).strftime('%m/%d/%Y')
            except (ValueError, TypeError):
                first_seen = 'N/A'
                last_seen = 'N/A'
            #-------------------------------------------------------------------
            # Create a one-line syslog message format
            syslog_msg = f"Source: Tenable, Scan ID: {SCAN_ID}, Severity: {severity}, IP: {ip}, Port: {port}, Protocol: {protocol}, Plugin Name: {pluginName}, Operating System: {operatingSystem}, CVSSv3 Base Score: {cvss_v3_base_score}, DNS Name: {dnsName}, First Seen: {first_seen}, Last Seen: {last_seen}"
            syslog_messages.append(syslog_msg) # Add syslog messagae to array of messages
        #-----------------------------------------------------------------------
        # Connect to syslog server and send batch of syslog messages
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((SYSLOG_SERVER, SYSLOG_PORT))
                batch_msg = '\n'.join(syslog_messages)
                sock.sendall(batch_msg.encode('utf-8'))
        except ConnectionError as e:
            print(f"Error: Unable to connect to the syslog endpoint - {e}")
            sys.exit(1)
    #---------------------------------------------------------------------------
    else:
        print("No data found based on your query filters.")
    #---------------------------------------------------------------------------
except Exception as e:
    print(f"Error: {e}")
 
finally:
    sc.logout()