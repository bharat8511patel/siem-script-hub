"""
Google Workspace Audit Log Collector - FortiSIEM FORMAT
Pulls audit events and sends to syslog server in FortiSIEM-compatible format.
Format: <134>timestamp ip java: [Google_Apps_{app}_{event}]:[key]=value,[key]=value,...
- First run: pulls last 10 minutes
- Subsequent runs: pulls from last timestamp to now
"""

import os
import json
import socket
from datetime import datetime, timedelta, timezone
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Configuration
SCOPES = ['https://www.googleapis.com/auth/admin.reports.audit.readonly']

# Admin user email (must be a Workspace admin who delegated access to the service account)
DELEGATED_ADMIN_EMAIL = 'info@varachha.bank.in'

# Syslog Server Configuration
SYSLOG_SERVER_IP = '192.168.10.250'
SYSLOG_SERVER_PORT = 514

# Timestamp file to track last pull time (same directory as script)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TIMESTAMP_FILE = os.path.join(SCRIPT_DIR, 'last_timestamp_raw.txt')

# Service Account Credentials (hardcoded)
SERVICE_ACCOUNT_INFO = {
    "type": "service_account",
    "project_id": "YOUR_PROJECT_ID_HERE",
    "private_key_id": "YOUR_PRIVATE_KEY_ID_HERE",
    "private_key": "YOUR_PRIVATE_KEY_HERE",
    "client_email": "YOUR_SERVICE_ACCOUNT_EMAIL_HERE",
    "client_id": "YOUR_CLIENT_ID_HERE",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "YOUR_CERT_URL_HERE",
    "universe_domain": "googleapis.com"
}

# Applications to fetch audit logs from
APPLICATIONS = [
    'login',
    'admin',
    'drive',
    'calendar',
    'token',
    'chat',
    'meet',
    'groups',
    'gcp',
    'user_accounts',
]


def get_credentials():
    """Create credentials with domain-wide delegation."""
    credentials = service_account.Credentials.from_service_account_info(
        SERVICE_ACCOUNT_INFO,
        scopes=SCOPES
    )
    delegated_credentials = credentials.with_subject(DELEGATED_ADMIN_EMAIL)
    return delegated_credentials


def read_last_timestamp():
    """Read the last timestamp from file. Returns None if file doesn't exist."""
    try:
        if os.path.exists(TIMESTAMP_FILE):
            with open(TIMESTAMP_FILE, 'r') as f:
                timestamp_str = f.read().strip()
                if timestamp_str:
                    return timestamp_str
    except Exception as e:
        print(f"Error reading timestamp file: {e}")
    return None


def save_timestamp(timestamp_str):
    """Save the current timestamp to file."""
    try:
        with open(TIMESTAMP_FILE, 'w') as f:
            f.write(timestamp_str)
        print(f"  Timestamp saved: {timestamp_str}")
    except Exception as e:
        print(f"Error saving timestamp: {e}")


def get_time_range():
    """Get the time range based on last timestamp or default to last 10 minutes."""
    now = datetime.now(timezone.utc)
    end_time = now.strftime('%Y-%m-%dT%H:%M:%S.000Z')

    # Check for existing timestamp
    last_timestamp = read_last_timestamp()

    if last_timestamp:
        print(f"  Found last timestamp: {last_timestamp}")
        start_time = last_timestamp
    else:
        # First run - pull last 10 minutes
        ten_min_ago = now - timedelta(minutes=10)
        start_time = ten_min_ago.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        print(f"  First run - pulling last 10 minutes")

    return start_time, end_time


def send_to_syslog_server(syslog_lines):
    """Send syslog lines to the syslog server via UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent_count = 0
    failed_count = 0

    print(f"\nSending {len(syslog_lines)} logs to {SYSLOG_SERVER_IP}:{SYSLOG_SERVER_PORT}...")

    for line in syslog_lines:
        try:
            message = line.encode('utf-8')
            sock.sendto(message, (SYSLOG_SERVER_IP, SYSLOG_SERVER_PORT))
            sent_count += 1
        except Exception as e:
            failed_count += 1
            if failed_count == 1:
                print(f"  Error sending log: {e}")

    sock.close()
    print(f"  Sent: {sent_count}, Failed: {failed_count}")
    return sent_count, failed_count


def flatten_dict(d, parent_key='', sep='.'):
    """Flatten a nested dictionary into dot-notation keys."""
    items = []
    if isinstance(d, dict):
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(flatten_dict(v, new_key, sep).items())
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        items.extend(flatten_dict(item, f"{new_key}[{i}]", sep).items())
                    else:
                        items.append((f"{new_key}[{i}]", item))
            else:
                items.append((new_key, v))
    return dict(items)


def convert_to_fortisiem_format(activity):
    """Convert activity to FortiSIEM-compatible syslog format."""
    syslog_lines = []

    # Extract key info
    app_name = activity.get('id', {}).get('applicationName', 'unknown')
    ip_address = activity.get('ipAddress', '0.0.0.0')
    event_time = activity.get('id', {}).get('time', '')

    # Parse event timestamp for syslog header
    try:
        dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
        timestamp = dt.strftime('%b %d %H:%M:%S')
    except:
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')

    # Process each event in the activity
    events = activity.get('events', [])
    if not events:
        events = [{}]

    for event in events:
        event_type = event.get('type', 'unknown')
        event_name = event.get('name', 'unknown')

        # Build event identifier: [Google_Apps_{app}_{event_name}]
        event_id = f"[Google_Apps_{app_name}_{event_name}]"

        # Build key-value pairs
        kv_pairs = []

        # Add static fields
        kv_pairs.append("[eventSeverity]=PHL_INFO")

        # Add actor info
        actor = activity.get('actor', {})
        if actor.get('profileId'):
            kv_pairs.append(f"[actor.profileId]={actor['profileId']}")
        if actor.get('email'):
            kv_pairs.append(f"[actor.email]={actor['email']}")

        # Add ID fields
        id_info = activity.get('id', {})
        if id_info.get('applicationName'):
            kv_pairs.append(f"[id.applicationName]={id_info['applicationName']}")
        if id_info.get('time'):
            kv_pairs.append(f"[id.time]={id_info['time']}")
        if id_info.get('customerId'):
            kv_pairs.append(f"[id.customerId]={id_info['customerId']}")
        if id_info.get('uniqueQualifier'):
            kv_pairs.append(f"[id.uniqueQualifier]={id_info['uniqueQualifier']}")

        # Add kind
        if activity.get('kind'):
            kv_pairs.append(f"[kind]={activity['kind']}")

        # Add IP and network info
        if activity.get('ipAddress'):
            kv_pairs.append(f"[ipAddress]={activity['ipAddress']}")

        network_info = activity.get('networkInfo', {})
        if network_info.get('regionCode'):
            kv_pairs.append(f"[networkInfo.regionCode]={network_info['regionCode']}")
        if network_info.get('subdivisionCode'):
            kv_pairs.append(f"[networkInfo.subdivisionCode]={network_info['subdivisionCode']}")
        if network_info.get('ipAsn'):
            for i, asn in enumerate(network_info['ipAsn']):
                kv_pairs.append(f"[networkInfo.ipAsn[{i}]]={asn}")

        # Add event info
        kv_pairs.append(f"[event.type]={event_type}")
        kv_pairs.append(f"[event.name]={event_name}")

        # Add event parameters
        parameters = event.get('parameters', [])
        for param in parameters:
            param_name = param.get('name', '')
            # Get value from various possible fields
            value = param.get('value') or param.get('boolValue') or param.get('intValue') or param.get('multiValue')
            if value is not None:
                if isinstance(value, list):
                    value = ','.join(str(v) for v in value)
                elif isinstance(value, bool):
                    value = str(value).lower()
                kv_pairs.append(f"[event.parameters.{param_name}]={value}")

        # Add resource IDs from event
        resource_ids = event.get('resourceIds', [])
        for i, rid in enumerate(resource_ids):
            kv_pairs.append(f"[event.resourceIds[{i}]]={rid}")

        # Add resource details
        resource_details = activity.get('resourceDetails', [])
        for i, rd in enumerate(resource_details):
            if rd.get('id'):
                kv_pairs.append(f"[resourceDetails[{i}].id]={rd['id']}")
            if rd.get('type'):
                kv_pairs.append(f"[resourceDetails[{i}].type]={rd['type']}")
            if rd.get('title'):
                kv_pairs.append(f"[resourceDetails[{i}].title]={rd['title']}")

        # Add etag
        if activity.get('etag'):
            kv_pairs.append(f"[etag]={activity['etag']}")

        # Build syslog line
        # Format: <134>Jan 07 08:11:01 {ip} java: [Google_Apps_{app}_{event}]:[key]=value,[key]=value,...
        kv_string = ','.join(kv_pairs)
        syslog_line = f"<134>{timestamp} {ip_address} java: {event_id}:{kv_string}"
        syslog_lines.append(syslog_line)

    return syslog_lines


def fetch_audit_logs(service, application, start_time, end_time):
    """Fetch audit logs for a specific application."""
    all_events = []
    page_token = None

    print(f"  Fetching {application} logs...")

    try:
        while True:
            results = service.activities().list(
                userKey='all',
                applicationName=application,
                startTime=start_time,
                endTime=end_time,
                maxResults=1000,
                pageToken=page_token
            ).execute()

            activities = results.get('items', [])
            all_events.extend(activities)

            page_token = results.get('nextPageToken')
            if not page_token:
                break

        if all_events:
            print(f"    Found {len(all_events)} events")
        return all_events

    except HttpError as e:
        if e.resp.status == 400:
            pass  # Application not available or no data
        elif e.resp.status == 403:
            print(f"    Access denied for '{application}'")
        else:
            print(f"    Error: {e}")
        return []


def main():
    print("=" * 60)
    print("Google Workspace Audit Log Collector - RAW JSON")
    print(f"Run time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Get time range
    print("\nDetermining time range...")
    start_time, end_time = get_time_range()
    print(f"  Start: {start_time}")
    print(f"  End:   {end_time}")

    # Initialize credentials and service
    print("\nAuthenticating...")
    try:
        credentials = get_credentials()
        service = build('admin', 'reports_v1', credentials=credentials)
        print("  Authentication successful")
    except Exception as e:
        print(f"  Authentication failed: {e}")
        return

    # Collect all events
    print("\nFetching audit logs...")
    all_syslog_lines = []
    total_events = 0

    for app in APPLICATIONS:
        events = fetch_audit_logs(service, app, start_time, end_time)
        for event in events:
            # Convert to FortiSIEM format
            syslog_lines = convert_to_fortisiem_format(event)
            all_syslog_lines.extend(syslog_lines)
        total_events += len(events)

    # Print sample log for debugging
    if all_syslog_lines:
        print("\nSample log message:")
        print("-" * 40)
        print(all_syslog_lines[0][:500] + "..." if len(all_syslog_lines[0]) > 500 else all_syslog_lines[0])
        print("-" * 40)

    # Send to syslog server
    if all_syslog_lines:
        sent, failed = send_to_syslog_server(all_syslog_lines)

        # Only save timestamp if logs were sent successfully
        if sent > 0:
            print("\nUpdating timestamp...")
            save_timestamp(end_time)
    else:
        print("\nNo new events found.")
        # Still update timestamp to avoid re-checking same period
        print("\nUpdating timestamp...")
        save_timestamp(end_time)

    print(f"\nSummary:")
    print(f"  Events collected: {total_events}")
    print(f"  Syslog lines sent: {len(all_syslog_lines)}")
    print(f"  Syslog server: {SYSLOG_SERVER_IP}:{SYSLOG_SERVER_PORT}")
    print(f"  Timestamp file: {TIMESTAMP_FILE}")

    print("\n" + "=" * 60)
    print("Complete!")
    print("=" * 60)


if __name__ == '__main__':
    main()
