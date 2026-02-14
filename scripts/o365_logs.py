"""
Office 365 Activity Log Extraction Script
Pulls audit logs and sends to syslog server

Usage:
    python o365_logs.py    # First run: last 10 min, then incremental
"""

import requests
import json
import time
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import msal
except ImportError:
    print("ERROR: msal package not installed.")
    print("Run: pip install msal requests")
    exit(1)

# =============================================================================
# CONFIGURATION
# =============================================================================
TENANT_ID = "YOUR_TENANT_ID_HERE"
CLIENT_ID = "YOUR_CLIENT_ID_HERE"
CLIENT_SECRET = "YOUR_CLIENT_SECRET_HERE"

SYSLOG_HOST = "127.0.0.1"  # UPDATE THIS
SYSLOG_PORT = 514
SYSLOG_PROTOCOL = "udp"  # "udp" or "tcp"
# =============================================================================


class SyslogSender:
    """Send logs to syslog server"""

    def __init__(self, host, port=514, protocol="udp"):
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.socket = None
        self._connect()

    def _connect(self):
        try:
            if self.protocol == "tcp":
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10)
                self.socket.connect((self.host, self.port))
            else:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            print(f"[+] Connected to syslog {self.host}:{self.port} ({self.protocol.upper()})")
            return True
        except Exception as e:
            print(f"[-] Syslog connection failed: {e}")
            return False

    def send(self, event):
        """Send event to syslog in FortiSIEM format"""
        json_str = json.dumps(event, separators=(',', ':'))
        msg = f"[OFFICE365_EVENT_DATA] = {json_str}"

        try:
            if self.protocol == "tcp":
                self.socket.send((msg + "\n").encode('utf-8'))
            else:
                self.socket.sendto(msg.encode('utf-8'), (self.host, self.port))
            return True
        except Exception:
            return False

    def close(self):
        if self.socket:
            self.socket.close()


class O365ActivityLogs:
    """Extract activity logs from Office 365 Management Activity API"""

    API_URL = "https://manage.office.com/api/v1.0"
    CONTENT_TYPES = [
        "Audit.AzureActiveDirectory",
        "Audit.Exchange",
        "Audit.SharePoint",
        "Audit.General",
        "DLP.All"
    ]

    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.data_dir = Path("logs_output")
        self.data_dir.mkdir(exist_ok=True)
        self.last_run_file = self.data_dir / "last_run_time.txt"

    def authenticate(self):
        authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        app = msal.ConfidentialClientApplication(
            self.client_id, authority=authority, client_credential=self.client_secret
        )
        result = app.acquire_token_for_client(scopes=["https://manage.office.com/.default"])

        if "access_token" in result:
            self.access_token = result["access_token"]
            print("[+] Authentication successful")
            return True
        print(f"[-] Authentication failed: {result.get('error_description', 'Unknown')}")
        return False

    def _get_headers(self):
        return {"Authorization": f"Bearer {self.access_token}", "Content-Type": "application/json"}

    def _get_last_run_time(self):
        if self.last_run_file.exists():
            try:
                with open(self.last_run_file, 'r') as f:
                    return datetime.fromisoformat(f.read().strip())
            except:
                pass
        return None

    def _save_last_run_time(self, run_time):
        with open(self.last_run_file, 'w') as f:
            f.write(run_time.isoformat())

    def start_subscription(self, content_type):
        url = f"{self.API_URL}/{self.tenant_id}/activity/feed/subscriptions/start?contentType={content_type}"
        try:
            response = requests.post(url, headers=self._get_headers(), timeout=30)
            if response.status_code == 200 or "already enabled" in response.text.lower():
                print(f"    [+] {content_type}: active")
                return True
            print(f"    [-] {content_type}: failed")
            return False
        except:
            return False

    def get_content_blobs(self, content_type, start_time, end_time):
        url = f"{self.API_URL}/{self.tenant_id}/activity/feed/subscriptions/content"
        url += f"?contentType={content_type}&startTime={start_time}&endTime={end_time}"
        all_content = []

        while url:
            try:
                response = requests.get(url, headers=self._get_headers(), timeout=60)
                if response.status_code == 200:
                    try:
                        content = response.json()
                        if content:
                            all_content.extend(content)
                    except:
                        pass
                    url = response.headers.get("NextPageUri")
                else:
                    break
            except:
                break
        return all_content

    def fetch_blob(self, uri):
        try:
            response = requests.get(uri, headers=self._get_headers(), timeout=60)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return []

    def get_activity_logs(self, content_type, start_time, end_time):
        print(f"\n[*] {content_type}...")
        blobs = self.get_content_blobs(content_type, start_time, end_time)

        if not blobs:
            print(f"    No content")
            return []

        print(f"    {len(blobs)} blob(s)")
        all_events = []
        uris = [b.get("contentUri") for b in blobs if b.get("contentUri")]

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.fetch_blob, uri): uri for uri in uris}
            for future in as_completed(futures):
                events = future.result()
                if events:
                    all_events.extend(events)

        print(f"    {len(all_events)} events")
        return all_events

    def run(self, syslog_host, syslog_port, syslog_protocol):
        print("=" * 60)
        print("Office 365 Activity Log Extraction")
        print("=" * 60)

        if not self.authenticate():
            return False

        # Determine time range
        now = datetime.now(timezone.utc)
        last_run = self._get_last_run_time()

        if last_run:
            start_time = last_run
            print(f"\n[*] Incremental: {last_run.isoformat()} to now")
        else:
            start_time = now - timedelta(minutes=10)
            print(f"\n[*] First run: last 10 minutes")

        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S")
        end_str = now.strftime("%Y-%m-%dT%H:%M:%S")
        print(f"[*] Range: {start_str} to {end_str}")

        # Check subscriptions
        print("\n[*] Subscriptions...")
        active = {ct: self.start_subscription(ct) for ct in self.CONTENT_TYPES}
        time.sleep(2)

        # Connect to syslog
        syslog = SyslogSender(syslog_host, syslog_port, syslog_protocol)

        # Fetch and send logs
        total_sent = 0
        total_failed = 0

        for ct in self.CONTENT_TYPES:
            if not active.get(ct):
                continue

            events = self.get_activity_logs(ct, start_str, end_str)

            for event in events:
                if syslog.send(event):
                    total_sent += 1
                else:
                    total_failed += 1

        syslog.close()

        # Save run time
        self._save_last_run_time(now)

        print("\n" + "=" * 60)
        print("Complete!")
        print(f"Sent to syslog: {total_sent}")
        print(f"Failed: {total_failed}")
        print("=" * 60)

        return {"sent": total_sent, "failed": total_failed}


def main():
    extractor = O365ActivityLogs(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    extractor.run(SYSLOG_HOST, SYSLOG_PORT, SYSLOG_PROTOCOL)


if __name__ == "__main__":
    main()
