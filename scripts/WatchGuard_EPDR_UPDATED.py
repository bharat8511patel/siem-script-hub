#!/usr/bin/env python3
"""
WatchGuard EPDR Log Pulling Script - Generic Client
Fetches security events from all endpoints and sends to syslog with SPOOFED source IP.
Supports multiple clients via configuration.
Sends "NO DATA" message if nothing was sent during the run.
"""

import os
import sys
import json
import time
import socket
import base64
import argparse
from datetime import datetime, timezone, timedelta
import requests

# Scapy for packet crafting & spoofing
from scapy.all import IP, UDP, Raw, send

# ========= CLIENT CONFIGURATION =========
# You can override these via command-line arguments
DEFAULT_CLIENT_NAME = "WatchGuard-Client"          # Default/fallback name

# ========= API CONFIG (per client) =========
API_BASE   = "https://api.jpn.cloud.watchguard.com"
AUTH_URL   = f"{API_BASE}/oauth/token"

ACCOUNT_ID = "WGC-3-0a8a97f8c8fa451eb7b9"
ACCESS_ID  = "c3958d3e659cebf9_r_id"
ACCESS_PW  = "F'sL=3d3b0J0"
API_KEY    = "u4yVMU29P7biQravxrBMZhjpxe1c/OW7mBb30y/T" # ← CHANGE PER CLIENT

# ========= SYSLOG CONFIG =========
SYSLOG_SERVER = "192.168.10.233"   # Syslog server IP or hostname
SYSLOG_PORT   = 514                # Syslog port (usually 514 for UDP)
SYSLOG_PROTOCOL = "UDP"            # Currently only UDP is supported for spoofing

SPOOFED_SRC_IP = "10.1.10.2"       # The source IP we will spoof

# ========= FETCH CONFIG =========
FIRST_RUN_DAYS = 10       # First run: pull last N days (local filtering)
PERIOD = 1                # API export period - ONLY 1 is valid (returns last 24h data)
TIMESTAMP_FILE = "last_pull.txt"  # Generic checkpoint file name
TIMEOUT = 90

# ========= EVENT TYPES =========
EVENT_TYPES = {
    1:  "Malware",
    2:  "PUPs",
    3:  "BlockedPrograms",
    4:  "Exploits",
    5:  "BlockedByAdvancedPolicies",
    6:  "Virus",
    7:  "Spyware",
    8:  "HackingToolsAndPUPsByAV",
    9:  "Phishing",
    10: "Suspicious",
    11: "DangerousActions",
    12: "TrackingCookies",
    13: "MalwareURLs",
    14: "OtherSecurityEventByAV",
    15: "IntrusionAttempts",
    16: "BlockedConnections",
    17: "BlockedDevices",
    18: "IndicatorsOfAttack",
    19: "NetworkAttackProtection",
}


def parse_arguments():
    parser = argparse.ArgumentParser(description="WatchGuard EPDR Log Puller")
    parser.add_argument("--client-name", default=DEFAULT_CLIENT_NAME,
                        help="Name of the client (used in logs and syslog app-name)")
    parser.add_argument("--account-id", help="Override ACCOUNT_ID")
    parser.add_argument("--access-id", help="Override ACCESS_ID")
    parser.add_argument("--access-pw", help="Override ACCESS_PW")
    parser.add_argument("--api-key", help="Override API_KEY")
    parser.add_argument("--spoof-ip", default=SPOOFED_SRC_IP,
                        help="Source IP to spoof in syslog packets")
    return parser.parse_args()


def get_last_pull_time():
    """Read last pull timestamp from checkpoint file."""
    if os.path.exists(TIMESTAMP_FILE):
        try:
            with open(TIMESTAMP_FILE, "r") as f:
                ts_str = f.read().strip()
                if ts_str:
                    return datetime.fromisoformat(ts_str)
        except Exception as e:
            print(f"[WARN] Could not read timestamp file: {e}")
    return None


def save_pull_time(dt):
    """Save current pull timestamp to checkpoint file."""
    try:
        with open(TIMESTAMP_FILE, "w") as f:
            f.write(dt.isoformat())
        print(f"[INFO] Saved checkpoint: {TIMESTAMP_FILE}")
    except Exception as e:
        print(f"[ERROR] Could not save timestamp: {e}", file=sys.stderr)


def get_access_token():
    """Authenticate and get bearer token."""
    creds = base64.b64encode(f"{ACCESS_ID}:{ACCESS_PW}".encode()).decode()

    headers = {
        "Accept": "application/json",
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    data = {"grant_type": "client_credentials", "scope": "api-access"}

    r = requests.post(AUTH_URL, headers=headers, data=data, timeout=30)
    r.raise_for_status()

    token = r.json()["access_token"]
    print("[INFO] Access token obtained successfully.")
    return token


def fetch_events(token, event_type_id):
    """Fetch events for a specific event type."""
    url = (
        f"{API_BASE}/rest/endpoint-security/management/api/v1/"
        f"accounts/{ACCOUNT_ID}/securityevents/{event_type_id}/export/{PERIOD}"
    )

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "WatchGuard-API-Key": API_KEY,
        "Authorization": f"Bearer {token}",
    }

    r = requests.get(url, headers=headers, timeout=TIMEOUT)

    if r.status_code == 204:
        return []

    try:
        r.raise_for_status()
    except requests.HTTPError as e:
        print(f"[WARN] Event type {event_type_id}: {r.status_code} - {str(e)[:100]}", file=sys.stderr)
        return []

    data = r.json()
    return data.get("data", data) if isinstance(data, dict) else data


def parse_timestamp(ts_string):
    """Parse ISO timestamp string to datetime."""
    if not ts_string:
        return None

    try:
        ts = str(ts_string)
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def send_to_syslog(event, server, port, app_name, protocol="UDP", spoof_src="10.1.10.2"):
    if protocol.upper() != "UDP":
        print("[ERROR] Source IP spoofing is only implemented for UDP", file=sys.stderr)
        return False

    try:
        message = json.dumps(event, ensure_ascii=False)

        priority = 134  # local0.info
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        hostname = socket.gethostname()

        syslog_content = f"<{priority}>1 {timestamp} {hostname} {app_name} - - - {message}\n"

        packet = (
            IP(src=spoof_src, dst=server) /
            UDP(sport=514, dport=port) /
            Raw(load=syslog_content.encode('utf-8'))
        )

        send(packet, verbose=False)
        return True

    except Exception as e:
        print(f"[ERROR] Failed to send spoofed syslog: {e}", file=sys.stderr)
        return False


def send_no_data_message(server, port, app_name, protocol="UDP", spoof_src="10.1.10.2"):
    if protocol.upper() != "UDP":
        print("[WARN] NO DATA message only sent for UDP", file=sys.stderr)
        return False

    try:
        priority = 134
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        hostname = socket.gethostname()

        message = "NO DATA - No security events fetched or sent in this run"

        syslog_content = f"<{priority}>1 {timestamp} {hostname} {app_name} - - - {message}\n"

        packet = (
            IP(src=spoof_src, dst=server) /
            UDP(sport=514, dport=port) /
            Raw(load=syslog_content.encode('utf-8'))
        )

        send(packet, verbose=False)
        print("[INFO] Sent 'NO DATA' message to syslog")
        return True

    except Exception as e:
        print(f"[ERROR] Failed to send NO DATA message: {e}", file=sys.stderr)
        return False


def main():
    args = parse_arguments()

    # Use command-line values if provided, otherwise fall back to globals
    global ACCOUNT_ID, ACCESS_ID, ACCESS_PW, API_KEY, SPOOFED_SRC_IP
    if args.account_id:
        ACCOUNT_ID = args.account_id
    if args.access_id:
        ACCESS_ID = args.access_id
    if args.access_pw:
        ACCESS_PW = args.access_pw
    if args.api_key:
        API_KEY = args.api_key
    if args.spoof_ip:
        SPOOFED_SRC_IP = args.spoof_ip

    client_name = args.client_name
    print("=" * 60)
    print(f"WatchGuard EPDR Log Puller - {client_name}")
    print("=" * 60)

    token = get_access_token()

    current_time = datetime.now(timezone.utc)
    last_pull_time = get_last_pull_time()

    if last_pull_time:
        cutoff = last_pull_time
        print(f"[INFO] Incremental pull from: {cutoff.isoformat()}")
    else:
        cutoff = current_time - timedelta(days=FIRST_RUN_DAYS)
        print(f"[INFO] First run - pulling last {FIRST_RUN_DAYS} days")
        print(f"[INFO] From: {cutoff.isoformat()}")

    print(f"[INFO] To: {current_time.isoformat()}")
    print(f"[INFO] Account ID: {ACCOUNT_ID}")
    print(f"[INFO] Syslog destination: {SYSLOG_SERVER}:{SYSLOG_PORT} ({SYSLOG_PROTOCOL})")
    print(f"[INFO] Spoofing source IP as: {SPOOFED_SRC_IP}")
    print(f"[INFO] Client name: {client_name}")
    print("-" * 60)

    summary = []
    total_syslog_sent = 0

    for eid, name in EVENT_TYPES.items():
        print(f"[{eid:02d}/19] Fetching {name}...", end=" ")

        rows = fetch_events(token, eid)
        raw_count = len(rows) if rows else 0

        if not rows:
            print("No data")
            summary.append((name, 0, 0))
            continue

        syslog_sent = 0
        for r in rows:
            event_time = parse_timestamp(r.get("security_event_date"))
            if event_time and event_time >= cutoff:
                r["_event_type_id"] = eid
                r["_event_type_name"] = name
                r["_fetched_at"] = current_time.isoformat()
                r["_client"] = client_name   # ← now uses the variable

                if send_to_syslog(r, SYSLOG_SERVER, SYSLOG_PORT, client_name,
                                 SYSLOG_PROTOCOL, SPOOFED_SRC_IP):
                    syslog_sent += 1

        total_syslog_sent += syslog_sent
        print(f"{raw_count} raw -> {syslog_sent} sent (spoofed)")
        summary.append((name, raw_count, syslog_sent))

        time.sleep(0.2)

    save_pull_time(current_time)

    # Send NO DATA marker if nothing was sent
    if total_syslog_sent == 0:
        send_no_data_message(
            SYSLOG_SERVER, SYSLOG_PORT, client_name,
            SYSLOG_PROTOCOL, SPOOFED_SRC_IP
        )

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"{'Event Type':<28} {'Raw':>8} {'Syslog':>8}")
    print("-" * 60)
    for name, raw, syslog in summary:
        if raw > 0 or syslog > 0:
            print(f"{name:<28} {raw:>8} {syslog:>8}")
    print("-" * 60)
    total_raw = sum(s[1] for s in summary)
    print(f"{'TOTAL':<28} {total_raw:>8} {total_syslog_sent:>8}")
    print("=" * 60)

    print(f"\n[DONE] Checkpoint: {TIMESTAMP_FILE}")
    if total_syslog_sent > 0:
        print(f"[DONE] {total_syslog_sent} events sent (source IP: {SPOOFED_SRC_IP})")
    else:
        print(f"[DONE] No events sent - 'NO DATA' message was sent to syslog")


if __name__ == "__main__":
    main()