#!/usr/bin/env python3
import json
import requests
import socket
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

# =======================================
# CONFIG
# =======================================
API_BASE = "https://api.in.xdr.trendmicro.com"

# Replace with your actual token
API_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJjaWQiOiJlYjRkOTA5ZC05Mzc4LTQyYWQtYjA5Yy0wNTRkMmQwZjYxZDkiLCJjcGlkIjoic3ZwIiwicHBpZCI6ImN1cyIsIml0IjoxNzY1Mjg1ODMwLCJldCI6MTc5NjgyMTgyOSwiaWQiOiJhZDk3ODUxNi00ZWI3LTQxNzAtOWMyMi1mYTQ5NDE5MDM0YWYiLCJ0b2tlblVzZSI6ImN1c3RvbWVyIn0.G_Aab2aGUB8ybWtaUE8nwB6yxl2Xvx-LmZPexZuUREgPwBKsiSaHK2qU-ALub-vry5o4rVkwY6depihq08MHrx2wOC6tSiCbifrkCoAi2XSJ0gMiTfjkmCpeBPwGxKJbGfCNRZU0KbMkwXmzjJ7ufK_vyydpGzYJrmrr-m445uUwoK334IpB8HXJian5WEjIi4acIlPhqqZpGmR2d4JFTrLBtBdVoHS1nq1Eu4Gn1Q-hpBqm4S5Zu3jT39WN0WH52eBEBHT0tYbxaEKOyeDRK2F8v2afE44DYSEkyVUs3KHWiuDsES67qGjs-gtRdO1rIfBDlIyF1UmpkiVpYYvLdC1w-tSy405-P4TagfbraXB48YfYaBZkO_FGZkKgXRO0RkxQnF1mpvL12qoUrIoMl4-qXeR8LYD9jAGAglT8b-Qef-edI_MUP7oUHubxhVOFsJZeAiv6kqngJfIESvJ9hIylqNZI_mWaSRbuO3sa2yp9waoCJXvXvTmofTgQJ7wwioW_7MkjsSBksWymPitF0psD3sIPySolTOuK-VtCv8ZBehNsWWg8e4onZrYk6UGxY4mqTxx50VJEmah6fzaOVqQw4_EF7Mw_bg0GxQ8efNqBgw9btZGwlyj1XCOGH0-AAhoEihtQdmJh-Z6ghOUPtil19y8cnUsCeGfnlMVlSxg"

SYSLOG_SERVER = "192.168.10.233"
SYSLOG_PORT = 514

USE_TCP = False                     # MUST be False for source IP spoofing
SPOOF_SOURCE_IP = "2.2.2.2"         # This IP will appear as the source

TIMESTAMP_FILE = "TMV1_timestamp.txt"
FIRST_RUN_MINUTES = 5            # ← Increased from 10 to 60 minutes for first run

# =======================================
# TREND VISION ONE API ENDPOINTS
# =======================================
TREND_APIS = [
    {
        "Keyword": "Trend_Vision_One_Audit_log",
        "Path": "/v3.0/audit/logs",
        "Params": {"top": 200, "orderBy": "loggedDateTime asc"}
    },
    {
        "Keyword": "Trend_Vision_One_Alert",
        "Path": "/v3.0/workbench/alerts",
        "Params": {"dateTimeTarget": "createdDateTime", "orderBy": "createdDateTime asc"}
    },
    {
        "Keyword": "Trend_Vision_One_Analysis_Result",
        "Path": "/v3.0/sandbox/analysisResults",
        "Params": {"top": 200, "orderBy": "analysisCompletionDateTime asc"}
    },
    {
        "Keyword": "Trend_Vision_One_Endpoint_Activity",
        "Path": "/v3.0/search/endpointActivities",
        "Params": {"top": 1000, "mode": "default"},
        "Headers": {"TMV1-Query": "uuid:*"}
    },
    {
        "Keyword": "Trend_Vision_One_Detection",
        "Path": "/v3.0/search/detections",
        "Params": {"top": 1000, "mode": "default"},
        "Headers": {"TMV1-Query": "uuid:*"}
    },
    {
        "Keyword": "Trend_Vision_One_Email_Activity",
        "Path": "/v3.0/search/emailActivities",
        "Params": {"top": 1000, "mode": "default"},
        "Headers": {"TMV1-Query": "uuid:*"}
    },
    {
        "Keyword": "Trend_Vision_One_Network_Activity",
        "Path": "/v3.0/search/networkActivities",
        "Params": {"top": 1000, "mode": "default"},
        "Headers": {"TMV1-Query": "uuid:*"}
    },
    {
        "Keyword": "Trend_Vision_One_Container_Activity",
        "Path": "/v3.0/search/containerActivities",
        "Params": {"top": 1000, "mode": "default"},
        "Headers": {"TMV1-Query": "uuid:*"}
    },
    {
        "Keyword": "Trend_Vision_One_OAT_Detections",
        "Path": "/v3.0/oat/detections",
        "Params": {"top": 200, "orderBy": "detectedDateTime asc"},
        "CustomTimeKeys": {
            "start": "detectedStartDateTime",
            "end": "detectedEndDateTime"
        }
    }
]

# =======================================
# SYSLOG SENDING WITH SPOOFING (UDP + Scapy)
# =======================================
def send_syslog(message: str):
    """Send message with spoofed source IP using Scapy (UDP)"""
    try:
        from scapy.all import IP, UDP, send
        full_msg = (message + "\n").encode('utf-8')
        packet = (
            IP(src=SPOOF_SOURCE_IP, dst=SYSLOG_SERVER) /
            UDP(sport=49152, dport=SYSLOG_PORT) /   # random high port as source
            full_msg
        )
        send(packet, verbose=0)
        # Optional: print confirmation (remove in production if not needed)
        # print(f"[SENT from {SPOOF_SOURCE_IP}] {message[:120]}...")
    except ImportError:
        print("[CRITICAL] scapy not installed. Install with: pip3 install scapy")
        sys.exit(1)
    except Exception as e:
        print(f"[SYSLOG SPOOF ERROR] {e}")
        # Fallback: send without spoofing
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto((message + "\n").encode('utf-8'), (SYSLOG_SERVER, SYSLOG_PORT))
            sock.close()
        except Exception as fb_e:
            print(f"[FALLBACK FAILED] {fb_e}")

def send_error(msg: str):
    """Send error to both console and syslog"""
    full_msg = f"[ERROR] {msg}"
    print(full_msg)
    send_syslog(full_msg)

# =======================================
# TIMESTAMP MANAGEMENT
# =======================================
def load_last_timestamp():
    if not os.path.exists(TIMESTAMP_FILE):
        return None
    try:
        with open(TIMESTAMP_FILE, "r") as f:
            ts_str = f.read().strip()
            return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None

def save_timestamp(ts: datetime):
    try:
        with open(TIMESTAMP_FILE, "w") as f:
            f.write(ts.strftime("%Y-%m-%dT%H:%M:%SZ"))
    except Exception as e:
        send_error(f"Failed to save timestamp: {e}")

def get_time_window():
    now = datetime.now(timezone.utc)
    last_ts = load_last_timestamp()

    if last_ts is None:
        # First run: pull last 60 minutes
        start = now - timedelta(minutes=FIRST_RUN_MINUTES)
    else:
        # Normal run: continue from last successful timestamp
        start = last_ts

    return (
        start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        now
    )

# =======================================
# FETCH DATA FROM TREND APIs
# =======================================
BASE_HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Accept": "application/json"
}

def fetch_with_pagination(api, start: str, end: str):
    base_url = API_BASE + api["Path"]
    params = api["Params"].copy()

    # Handle custom time keys (mainly for OAT detections)
    if "CustomTimeKeys" in api:
        params[api["CustomTimeKeys"]["start"]] = start
        params[api["CustomTimeKeys"]["end"]] = end
    else:
        params["startDateTime"] = start
        params["endDateTime"] = end

    headers = BASE_HEADERS.copy()
    if "Headers" in api:
        headers.update(api["Headers"])

    url = base_url + "?" + urlencode(params)
    total = 0

    while url:
        try:
            resp = requests.get(url, headers=headers, timeout=70)

            if resp.status_code in (401, 403):
                send_error(f"Authentication failed ({resp.status_code}) - {api['Keyword']}")
                return total
            if resp.status_code == 429:
                send_error(f"Rate limit hit (429) - {api['Keyword']}")
                time.sleep(60)
                continue
            if resp.status_code != 200:
                send_error(f"HTTP {resp.status_code} - {api['Keyword']}: {resp.text[:300]}")
                return total

            data = resp.json()
            items = data.get("items", [])

            for record in items:
                log_line = f"[{api['Keyword']}] = {json.dumps(record)}"
                send_syslog(log_line)
                total += 1

            # Pagination
            next_link = data.get("nextLink") or data.get("paging", {}).get("nextLink")
            url = next_link

        except requests.Timeout:
            send_error(f"Timeout fetching {api['Keyword']}")
            break
        except Exception as e:
            send_error(f"Exception on {api['Keyword']}: {e}")
            break

    # Report no data
    if total == 0:
        send_syslog(f"[{api['Keyword']}] NO DATA in time window")

    return total

# =======================================
# MAIN
# =======================================
def main():
    start, end, now_ts = get_time_window()
    print(f"\n>>> Pulling Trend Vision One events")
    print(f"    Time window: {start} → {end}")
    print(f"    Spoofed from: {SPOOF_SOURCE_IP} → {SYSLOG_SERVER}:{SYSLOG_PORT} (UDP)")
    print("")

    total_events = 0

    for api in TREND_APIS:
        print(f"[+] {api['Keyword']}")
        count = fetch_with_pagination(api, start, end)
        print(f"    → {count} events sent")
        total_events += count

    save_timestamp(now_ts)
    print(f"\n[✓] Finished. Total events: {total_events}")
    print(f"    New checkpoint: {now_ts.strftime('%Y-%m-%dT%H:%M:%SZ')}\n")

if __name__ == "__main__":
    # Quick reminder for dependencies
    try:
        from scapy.all import IP, UDP, send
    except ImportError:
        print("ERROR: scapy is required for IP spoofing")
        print("Install it with:   pip3 install scapy")
        sys.exit(1)

    main()