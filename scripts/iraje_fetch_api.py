#!/usr/bin/env python3
"""
Full Iraje PAM integration script (fixed version)
-------------------------------------------------
Fetches events from /api/irajeevents and:
 - Builds clean output in format: Iraje_PAM_API_{...}
 - Disables SSL verification
 - Uses timestamp + username + message for deduplication
 - Posts to SIEM via Scapy (spoofed source IP)
 - Maintains a last-timestamp pointer file (no DB)
 - Logs readable info to console + daily log
 - Removes logs older than 5 days
 - Sends clean "Iraje_PAM_API_No New Data Last Data at <timestamp>" if no events

FIX: Uses proper datetime comparison instead of string comparison
     to handle DD-MM-YYYY format correctly across month boundaries.

Run as root (Scapy requires raw socket privileges).
"""

import os
import sys
import json
import time
import hashlib
import requests
import urllib3
import logging
from datetime import datetime, timedelta
from pathlib import Path
from scapy.all import IP, UDP, Raw, send  # root required

# ---------------- CONFIG ----------------
API_BASE = "https://10.1.10.92"     # <-- replace with your Iraje URL
API_PATH = "/api/irajeevents"
USERNAME = "siemirajelog@ahm.lambdacro.com"            # <-- replace
PASSWORD = "L@mbda@#2025@#"               # <-- replace

VERIFY_SSL = False
FETCH_SECONDS = 300                      # last 5 mins
RUN_INTERVAL = 300                       # cron will run every 5 mins

# Syslog / Scapy
DEST_IP = "10.1.10.54"                    # <-- SIEM destination IP
DEST_PORT = 514
SOURCE_IP = "1.2.3.4"                    # <-- spoofed source IP
DELAY_BETWEEN_SENDS = 0.05
SEND_VIA_SCAPY = True                    # enable spoofed sending

# Paths
SCRIPT_DIR = Path("/root/script/iraje")
LOG_DIR = SCRIPT_DIR / "logs"
STATE_FILE = SCRIPT_DIR / "last_timestamp.txt"
QUEUE_FILE = SCRIPT_DIR / "iraje_syslog_queue.log"
LOG_RETENTION_DAYS = 5
# ----------------------------------------

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
SCRIPT_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Logging setup
logger = logging.getLogger("iraje")
logger.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(fmt)
logger.addHandler(ch)
logfile = LOG_DIR / f"iraje_terminal_{datetime.utcnow():%Y%m%d}.log"
fh = logging.FileHandler(logfile)
fh.setFormatter(fmt)
logger.addHandler(fh)


# ---------------- HELPERS ----------------
def load_last_timestamp() -> str:
    if STATE_FILE.exists():
        return STATE_FILE.read_text().strip()
    return ""

def save_last_timestamp(ts: str):
    STATE_FILE.write_text(ts)

def cleanup_old_logs(days=5):
    cutoff = datetime.utcnow() - timedelta(days=days)
    for p in LOG_DIR.glob("iraje_terminal_*.log"):
        try:
            mtime = datetime.utcfromtimestamp(p.stat().st_mtime)
            if mtime < cutoff:
                p.unlink()
                logger.info(f"Removed old log: {p.name}")
        except Exception:
            pass

def parse_timestamp(ts_str: str) -> datetime:
    """Convert DD-MM-YYYY HH:MM:SS to datetime."""
    try:
        return datetime.strptime(ts_str, "%d-%m-%Y %H:%M:%S")
    except Exception:
        return datetime.min  # Return minimum date on parse failure

def build_unique_key(evt):
    key = f"{evt.get('Timestamp')}|{evt.get('Username')}|{evt.get('Message')}"
    return hashlib.sha256(key.encode()).hexdigest()

def format_syslog_payload(evt):
    """Create JSON payload for real events."""
    payload = {
        "EventId": evt.get("EventId"),
        "EventName": evt.get("EventName"),
        "Username": evt.get("Username"),
        "Connection": evt.get("Connection"),
        "Type": evt.get("Type"),
        "Group": evt.get("Group"),
        "Source": evt.get("Source"),
        "Timestamp": evt.get("Timestamp"),
        "Message": evt.get("Message")
    }
    return f"Iraje_PAM_API_{json.dumps(payload, ensure_ascii=False)}"

def build_syslog_line(_, msg: str):
    """Return clean line without syslog header."""
    return msg  # no <14> or hostname prefix

def write_queue(line: str):
    with open(QUEUE_FILE, "a", encoding="utf-8") as f:
        f.write(line.rstrip() + "\n")

def send_via_scapy(line: str):
    try:
        pkt = IP(src=SOURCE_IP, dst=DEST_IP) / UDP(sport=514, dport=DEST_PORT) / Raw(load=line.encode())
        send(pkt, verbose=False)
        return True
    except PermissionError:
        logger.error("Permission denied (run as root).")
        return False
    except Exception as e:
        logger.warning(f"Scapy send failed: {e}")
        return False


# ---------------- MAIN ----------------
def main():
    url = f"{API_BASE.rstrip('/')}{API_PATH}?beforeSeconds={FETCH_SECONDS}"
    logger.info(f"Fetching Iraje events: {url}")
    auth = (USERNAME, PASSWORD)
    last_ts = load_last_timestamp()
    seen_keys = set()
    newest_ts = last_ts

    try:
        r = requests.get(url, auth=auth, verify=VERIFY_SSL, timeout=60)
        if r.status_code != 200:
            logger.error(f"HTTP {r.status_code}: {r.text[:400]}")
            return
        try:
            data = r.json()
        except Exception:
            logger.error("Failed to decode JSON")
            return

        # --- No new data from API ---
        if not data:
            msg = f"Iraje_PAM_API_No New Data Last Data at {last_ts or 'N/A'}"
            write_queue(msg)
            if SEND_VIA_SCAPY:
                send_via_scapy(msg)
            logger.info(msg)
            cleanup_old_logs(LOG_RETENTION_DAYS)
            return

        # Sort chronologically using proper datetime comparison
        data.sort(key=lambda x: parse_timestamp(x.get("Timestamp", "")))

        # Parse last_ts once for comparison (FIX: use datetime, not string)
        last_dt = parse_timestamp(last_ts) if last_ts else None

        new_events = []
        for evt in data:
            evt_ts = evt.get("Timestamp", "")
            evt_dt = parse_timestamp(evt_ts)
            
            # FIX: Compare datetime objects, not strings
            if last_dt and evt_dt <= last_dt:
                continue
            
            key = build_unique_key(evt)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            new_events.append(evt)
            newest_ts = evt_ts

        if not new_events:
            msg = f"Iraje_PAM_API_No New Data Last Data at {last_ts or 'N/A'}"
            write_queue(msg)
            if SEND_VIA_SCAPY:
                send_via_scapy(msg)
            logger.info(msg)
            cleanup_old_logs(LOG_RETENTION_DAYS)
            return

        logger.info(f"Processing {len(new_events)} new events")
        for evt in new_events:
            payload = format_syslog_payload(evt)
            line = build_syslog_line("Iraje_PAM_API", payload)
            write_queue(line)
            if SEND_VIA_SCAPY:
                if send_via_scapy(line):
                    logger.info(f"Sent {evt.get('EventName')} by {evt.get('Username')} ({evt.get('Timestamp')})")
                else:
                    logger.warning("Failed to send via Scapy")
                time.sleep(DELAY_BETWEEN_SENDS)
            else:
                logger.info(f"Prepared: {evt.get('EventName')} {evt.get('Username')} {evt.get('Timestamp')}")

        save_last_timestamp(newest_ts)
        logger.info(f"Updated last timestamp to {newest_ts}")

    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
    finally:
        cleanup_old_logs(LOG_RETENTION_DAYS)


if __name__ == "__main__":
    main()
