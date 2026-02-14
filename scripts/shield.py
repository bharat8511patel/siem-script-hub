#!/usr/bin/env python3
"""
TechOwlShield alert fetcher → spoofed syslog sender
Uses scapy to spoof source IP (12.12.12.12)

WARNING:
- Requires root privileges
- Spoofing usually works only in local/lab networks
- Most production networks/routers drop spoofed packets (uRPF, BCP 38)
"""

import subprocess
import json
import time
import sys
import os
import logging
from datetime import datetime, timedelta

# ─── Spoofing support ────────────────────────────────────────────────
from scapy.all import IP, UDP, Raw, send

# ================= CONFIG =================
API_URL = "https://app.techowlshield.com/api/alert"
API_KEY = os.getenv("TECHOWL_API_KEY", "jHTAIavdufpO2acSIAU5FJIOIneLb1wX")

# Spoofed source IP that will appear in FortiSIEM logs
SPOOFED_SRC_IP = "12.12.12.12"

# Where the REAL syslog collector is listening
SYSLOG_HOST = "127.0.0.1"           # ← CHANGE THIS to your FortiSIEM collector IP
SYSLOG_PORT = 514

PER_PAGE = 100
CURL_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 5
STATE_FILE = "/var/tmp/techowl_last_run_time.txt"
LOG_FILE = "/var/log/techowl_alert_fetch.log"
APP_PREFIX = "TechOwlShield"

# ================= LOGGING =================
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger("").addHandler(console)

# ================= TIME WINDOW =================
def load_time_window():
    now = datetime.now()
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                start = datetime.strptime(f.read().strip(), "%d-%m-%Y %H:%M")
        except Exception:
            logging.warning("State file corrupt. Falling back to last 7 days.")
            start = now - timedelta(days=7)
    else:
        start = now - timedelta(days=7)
    return (
        start.strftime("%d-%m-%Y %H:%M"),
        now.strftime("%d-%m-%Y %H:%M"),
        now
    )

def save_last_run(ts):
    try:
        with open(STATE_FILE, "w") as f:
            f.write(ts.strftime("%d-%m-%Y %H:%M"))
    except Exception as e:
        logging.error("Failed to save state file: %s", e)

# ================= CURL EXEC =================
def run_curl(cmd):
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=CURL_TIMEOUT
    )
    stdout = proc.stdout.decode(errors="ignore").strip()
    stderr = proc.stderr.decode(errors="ignore").strip()
    if proc.returncode != 0:
        raise RuntimeError(f"curl failed: {stderr}")
    return stdout

# ================= FETCH ALERTS =================
def fetch_alerts(start_time, end_time):
    page = 1
    alerts = []
    while True:
        cmd = [
            "curl", "-k", "--silent", "--show-error", "--location",
            "--max-time", str(CURL_TIMEOUT),
            API_URL,
            "--header", f"X-API-KEY: {API_KEY}",
            "--form", f"start={start_time}",
            "--form", f"end={end_time}",
            "--form", f"page={page}",
            "--form", f"perPage={PER_PAGE}"
        ]
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                output = run_curl(cmd)
                if not output:
                    raise ValueError("Empty API response")
                if output.startswith("<"):
                    raise ValueError("HTML response (possible Cloudflare block)")
                result = json.loads(output)
                if result.get("status") != "success":
                    raise ValueError(f"API error: {result}")
                data = result.get("data", [])
                if not data:
                    return alerts
                alerts.extend(data)
                page += 1
                time.sleep(0.3)
                break
            except Exception as e:
                logging.error(
                    "API error (attempt %s/%s): %s",
                    attempt, MAX_RETRIES, e
                )
                if attempt == MAX_RETRIES:
                    raise
                time.sleep(RETRY_DELAY)
    return alerts

# ================= SYSLOG FORMAT =================
def format_log(payload: dict) -> str:
    """
    Format we want to see in FortiSIEM:
    TechOwlShield {"key":"value",...}
    """
    return f"{APP_PREFIX} {json.dumps(payload, separators=(',', ':'))}"

# ================= SPOOFED SENDING =================
def send_spoofed_syslog(messages: list[str]):
    sent = 0

    for msg in messages:
        try:
            packet = (
                IP(src=SPOOFED_SRC_IP, dst=SYSLOG_HOST) /
                UDP(sport=514, dport=SYSLOG_PORT) /
                Raw(msg.encode('utf-8'))
            )

            send(packet, verbose=False)
            sent += 1
            time.sleep(0.012)   # very light pacing

        except Exception as e:
            logging.error("Failed to send spoofed packet: %s", e)
            continue

    return sent

# ================= MAIN =================
def main():
    if os.geteuid() != 0:
        logging.critical("This script must run as root when using source IP spoofing!")
        return 2

    try:
        start, end, now_ts = load_time_window()
        logging.info("Fetching alerts from %s to %s", start, end)

        alerts = fetch_alerts(start, end)
        logging.info("Fetched %d alerts", len(alerts))

        messages = []
        if not alerts:
            heartbeat = {
                "Application": APP_PREFIX,
                "Message": "No alerts found",
                "StartTime": start,
                "EndTime": end
            }
            messages.append(format_log(heartbeat))
        else:
            for alert in alerts:
                messages.append(format_log(alert))

        logging.info(
            "Sending %d spoofed syslog messages from %s → %s:%d",
            len(messages), SPOOFED_SRC_IP, SYSLOG_HOST, SYSLOG_PORT
        )

        sent = send_spoofed_syslog(messages)

        logging.info("Successfully spoof-sent %d messages", sent)

        save_last_run(now_ts)
        return 0

    except Exception as e:
        logging.critical("Script failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
