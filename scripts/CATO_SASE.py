#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cato SASE -> Syslog (periodic, checkpointed, SSL off)

- First run: create cato_last_time.txt, fetch up to 50 latest events.
- Next runs: fetch events between last_time and run_start.
- Sends every event as one syslog JSON message.
- If no new records: send a "No new records" syslog message.
- Updates marker and last_time after each run.

Requires: requests
"""

import os
import json
import socket
from datetime import datetime, timezone
from typing import Optional
import requests

# ======== HARD-CODED SETTINGS ========
API_URL    = "https://api.org_name.com/api/v1/graphql2"  # Api URL
API_KEY    = "API_key" #enter your API Key
ACCOUNT_ID = "Your Account ID"   # Please make sure you enter your Account ID

SYSLOG_HOST = "127.0.0.1"
SYSLOG_PORT = 514
SYSLOG_PROTO = "udp"   # "udp" or "tcp"

FIRST_RUN_MAX = 50
STATE_MARKER_PATH = "cato_marker.txt"
STATE_TIME_PATH   = "cato_last_time.txt"
# =====================================

GRAPHQL_QUERY = """
query EventsFeed($accountIDs:[ID!]!, $marker:String) {
  eventsFeed(accountIDs: $accountIDs, marker: $marker) {
    marker
    fetchedCount
    accounts {
      id
      records {
        time
        fieldsMap
        flatFields
      }
    }
  }
}
"""

# ---------- Helpers ----------
def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s: return None
    try:
        if s.endswith("Z"): s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception: return None

def fmt_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def load_text(path: str) -> Optional[str]:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            val = f.read().strip()
            return val or None
    return None

def save_text(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)

def open_syslog():
    if SYSLOG_PROTO.lower() == "udp":
        return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        return socket.create_connection((SYSLOG_HOST, SYSLOG_PORT), timeout=10)

def syslog_send(sock, msg: dict):
    data = json.dumps(msg, ensure_ascii=False).encode("utf-8")
    try:
        if SYSLOG_PROTO.lower() == "udp":
            sock.sendto(data, (SYSLOG_HOST, SYSLOG_PORT))
        else:
            sock.sendall(data + b"\n")
        print(f"[SYSLOG] sent: {msg}")
    except Exception as e:
        print(f"[SYSLOG] failed: {e}")

def gql_call(session, marker: Optional[str]):
    headers = {"Content-Type": "application/json", "x-api-key": API_KEY}
    payload = {"query": GRAPHQL_QUERY,
               "variables": {"accountIDs": [ACCOUNT_ID], "marker": "" if marker in (None, "") else marker}}
    resp = session.post(API_URL, headers=headers, json=payload, timeout=60)
    if resp.status_code == 200:
        data = resp.json()
        if "errors" in data:
            raise RuntimeError(f"GraphQL errors: {data['errors']}")
        return data["data"]["eventsFeed"]
    raise RuntimeError(f"HTTP {resp.status_code}: {resp.text}")
# -----------------------------

def main():
    session = requests.Session()
    session.verify = False
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    run_start_iso = now_utc_iso()
    run_start_dt = parse_iso(run_start_iso)

    last_iso = load_text(STATE_TIME_PATH)
    first_run = False
    if not last_iso:
        first_run = True
        last_iso = run_start_iso
        save_text(STATE_TIME_PATH, last_iso)
        print(f"[INIT] first run, created {STATE_TIME_PATH}={last_iso}")
    last_dt = parse_iso(last_iso)

    marker = load_text(STATE_MARKER_PATH)
    sock = open_syslog()

    total_sent = 0
    considered = 0

    while True:
        feed = gql_call(session, marker)
        next_marker = feed.get("marker")
        fetched = int(feed.get("fetchedCount") or 0)
        if next_marker:
            marker = next_marker
            save_text(STATE_MARKER_PATH, marker)

        if fetched == 0:
            break

        for acct in (feed.get("accounts") or []):
            for rec in (acct.get("records") or []):
                fields = rec.get("fieldsMap") or {}
                ev_iso = fields.get("time_str") or rec.get("time")
                ev_dt = parse_iso(ev_iso)

                include = True
                if not first_run:
                    if ev_dt and last_dt and ev_dt <= last_dt:
                        include = False
                    if ev_dt and ev_dt > run_start_dt:
                        include = False

                if first_run:
                    considered += 1
                    if considered > FIRST_RUN_MAX:
                        include = False

                if not include:
                    continue

                msg = {
                    "vendor": "Cato Networks",
                    "product": "SASE",
                    "account_id": ACCOUNT_ID,
                    "event_time": ev_iso or rec.get("time"),
                    "fields": fields,
                }
                syslog_send(sock, msg)
                total_sent += 1

    if total_sent == 0:
        # send "no new records" heartbeat
        hb = {
            "vendor": "Cato Networks",
            "product": "SASE",
            "note": "No new records",
            "run_start": run_start_iso
        }
        syslog_send(sock, hb)
        print("[INFO] No new records this run")

    # update last_time to run_start (so next run window is clean)
    save_text(STATE_TIME_PATH, run_start_iso)
    print(f"[DONE] sent={total_sent}, updated last_time={run_start_iso}")

if __name__ == "__main__":
    main()
