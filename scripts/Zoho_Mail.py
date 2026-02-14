#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zoho -> syslog exporter with optional UDP source-IP spoofing using Scapy.
Notes:
 - Spoofing requires root and works only for UDP.
 - Do NOT use 127.0.0.1 as SYSLOG_HOST when spoofing.
"""

import os
import sys
import time
import json
import socket
import ssl
from datetime import datetime, timezone, timedelta
import requests

# ---------- Config (env-first, then fallback) ----------
ACCESS_TOKEN  = os.getenv("ZACCESS_TOKEN",  "1000.44ce4093547e1c46160c92268f20d169.8a86e17cdd8b561073a39fd0b000f4b8")
CLIENT_ID     = os.getenv("ZCLIENT_ID",     "1000.8FVMFBL4N90R583C031WQDDUGXS6TY")
CLIENT_SECRET = os.getenv("ZCLIENT_SECRET", "67dcd4ac099e8af732adc2a152c3123b097c9779c0")
REFRESH_TOKEN = os.getenv("ZREFRESH_TOKEN", "1000.4c0de4a542e7a6506c27e05b5643b663.af88b4ff830949d045d8a1a3d070b68f")

MAIL_BASE     = os.getenv("ZMAIL_BASE",     "https://mail.zoho.in")
ACCOUNTS_BASE = os.getenv("ZACCOUNTS_BASE", "https://accounts.zoho.in")
ORG_ID        = os.getenv("ZORG_ID",        "60032878683")

LOOKBACK_MINUTES   = 5   # last 5 mins
OVERLAP_SECONDS    = 60
SAFETY_FUTURE_SEC  = 60
NINETY_DAYS_MS     = 90 * 24 * 60 * 60 * 1000

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
STATE_FILE  = os.path.join(BASE_DIR, "zoho_login_state.json")

SYSLOG_HOST     = os.getenv("SYSLOG_HOST", "192.168.10.250")
SYSLOG_PORT     = int(os.getenv("SYSLOG_PORT", "514"))
SYSLOG_PROTO    = os.getenv("SYSLOG_PROTO", "udp").lower()
SYSLOG_TLS      = os.getenv("SYSLOG_TLS", "false").lower() == "true"
SYSLOG_FACILITY = 16
SYSLOG_SEVERITY = 6
APPNAME         = "zoho-login-exporter"
HOSTNAME        = socket.gethostname()

SPOOF_SRC = os.getenv("SPOOF_SRC", "192.168.101.250")
if SPOOF_SRC.strip().lower() in ("", "none", "false", "0"):
    SPOOF_SRC = None

MODES = ["loginActivity", "failedLoginActivity", "protocolLoginActivity", "failedProtocolLoginActivity"]

# ---------------- helpers ----------------
def now_ms():
    return int(time.time() * 1000)

def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)

def calc_window(prior_to_ms):
    hard_to = now_ms() - SAFETY_FUTURE_SEC * 1000
    if prior_to_ms and prior_to_ms > 0:
        from_ms = max(0, prior_to_ms - OVERLAP_SECONDS * 1000)
    else:
        from_ms = hard_to - LOOKBACK_MINUTES * 60 * 1000
    to_ms = min(hard_to, from_ms + NINETY_DAYS_MS - 1)
    if to_ms < from_ms:
        to_ms = hard_to
        from_ms = hard_to - LOOKBACK_MINUTES * 60 * 1000
    return int(from_ms), int(to_ms)

def ms_to_readable_ist(ms_timestamp):
    if ms_timestamp in (None, -1, "-1"):
        return ""
    try:
        dt_utc = datetime.fromtimestamp(int(ms_timestamp)/1000, tz=timezone.utc)
        dt_ist = dt_utc + timedelta(hours=5, minutes=30)
        return dt_ist.strftime("%Y-%m-%d %H:%M:%S IST")
    except Exception:
        return str(ms_timestamp)

def refresh_access_token():
    try:
        r = requests.post(
            f"{ACCOUNTS_BASE}/oauth/v2/token",
            data={
                "refresh_token": REFRESH_TOKEN,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "refresh_token",
            },
            timeout=30,
        )
    except requests.RequestException as e:
        print(f"[-] Token refresh HTTP error: {e}", file=sys.stderr)
        return None

    if not r.ok:
        print(f"[-] Token refresh failed: {r.status_code} {r.text[:300]}", file=sys.stderr)
        return None
    tok = r.json().get("access_token")
    print("[+] Access token refreshed" if tok else "[-] Refresh OK but no access_token", file=sys.stderr)
    return tok

def rfc5424_line(pri, appname, msg, hostname=HOSTNAME):
    ts = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
    return f"{pri}1 {ts} {hostname} {appname} - - - {msg}"

def safe_q(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    return '"' + str(v).replace('"', "'") + '"'

def open_syslog_sender():
    pri = f"<{SYSLOG_FACILITY*8 + SYSLOG_SEVERITY}>"
    if SPOOF_SRC:
        if SYSLOG_HOST in ("127.0.0.1", "localhost"):
            print("[-] Spoofing mode: SYSLOG_HOST cannot be 127.0.0.1/localhost.", file=sys.stderr)
            sys.exit(2)
        if os.geteuid() != 0:
            print("[-] Spoofing requires root. Run with sudo.", file=sys.stderr)
            sys.exit(2)
        try:
            from scapy.all import IP, UDP, Raw, send as scapy_send, conf as scapy_conf
            scapy_conf.verb = 0
        except Exception as e:
            print(f"[-] Failed to import scapy: {e}", file=sys.stderr)
            sys.exit(2)

        def send_fn(msg_text):
            try:
                payload = msg_text if isinstance(msg_text, (bytes, bytearray)) else msg_text.encode("utf-8", "replace")
                pkt = IP(src=SPOOF_SRC, dst=SYSLOG_HOST) / UDP(sport=514, dport=SYSLOG_PORT) / Raw(load=payload)
                scapy_send(pkt, verbose=False)
            except Exception as e:
                print(f"[-] Scapy send failed: {e}", file=sys.stderr)
        return None, pri, send_fn

    if SYSLOG_PROTO == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        def send_fn(msg):
            s.sendto(msg.encode("utf-8", "replace"), (SYSLOG_HOST, SYSLOG_PORT))
        return s, pri, send_fn

    if SYSLOG_PROTO == "tcp":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(15)
        try:
            s.connect((SYSLOG_HOST, SYSLOG_PORT))
        except Exception as e:
            print(f"[-] TCP connect failed: {e}", file=sys.stderr)
            sys.exit(2)
        if SYSLOG_TLS:
            try:
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(s, server_hostname=SYSLOG_HOST)
            except Exception as e:
                print(f"[-] TLS wrap failed: {e}", file=sys.stderr)
                sys.exit(2)
        def send_fn(msg):
            s.sendall((msg + "\n").encode("utf-8", "replace"))
        return s, pri, send_fn

    raise RuntimeError("SYSLOG_PROTO must be 'udp' or 'tcp'")

def normalize_email(rec: dict):
    return rec.get("primaryEmailAddress") or rec.get("mailboxAddress") or ""

def pick_records_for_mode(mode: str, data: dict):
    if not isinstance(data, dict):
        return []
    if mode == "loginActivity":
        return data.get("loginRecords") or []
    if mode == "protocolLoginActivity":
        return data.get("protocolLoginRecords") or []
    if mode == "failedLoginActivity":
        return data.get("failedLoginRecords") or []
    if mode == "failedProtocolLoginActivity":
        return data.get("failedProtocolLoginRecords") or []
    return []

def send_record(send_fn, pri, mode, rec):
    ua = rec.get("userAgentObj") or {}
    payload = [
        'event=ZOHO_LOGIN',
        f"mode={safe_q(mode)}",
        f"email={safe_q(normalize_email(rec))}",
        f"ip={safe_q(rec.get('iPAddress'))}",
        f"loginTime={safe_q(ms_to_readable_ist(rec.get('loginTime')))}",
        f"logoutTime={safe_q(ms_to_readable_ist(rec.get('logoutTime')))}",
        f"duration={safe_q(rec.get('loginDuration'))}",
        f"service={safe_q(rec.get('serviceName'))}",
        f"protocol={safe_q(rec.get('protocol'))}",
        f"browser={safe_q(ua.get('browser'))}",
        f"os={safe_q(ua.get('os'))}",
        f"device={safe_q(ua.get('device'))}",
        f"location={safe_q(rec.get('loginLocation'))}",
        f"isSuspicious={safe_q(rec.get('isSuspiciousSignIn'))}",
        f"failureReason={safe_q(rec.get('failureReason'))}",
        f"referrer={safe_q(rec.get('referrer'))}",
        f"userAgent={safe_q(rec.get('userAgent'))}",
        f"loginTimeMs={safe_q(rec.get('loginTime'))}",
    ]
    msg = " ".join(payload)
    line = rfc5424_line(pri, APPNAME, msg)
    send_fn(line)

def fetch_mode(mode: str, token: str, from_ms: int, to_ms: int, send_fn, pri):
    url = f"{MAIL_BASE}/api/organization/{ORG_ID}/accounts/reports/loginHistory"
    scroll_id, written = None, 0
    batch_idx = 0
    while True:
        params = {
            "mode": mode,
            "fromTime": str(from_ms),
            "toTime": str(to_ms),
            "batchSize": "500",
            "accessType": "all",
        }
        if scroll_id:
            params["scrollId"] = scroll_id
        headers = {
            "Authorization": f"Zoho-oauthtoken {token}",
            "Accept": "application/json",
        }
        try:
            r = requests.get(url, params=params, headers=headers, timeout=120)
        except requests.RequestException as e:
            print(f"[-] {mode} request error: {e}", file=sys.stderr)
            return written, "bad"

        if r.status_code == 401:
            return written, "401"
        if not r.ok:
            print(f"[-] {mode} HTTP {r.status_code}: {r.text[:300]}", file=sys.stderr)
            return written, "bad"
        try:
            j = r.json()
        except Exception:
            print(f"[-] {mode} non-JSON: {r.text[:300]}", file=sys.stderr)
            return written, "bad"
        if (j.get("status") or {}).get("code") != 200:
            print(f"[-] {mode} API status not 200: {str(j)[:400]}", file=sys.stderr)
            return written, "bad"

        data = j.get("data") or {}
        recs = pick_records_for_mode(mode, data)
        if not recs and batch_idx == 0:
            print(f"[i] {mode}: No records. Keys: {list(data.keys())}", file=sys.stderr)
        for rec in recs:
            send_record(send_fn, pri, mode, rec)
            written += 1

        scroll_id = data.get("scrollId")
        batch_idx += 1
        if not scroll_id:
            break
        time.sleep(0.2)
    return written, "ok"

def main():
    state = load_state()
    from_ms, to_ms = calc_window(state.get("last_to_ms"))
    print(f"[i] Window: {ms_to_readable_ist(from_ms)} → {ms_to_readable_ist(to_ms)}")

    sock, pri, send_fn = open_syslog_sender()

    token = ACCESS_TOKEN or None
    if not token:
        token = refresh_access_token()
        if not token:
            print("[-] No access token and refresh failed.", file=sys.stderr)
            return 2

    total = 0
    for mode in MODES:
        wrote, status = fetch_mode(mode, token, from_ms, to_ms, send_fn, pri)
        if status == "401":
            print(f"[i] 401 on {mode}. Refreshing token...", file=sys.stderr)
            token = refresh_access_token()
            if not token:
                print("[-] Token refresh failed. Aborting.", file=sys.stderr)
                break
            wrote, status = fetch_mode(mode, token, from_ms, to_ms, send_fn, pri)
        total += wrote
        print(f"[+] {mode}: {wrote} records sent")

    try:
        if sock:
            sock.close()
    except Exception:
        pass

    state["last_to_ms"] = to_ms
    save_state(state)
    print(f"[+] Completed. Total records sent: {total}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
