#!/usr/bin/env python3
"""
pull_rediff_15m_to_syslog_spoof.py
Fetch last 15 minutes of RediffmailPro logs and forward each record to syslog.
Optionally send UDP syslog packets with a spoofed source IP using Scapy.

Requirements for spoofing:
  - Run as root (or with CAP_NET_RAW).
  - scapy installed: pip3 install scapy

Notes:
  - Spoofing implemented for UDP only.
  - If SPOOF_SRC is False, script uses normal sockets (UDP/TCP).
"""

import os
import socket
import json
import base64
import random
from datetime import datetime, timezone, timedelta

import requests

# ----------------- USER CONFIG -----------------
# Rediff credentials / window
DOMAIN          = "xxxxxxx.co.in"
USER_EMAIL      = " xxxxxx.co.in"
PASSWORD_PLAIN  = "xxxxxxxxxxxxxxx"                # plain password (script will base64 it)
WINDOW_MINUTES  = 5
API_URL         = "https://cl-logs.rediffmailpro.com/logs/get"
REQUEST_TIMEOUT = 30

# Syslog target
SYSLOG_HOST     = "172.21.1.31"               # FortiSIEM Collector (change if needed)
SYSLOG_PORT     = 514
SYSLOG_PROTO    = "udp"                         # "udp" or "tcp"
SYSLOG_FORMAT   = "rfc3164"                     # "rfc3164" or "rfc5424"
SYSLOG_FACILITY = 16                            # local0
SYSLOG_SEVERITY = 6                             # info
SYSLOG_TAG      = "rediffmailpro"

# Spoofing config
SPOOF_SRC       = True                          # Enable source IP spoofing (UDP only)
SPOOF_SRC_IP    = "10.1.10.2"                   # the spoofed source IP you asked for
# ------------------------------------------------

# optional import of scapy (only used if SPOOF_SRC True)
SCAPY_AVAILABLE = False
if SPOOF_SRC:
    try:
        # scapy import may print warnings; keep minimal
        from scapy.all import IP, UDP, Raw, send
        SCAPY_AVAILABLE = True
    except Exception as e:
        SCAPY_AVAILABLE = False


def epoch_seconds(dt: datetime) -> int:
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def pri_val(facility: int, severity: int) -> int:
    return facility * 8 + severity


def rfc3164(ts: datetime, host: str, tag: str, msg: str, pri: int) -> bytes:
    ts_str = ts.strftime("%b %e %H:%M:%S")
    line = f"<{pri}>{ts_str} {host} {tag}: {msg}"
    return line.encode("utf-8", errors="replace")


def rfc5424(ts: datetime, host: str, tag: str, msg: str, pri: int) -> bytes:
    ts_str = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"<{pri}>1 {ts_str} {host} {tag} - - - {msg}"
    return line.encode("utf-8", errors="replace")


def syslog_sender_socket(host: str, port: int, proto: str):
    if proto.lower() == "tcp":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))
        return s, "tcp"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return s, "udp"


def send_syslog_socket(sock, proto: str, data: bytes, host: str, port: int):
    if proto == "tcp":
        sock.sendall(data + b"\n")
    else:
        sock.sendto(data, (host, port))


def send_syslog_spoof_udp(dst_host: str, dst_port: int, src_ip: str, payload: bytes):
    """
    Use Scapy to craft a UDP packet with spoofed source IP.
    This sends a single UDP packet (no handshake). Requires root.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy unavailable for spoofing (pip install scapy and run as root).")

    # random source port between 1025 and 65535
    sport = random.randint(1025, 65535)
    pkt = IP(src=src_ip, dst=dst_host) / UDP(sport=sport, dport=dst_port) / Raw(load=payload)
    # send() uses raw sockets; defaults to IPv4 and will send the packet out
    send(pkt, verbose=False)  # verbose False to avoid scapy output


def kv_join(d: dict) -> str:
    """
    Turn a dict into compact key=value pairs suitable for syslog.
    Non-str scalars kept as-is; everything else JSON-encoded.
    """
    parts = []
    for k, v in d.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            val = str(v)
        else:
            val = json.dumps(v, ensure_ascii=False, separators=(",", ":"))
        val = val.replace("\r", "\\r").replace("\n", "\\n")
        parts.append(f'{k}="{val}"')
    return " ".join(parts)


def pick_fields(rec: dict) -> dict:
    keys = [
        "date_time", "from_address", "return_path", "recipient", "service",
        "subject", "sender_ip", "rcpt_to_count", "rcpt_cc_count", "rcpt_bcc_count",
        "attachment_names", "mail_size_bytes", "status", "status_code"
    ]
    out = {}
    for k in keys:
        if k in rec:
            out[k] = rec[k]
    return out


def main():
    now = datetime.now(timezone.utc)
    frm = now - timedelta(minutes=WINDOW_MINUTES)

    payload = {
        "domain": DOMAIN,
        "user_email": USER_EMAIL,
        "passwd": base64.b64encode(PASSWORD_PLAIN.encode("utf-8")).decode("ascii"),
        "fromtime_epoch": str(epoch_seconds(frm)),
        "totime_epoch": str(epoch_seconds(now)),
    }

    print(f"[INFO] Requesting {WINDOW_MINUTES}m window: {frm.isoformat()} .. {now.isoformat()}")
    print("[INFO] Note: API allows ~1 call/min and caller IP must be whitelisted.")

    try:
        resp = requests.post(API_URL, data=payload, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as e:
        print(f"[ERROR] HTTP request failed: {e}")
        return

    if resp.status_code != 200:
        print(f"[ERROR] HTTP {resp.status_code} → {resp.text[:1000]}")
        return

    try:
        body = resp.json()
    except ValueError:
        print("[ERROR] Non-JSON response:")
        print(resp.text[:2000])
        return

    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict):
        print("[WARN] No 'data' object in response. Nothing to forward.")
        return

    pri = pri_val(SYSLOG_FACILITY, SYSLOG_SEVERITY)
    local_host = socket.gethostname()

    # Prepare socket (non-spoofed path)
    sock = None
    sock_proto = None
    if not SPOOF_SRC or SYSLOG_PROTO.lower() == "tcp" or not SCAPY_AVAILABLE:
        # Use normal socket when not spoofing, or when using TCP (or scapy missing).
        try:
            sock, sock_proto = syslog_sender_socket(SYSLOG_HOST, SYSLOG_PORT, SYSLOG_PROTO)
        except Exception as e:
            print(f"[WARN] Could not open socket to {SYSLOG_HOST}:{SYSLOG_PORT} ({e}). Will attempt spoofed send if enabled.")
            sock = None
            sock_proto = None

    sent = 0
    sections = [
        ("outbound_mail_delivery_report", "rediff.outbound"),
        ("activity_report", "rediff.activity"),
    ]

    try:
        for sec_key, tag_suffix in sections:
            arr = data.get(sec_key)
            if not isinstance(arr, list) or not arr:
                continue

            for rec in arr:
                if not isinstance(rec, dict):
                    payload_fields = {"raw": rec}
                else:
                    payload_fields = pick_fields(rec)
                    payload_fields["section"] = sec_key

                msg = kv_join(payload_fields)

                if SYSLOG_FORMAT.lower() == "rfc5424":
                    line = rfc5424(datetime.utcnow(), local_host, f"{SYSLOG_TAG}/{tag_suffix}", msg, pri)
                else:
                    line = rfc3164(datetime.utcnow(), local_host, f"{SYSLOG_TAG}/{tag_suffix}", msg, pri)

                # Decide send method
                if SPOOF_SRC and SYSLOG_PROTO.lower() == "udp" and SCAPY_AVAILABLE:
                    # Use Scapy to spoof source IP (UDP only)
                    try:
                        send_syslog_spoof_udp(SYSLOG_HOST, SYSLOG_PORT, SPOOF_SRC_IP, line)
                        sent += 1
                    except Exception as e:
                        print(f"[ERROR] Spoof send failed: {e}. Falling back to socket send if available.")
                        if sock:
                            try:
                                send_syslog_socket(sock, sock_proto, line, SYSLOG_HOST, SYSLOG_PORT)
                                sent += 1
                            except Exception as e2:
                                print(f"[ERROR] Socket fallback also failed: {e2}")
                        else:
                            print("[WARN] No socket available for fallback send.")
                else:
                    # Normal socket send (either TCP or UDP non-spoof)
                    if SYSLOG_PROTO.lower() == "udp" and SPOOF_SRC and not SCAPY_AVAILABLE:
                        print("[WARN] SPOOF_SRC True but Scapy not available. Sending without spoof.")
                    if sock:
                        try:
                            send_syslog_socket(sock, sock_proto, line, SYSLOG_HOST, SYSLOG_PORT)
                            sent += 1
                        except Exception as e:
                            print(f"[ERROR] Socket send failed: {e}")
                    else:
                        # try a short-lived socket send
                        try:
                            tmp_sock, tmp_proto = syslog_sender_socket(SYSLOG_HOST, SYSLOG_PORT, SYSLOG_PROTO)
                            send_syslog_socket(tmp_sock, tmp_proto, line, SYSLOG_HOST, SYSLOG_PORT)
                            if tmp_proto == "tcp":
                                tmp_sock.close()
                            sent += 1
                        except Exception as e:
                            print(f"[ERROR] Transient socket send failed: {e}")

    finally:
        try:
            if sock and sock_proto == "tcp":
                sock.close()
        except Exception:
            pass

    status = body.get("status")
    status_code = body.get("status_code")
    print(f"[INFO] API status: {status} (code={status_code})")
    print(f"[INFO] Forwarded {sent} event(s) to {SYSLOG_HOST}:{SYSLOG_PORT} (proto={SYSLOG_PROTO}, spoof={SPOOF_SRC and SCAPY_AVAILABLE}).")
    print("[DONE]")


if __name__ == "__main__":
    main()
