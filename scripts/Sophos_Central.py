#!/usr/bin/env python3
"""
Sophos SIEM -> Local file forwarder (filtered)
- Pulls last-24h window using ISO ?from/?to, falls back to ?from_date (epoch ms)
- Follows cursor through all pages (limit up to 1000)
- Filters to "fresh" items: now - FORWARD_WINDOW_MIN and > watermark (with lateness buffer)
- Deduplicates across runs (recent IDs)
- Stores ONLY filtered items to a local log file (size-rotated)
"""

import os, sys, json, hashlib, shutil
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter, Retry
from dateutil import parser as dtparser

print("[INFO] SCRIPT=SOPHOS_FILTERED_TO_FILE", file=sys.stderr)

# =========================
# CONFIG — EDIT SAFELY
# =========================
CLIENT_ID     = "Your Client ID" #Please Enter your Client ID
CLIENT_SECRET = "Your Client Secret"  #Please Enter Secret

# Forwarding policy (independent of Sophos 24h API window)
FORWARD_WINDOW_MIN   = 5     # forward only items newer than (now - 5 min)
LATENESS_BUFFER_MIN  = 10    # allow late arrivals this many minutes behind watermark
MAX_LOOKBACK_MIN     = 240   # first-run lookback (<=24h per API)

# State & dedup
STATE_FILE           = "./filter_forward_state.json"
DEDUP_MAX_IDS        = 50000

# Output to file (enabled)
LOG_TO_FILE          = True
LOG_FILE_PATH        = "./sophos_filtered.log"
LOG_ROTATE_BYTES     = 50 * 1024 * 1024   # 50 MB
LOG_ROTATE_BACKUPS   = 5                  # keep .1 .. .5

# Syslog (disabled)
SEND_SYSLOG          = False
SYSLOG_HOST          = "127.0.0.1"  #Your syslog server or collector IP
SYSLOG_PORT          = 514
SYSLOG_PROTOCOL      = "udp"              # unused when SEND_SYSLOG=False

# Sophos API paging
PAGE_LIMIT           = 1000               # per docs: 200..1000
MAX_PAGES            = 100

# Debug prints
DEBUG                = True

# =========================
AUTH_URL   = "https://id.sophos.com/api/v2/oauth2/token"
WHOAMI_URL = "https://api.central.sophos.com/whoami/v1"
TIMEOUT    = (15, 60)

SESSION = requests.Session()
SESSION.headers.update({"Accept": "application/json"})
# Compatibility: older requests/urllib3 on Rocky Linux 8
SESSION.mount("https://", HTTPAdapter(max_retries=Retry(
    total=5,
    backoff_factor=1.2,
    status_forcelist=[429, 500, 502, 503, 504],
    method_whitelist=["GET", "POST"]   # use allowed_methods on newer stacks
)))

# =========================
# Helpers
# =========================
def logd(msg: str):
    if DEBUG:
        print(f"[DEBUG] {msg}", file=sys.stderr, flush=True)

def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def epoch_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)

def parse_iso_compat(s: str) -> datetime:
    """
    Compatibility parser: prefer dateutil.parser.isoparse if present,
    otherwise fall back to dateutil.parser.parse.
    """
    try:
        isoparse = getattr(dtparser, "isoparse", None)
        if callable(isoparse):
            dt = isoparse(s)
        else:
            dt = dtparser.parse(s)
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception as e:
        raise ValueError(f"Failed to parse ISO datetime: {s} ({e})")

def load_state() -> Dict[str, Any]:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"[WARN] state load error: {e}", file=sys.stderr)
        return {}

def save_state(s: Dict[str, Any]):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=2, sort_keys=True)
    os.replace(tmp, STATE_FILE)

# =========================
# File logging with simple rotation
# =========================
def _rotate_file(path: str, max_bytes: int, backups: int):
    try:
        if not os.path.exists(path):
            return
        if os.path.getsize(path) < max_bytes:
            return
        # rotate oldest -> drop, shift others up, current -> .1
        for i in range(backups, 0, -1):
            src = f"{path}.{i}"
            dst = f"{path}.{i+1}"
            if os.path.exists(dst):
                os.remove(dst)
            if os.path.exists(src):
                os.rename(src, dst)
        # current -> .1
        if os.path.exists(f"{path}.1"):
            os.remove(f"{path}.1")
        os.rename(path, f"{path}.1")
    except Exception as e:
        print(f"[WARN] rotation failed: {e}", file=sys.stderr)

def write_events_to_file(objs: List[Dict[str, Any]], path: str):
    if not objs:
        return 0
    # rotate if needed
    _rotate_file(path, LOG_ROTATE_BYTES, LOG_ROTATE_BACKUPS)
    # append JSONL; each line has an envelope with ts/kind/object
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        with open(path, "a", encoding="utf-8") as f:
            for obj in objs:
                kind = (obj.get("kind") or "").upper()
                line = {
                    "ingestTs": now_iso,
                    "kind": kind,
                    "event": obj
                }
                f.write(json.dumps(line, ensure_ascii=False) + "\n")
        return len(objs)
    except Exception as e:
        print(f"[ERROR] failed writing to {path}: {e}", file=sys.stderr)
        return 0

# =========================
# Sophos API
# =========================
def get_access_token() -> str:
    r = SESSION.post(AUTH_URL, data={
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "token",
    }, timeout=TIMEOUT)
    r.raise_for_status()
    logd("Got access_token")
    return r.json()["access_token"]

def whoami(tok: str) -> Tuple[str, str]:
    r = SESSION.get(WHOAMI_URL, headers={"Authorization": f"Bearer {tok}"}, timeout=TIMEOUT)
    r.raise_for_status()
    j = r.json()
    logd(f"whoami idType={j.get('idType')} id={j.get('id')} dataRegion={j.get('apiHosts',{}).get('dataRegion')}")
    return j["id"], j["apiHosts"]["dataRegion"]

def _pick_cursor(data: Dict[str, Any]) -> Optional[str]:
    for k in ("next_cursor", "next", "cursor", "nextCursor"):
        v = data.get(k)
        if v:
            return v
    pages = data.get("pages")
    if isinstance(pages, dict):
        for k in ("nextKey", "cursor", "next_cursor"):
            v = pages.get(k)
            if v:
                return v
    if data.get("nextKey"):
        return data["nextKey"]
    return None

def _page_once(url: str, hdr: Dict[str, str], params: Dict[str, Any], resource: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    logd(f"GET {url} params={params}")
    r = SESSION.get(url, headers=hdr, params=params, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    items = data.get("items") or data.get(resource) or []
    if not isinstance(items, list):
        logd(f"Unexpected items type: {type(items)}; forcing []")
        items = []
    next_cur = _pick_cursor(data)
    logd(f"Page got {len(items)} {resource} | next_cursor? {bool(next_cur)}")
    return items, next_cur

def fetch_resource(tok: str, tenant_id: str, base: str, resource: str,
                   from_iso: str, to_iso: str, from_ms: int) -> List[Dict[str, Any]]:
    """
    Try ISO ?from/?to first; if empty & no cursor, retry with ?from_date.
    Then follow ?cursor=... across pages.
    """
    url = f"{base}/siem/v1/{resource}"
    hdr = {"Authorization": f"Bearer {tok}", "X-Tenant-ID": tenant_id, "Accept": "application/json"}

    out: List[Dict[str, Any]] = []
    next_cursor: Optional[str] = None

    # Attempt ISO
    params = {"from": from_iso, "to": to_iso, "limit": PAGE_LIMIT}
    items, next_cursor = _page_once(url, hdr, params, resource)
    out.extend(items)

    if not items and not next_cursor:
        # Fallback to epoch
        logd("No items with ISO 'from/to'. Falling back to 'from_date'.")
        params = {"from_date": from_ms, "limit": PAGE_LIMIT}
        items, next_cursor = _page_once(url, hdr, params, resource)
        out.extend(items)

    # Cursor pages
    page = 1
    while next_cursor and page < MAX_PAGES:
        params = {"cursor": next_cursor, "limit": PAGE_LIMIT}
        items, next_cursor = _page_once(url, hdr, params, resource)
        if not items:
            break
        out.extend(items)
        page += 1

    logd(f"Total collected {resource}: {len(out)}")
    return out

# =========================
# Time / Filter / Dedup
# =========================
def extract_event_ts(obj: Dict[str, Any]) -> Optional[datetime]:
    for key in ("when", "time", "raisedAt", "createdAt"):
        v = obj.get(key)
        if not v:
            continue
        try:
            dt = dtparser.parse(str(v))
            return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    rec = obj.get("record") or {}
    for key in ("when", "time", "timestamp"):
        v = rec.get(key)
        if not v:
            continue
        try:
            dt = dtparser.parse(str(v))
            return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return None

def stable_id(obj: Dict[str, Any]) -> str:
    if obj.get("id"):
        return "id:" + str(obj["id"])
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=False)
    return "sha1:" + hashlib.sha1(blob.encode("utf-8")).hexdigest()

def filter_with_watermark(items: List[Dict[str, Any]], watermark_iso: Optional[str]) -> Tuple[List[Dict[str, Any]], str]:
    now = datetime.now(timezone.utc)
    lb = now - timedelta(minutes=FORWARD_WINDOW_MIN) if FORWARD_WINDOW_MIN else datetime.min.replace(tzinfo=timezone.utc)
    if watermark_iso:
        try:
            wm = parse_iso_compat(watermark_iso)
            lb = min(lb, wm - timedelta(minutes=LATENESS_BUFFER_MIN))
        except Exception as e:
            print(f"[WARN] ignoring invalid watermark in state: {watermark_iso} ({e})", file=sys.stderr)

    selected: List[Tuple[datetime, Dict[str, Any]]] = []
    max_ts: Optional[datetime] = None

    for obj in items:
        ts = extract_event_ts(obj)
        if not ts or ts < lb:
            continue
        selected.append((ts, obj))
        if (max_ts is None) or (ts > max_ts):
            max_ts = ts

    selected.sort(key=lambda x: x[0])
    new_wm = iso_utc(max_ts) if max_ts else (watermark_iso or iso_utc(now))
    return [o for _, o in selected], new_wm

# =========================
# Main
# =========================
def main():
    # Build first-page window
    state = load_state()
    watermark_iso = state.get("watermark_iso")
    now = datetime.now(timezone.utc)

    if watermark_iso:
        try:
            wm = parse_iso_compat(watermark_iso)
            from_dt = max(wm - timedelta(minutes=LATENESS_BUFFER_MIN), now - timedelta(hours=24))
            reason = f"wm={watermark_iso} - lateness={LATENESS_BUFFER_MIN}m"
        except Exception as e:
            print(f"[WARN] Bad watermark in state; falling back. value={watermark_iso} err={e}", file=sys.stderr)
            watermark_iso = None
            from_dt = now - timedelta(minutes=MAX_LOOKBACK_MIN)
            reason = f"first_run lookback={MAX_LOOKBACK_MIN}m"
    else:
        from_dt = now - timedelta(minutes=MAX_LOOKBACK_MIN)
        reason = f"first_run lookback={MAX_LOOKBACK_MIN}m"

    to_dt   = now
    from_iso = iso_utc(from_dt)
    to_iso   = iso_utc(to_dt)
    from_ms  = epoch_ms(from_dt)

    logd(f"Initial window ISO: from={from_iso} to={to_iso}  (reason: {reason}); limit={PAGE_LIMIT}")
    logd(f"Initial window EPOCH: from_date={from_ms}")

    # Auth / region
    token = get_access_token()
    tenant_id, base = whoami(token)

    # Pull both datasets
    alerts_raw = fetch_resource(token, tenant_id, base, "alerts", from_iso, to_iso, from_ms)
    events_raw = fetch_resource(token, tenant_id, base, "events", from_iso, to_iso, from_ms)

    # Tag kind
    alerts = [{"kind": "ALERT", **o} for o in alerts_raw]
    events = [{"kind": "EVENT", **o} for o in events_raw]

    # Filter & build watermark
    filt_alerts, wm1 = filter_with_watermark(alerts, watermark_iso)
    filt_events, wm2 = filter_with_watermark(events, watermark_iso)
    new_watermark = wm2 if wm2 and (wm2 >= (wm1 or "")) else wm1

    # Dedup across runs
    recent_ids: List[str] = state.get("recent_ids", [])
    recent_set = set(recent_ids)

    def not_seen(obj):
        sid = stable_id(obj)
        if sid in recent_set:
            return False
        recent_set.add(sid)
        recent_ids.append(sid)
        if len(recent_ids) > DEDUP_MAX_IDS:
            drop = len(recent_ids) - DEDUP_MAX_IDS
            recent_ids[:] = recent_ids[drop:]
        return True

    filtered = [o for o in filt_alerts if not_seen(o)] + [o for o in filt_events if not_seen(o)]
    logd(f"Selected (time+dedup): {len(filtered)}")

    # Store to file (JSONL lines)
    written = 0
    if LOG_TO_FILE and filtered:
        written = write_events_to_file(filtered, LOG_FILE_PATH)

    # Persist state
    save_state({"watermark_iso": new_watermark, "recent_ids": recent_ids})

    print(f"[INFO] stored={written} file={LOG_FILE_PATH} watermark={new_watermark}")

if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        print(f"[ERROR] {ex}", file=sys.stderr)
        sys.exit(2)
