import requests
import json
import socket
import time
import os

# Bharat v3.0.1 (429 Safe Version)
TOKEN = "cmJhY3YzOnJDWDJIN1UweldfUjItUE12bmVRVg=="
BASE_URL = "https://dtdcin.goskope.com/api/v2/events/data"
ENDPOINTS = ["alert", "application", "audit"]
SYSLOG_SERVER = "10.10.23.188"
SYSLOG_PORT = 514

STATE_DIR = os.path.dirname(os.path.abspath(__file__))

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/json"
}


def get_last_ts(endpoint):
    path = os.path.join(STATE_DIR, f"netskope_last_ts_{endpoint}.txt")
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return int(f.read().strip())
        except:
            pass
    return int(time.time()) - 300  # default 5 minutes


def save_ts(endpoint, ts):
    path = os.path.join(STATE_DIR, f"netskope_last_ts_{endpoint}.txt")
    try:
        with open(path, "w") as f:
            f.write(str(ts))
    except Exception as e:
        print(f"[!] Failed to write timestamp file for {endpoint}: {e}")


def send_syslog(msg):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg.encode(), (SYSLOG_SERVER, SYSLOG_PORT))
        sock.close()
    except Exception as e:
        print(f"[!] Syslog error: {e}")


def safe_api_call(url):
    """Handles API calls including 429 Too Many Requests."""
    max_retries = 5
    wait_time = 5  # seconds

    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=HEADERS, timeout=30)

            if response.status_code == 429:
                print(f"[!] 429 Rate Limit Hit. Sleeping {wait_time}s...")
                time.sleep(wait_time)
                wait_time *= 2  # exponential backoff
                continue

            response.raise_for_status()
            return response.json()

        except requests.RequestException as e:
            print(f"[!] HTTP error: {e}")
            time.sleep(wait_time)

    print("[!] Max retries reached. Skipping.")
    return None


def pull_all_events():
    now = int(time.time())

    for endpoint in ENDPOINTS:
        start_time = get_last_ts(endpoint)
        end_time = now

        url = f"{BASE_URL}/{endpoint}?starttime={start_time}&endtime={end_time}"

        data = safe_api_call(url)

        if not data:
            continue

        if data.get("ok") == 1 and "result" in data:
            for event in data["result"]:
                tagged = f"{endpoint.capitalize()}-Netskope {json.dumps(event)}"
                send_syslog(tagged)

        save_ts(endpoint, end_time)  # Save timestamp ONLY after success


if __name__ == "__main__":
    pull_all_events()

