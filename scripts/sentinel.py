import time
import requests
import socket
import os
import json
from datetime import datetime, timezone

# ===== CONFIGURATION =====
TOKEN = "eyJraWQiOiJhcC1zb3V0aGVhc3QtMS1wcm9kLTAiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzZXJ2aWNldXNlci0xMjFhM2NmMy02NjdmLTRhM2YtYjZiZS04ODYwNTdmMmIzZjdAbWdtdC01NC5zZW50aW5lbG9uZS5uZXQiLCJpc3MiOiJhdXRobi1hcC1zb3V0aGVhc3QtMS1wcm9kIiwiZGVwbG95bWVudF9pZCI6IjU0IiwidHlwZSI6InVzZXIiLCJleHAiOjE3NTMyNjM0MjIsImlhdCI6MTc1MDY3MTU5NiwianRpIjoiNzBjZTBlMzktYzY2Ni00YmUxLTk5MWQtOGI4ZGNjYzIxMWFmIn0.7mIArbR-C98s8JXYXLI711vy2iEcih3Hgc6nruRNm7ltlQhTKSxcwEYhQzJXsy0XaDHy2vNMIhNhxUISxyvkvQ"
BASE_URL = "https://apse1-2001.sentinelone.net/web/api/v2.1"
ENDPOINTS = {
    "activities": "activities",
    "threats": "threats",
    "cloud-detection/alerts": "cloud-detection/alerts"
}
LIMIT = 1000
TIMESTAMP_FILE = "s1_last_ts.txt"
SYSLOG_SERVER = "localhost"
SYSLOG_PORT = 514

# ===== SYSLOG SEND FUNCTION =====
def send_syslog(message):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode(), (SYSLOG_SERVER, SYSLOG_PORT))
        sock.close()
    except Exception as e:
        print(f"[Syslog Error] {e}")

# ===== TIME RANGE HANDLING =====
def get_time_range():
    if os.path.exists(TIMESTAMP_FILE):
        with open(TIMESTAMP_FILE, "r") as f:
            last_ts = int(f.read().strip())
    else:
        last_ts = int(time.time()) - 300  # fallback to last 5 min

    now_ts = int(time.time())
    return (
        datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat(),
        datetime.fromtimestamp(now_ts, tz=timezone.utc).isoformat(),
        now_ts
    )

# ===== ACTIVITY FIELD FILTER =====
def filter_activity_fields(event):
    data = event.get("data", {})
    return {
        "computerName": data.get("computerName"),
        "ipAddress": data.get("ipAddress"),
        "deviceName": data.get("deviceName"),
        "interface": data.get("interface"),
        "eventType": data.get("eventType"),
        "eventTime": data.get("eventTime"),
        "lastLoggedInUserName": data.get("lastLoggedInUserName"),
        "groupName": data.get("groupName"),
        "siteName": data.get("siteName"),
        "productId": data.get("productId"),
        "vendorId": data.get("vendorId"),
        "uid": data.get("uid"),
        "primaryDescription": event.get("primaryDescription"),
        "secondaryDescription": event.get("secondaryDescription"),
        "createdAt": event.get("createdAt"),
    }

# ===== THREAT FIELD FILTER =====
def filter_threat_fields(event):
    ti = event.get("threatInfo", {})
    ar = event.get("agentRealtimeInfo", {})
    ad = event.get("agentDetectionInfo", {})
    return {
        "threatId": ti.get("threatId"),
        "threatName": ti.get("threatName"),
        "classification": ti.get("classification"),
        "confidenceLevel": ti.get("confidenceLevel"),
        "incidentStatus": ti.get("incidentStatus"),
        "analystVerdict": ti.get("analystVerdict"),
        "filePath": ti.get("filePath"),
        "sha256": ti.get("sha256"),
        "md5": ti.get("md5"),
        "processUser": ti.get("processUser"),
        "originatorProcess": ti.get("originatorProcess"),
        "mitigationStatus": ti.get("mitigationStatus"),
        "storyline": ti.get("storyline"),
        "createdAt": ti.get("createdAt"),
        "updatedAt": ti.get("updatedAt"),
        "agentComputerName": ar.get("agentComputerName"),
        "agentDomain": ar.get("agentDomain"),
        "agentIpV4": ad.get("agentIpV4"),
        "agentLastLoggedInUserName": ad.get("agentLastLoggedInUserName"),
        "agentOsName": ad.get("agentOsName"),
        "agentVersion": ad.get("agentVersion"),
        "groupName": ad.get("groupName"),
        "siteName": ad.get("siteName"),
        "externalIp": ad.get("externalIp"),
        "indicators": event.get("indicators", []),
    }

# ===== DATA FETCHER =====
def pull_events(start_iso, end_iso, endpoint_name, api_path):
    url = f"{BASE_URL}/{api_path}"
    headers = {
        "Authorization": f"ApiToken {TOKEN}",
        "Content-Type": "application/json"
    }
    params = {
        "createdAt__gte": start_iso,
        "createdAt__lt": end_iso,
        "limit": LIMIT
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code != 200:
            print(f"[{endpoint_name.upper()}] HTTP {response.status_code}: {response.text}")
            return

        data = response.json().get("data", [])
        if not data:
            no_data_msg = f"SentinelOne-{endpoint_name} {{ \"status\": \"no data\", \"start\": \"{start_iso}\", \"end\": \"{end_iso}\" }}"
            send_syslog(no_data_msg)
            print(f"[{endpoint_name.upper()}] No data.")
        else:
            for event in data:
                if endpoint_name == "activities":
                    payload = filter_activity_fields(event)
                elif endpoint_name == "threats":
                    payload = filter_threat_fields(event)
                else:
                    payload = event  # Full for dv_events and cloud-detection/alerts
                log_msg = f"SentinelOne-{endpoint_name} {{ {json.dumps(payload)} }}"
                send_syslog(log_msg)
            print(f"[{endpoint_name.upper()}] {len(data)} events sent.")
    except Exception as ex:
        print(f"[{endpoint_name.upper()}] Error fetching data: {ex}")

# ===== MAIN =====
def main():
    start_iso, end_iso, now_ts = get_time_range()

    for name, path in ENDPOINTS.items():
        print(f"[{name.upper()}] Pulling from {start_iso} → {end_iso}")
        pull_events(start_iso, end_iso, name, path)

    with open(TIMESTAMP_FILE, "w") as f:
        f.write(str(now_ts))

if __name__ == "__main__":
    main()

