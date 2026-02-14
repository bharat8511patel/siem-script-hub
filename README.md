# SIEM Script Hub

A collection of SIEM integration scripts for log collection, syslog forwarding, and security event aggregation. Each script collects logs from a specific vendor/product and forwards them to a centralized syslog server (FortiSIEM, Sentinel, etc.).

## Scripts

| Script | Vendor | Product | Device Type |
|--------|--------|---------|-------------|
| `Final_Scapy_cloudwatch.txt` | AWS | CloudWatch VPC Logs | Cloud/SIEM |
| `TCS_Cloudwatch.txt` | AWS | CloudWatch VPC Logs (TCS) | Cloud/SIEM |
| `gsuit_Final.py` | Google | Google Workspace | IAM/Cloud Services |
| `iraje_fetch_api.py` | Iraje | Iraje PAM | IAM/PAM |
| `newnetskope.py` | Netskope | Netskope | Cloud/Network Security |
| `o365_logs.py` | Microsoft | Office 365 | Cloud/Email Security |
| `rediff.py` | Rediff | RediffmailPro | Email Security |
| `sentinel.py` | SentinelOne | SentinelOne | Endpoint Security |
| `shield_Arvind.py` | TechOwl | TechOwlShield | Endpoint Security |
| `UPDATED_TREND.py` | Trend Micro | Trend Vision One | Endpoint Security/XDR |
| `WatchGuard_EPDR_UPDATED.py` | WatchGuard | WatchGuard EPDR | Endpoint Security |
| `Zoho_Mail.py` | Zoho | Zoho Mail | Email Security |

## Usage

1. Download the script for your vendor/product
2. Configure the credentials and syslog server IP in the script
3. Run with Python 3

## Deployment

This site is hosted on GitHub Pages. To deploy your own:

1. Fork this repository
2. Go to **Settings > Pages**
3. Select **Deploy from branch** > **main** > **/ (root)**
4. Your site will be live at `https://<username>.github.io/siem-script-hub/`

## Disclaimer

Scripts are provided as-is. Always review and configure credentials before use in production environments.
