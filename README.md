# 🛡️ SIEM Threat Detection System

A lightweight SIEM pipeline built with Python and Elastic Stack that ingests Linux
auth logs, runs detection rules for common attack patterns, and surfaces alerts
on a live Kibana dashboard.

> Built as a portfolio project to demonstrate blue team skills —
> log analysis, threat detection, and SIEM tooling.

---

## What This Does

Most brute force attacks on Linux systems leave clear traces in `/var/log/auth.log`.
This project automates the process of finding those traces:

- Parses raw SSH failure logs using regex
- Flags IPs that cross a brute force threshold (5+ failed attempts)
- Catches username enumeration (same IP trying multiple accounts)
- Ships everything to Elasticsearch and visualizes it in Kibana

---

## Pipeline Architecture
```
auth.log ──► log_parser.py ──► threat_detector.py ──► elastic_forwarder.py ──► Kibana
```

---

## Tech Stack

- **Python 3** — parsing, detection logic, Elasticsearch client
- **Elasticsearch** — event storage and indexing
- **Kibana** — dashboard and visualization
- **Elastic Cloud** — hosted on GCP Mumbai (asia-south1)

---

## Detection Rules

**Brute Force** `HIGH`
Fires when a single IP exceeds 5 failed login attempts against any username.

**Username Enumeration** `MEDIUM`
Fires when a single IP attempts login against 2 or more different usernames —
a common indicator of credential stuffing or manual reconnaissance.

---

## Dashboard

Three panels built in Kibana:

| Panel | Type | Shows |
|-------|------|-------|
| Failed Logins by IP | Bar chart | Attack volume per source IP |
| Event Log | Table | Timestamp, username, source IP, count |
| Total Events | Metric | Running count of all ingested events |

![SIEM Dashboard](screenshots/dashboard.png)

---

## Sample Alerts
```json
{
  "alert": "BRUTE FORCE DETECTED",
  "source_ip": "192.168.1.105",
  "attempts": 5,
  "severity": "HIGH"
}

{
  "alert": "MULTIPLE USERNAMES ATTEMPTED",
  "source_ip": "192.168.1.105",
  "usernames_tried": ["root", "admin"],
  "severity": "MEDIUM"
}
```

---

## Setup
```bash
# Clone
git clone https://github.com/your-username/siem-threat-detection.git
cd siem-threat-detection

# Install dependencies
pip install -r requirements.txt

# Run the pipeline
python parser/log_parser.py
python detector/threat_detector.py

# Configure your Elastic Cloud credentials in forwarder/elastic_forwarder.py
# then run:
python forwarder/elastic_forwarder.py
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Detected By |
|-----------|----|-------------|
| Brute Force | T1110 | Threshold-based IP count |
| Valid Accounts / Enumeration | T1078 | Multi-username detection |

---

## Notes

Log data is simulated for demonstration. All IPs and usernames are fictional.

---

**Harsh Wanwe** — Cybersecurity Student, TISA Certified  
[LinkedIn](https://linkedin.com/in/harsh-wanwe-53944b256) · [GitHub](https://github.com/Underdog23923)