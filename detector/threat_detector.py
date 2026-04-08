import json
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'parser'))

from log_parser import parse_auth_log
from collections import Counter

LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'auth.log')
THRESHOLD = 5

def detect_brute_force(events):
    alerts = []
    ip_counts = Counter(e['source_ip'] for e in events)

    for ip, count in ip_counts.items():
        if count >= THRESHOLD:
            alerts.append({
                "alert": "BRUTE FORCE DETECTED",
                "source_ip": ip,
                "attempts": count,
                "severity": "HIGH"
            })
    return alerts

def detect_multiple_users(events):
    alerts = []
    ip_users = {}

    for e in events:
        ip = e['source_ip']
        user = e['user']
        if ip not in ip_users:
            ip_users[ip] = set()
        ip_users[ip].add(user)

    for ip, users in ip_users.items():
        if len(users) >= 2:
            alerts.append({
                "alert": "MULTIPLE USERNAMES ATTEMPTED",
                "source_ip": ip,
                "usernames_tried": list(users),
                "severity": "MEDIUM"
            })
    return alerts

if __name__ == "__main__":
    events = parse_auth_log(LOG_FILE)

    print("\n--- BRUTE FORCE ALERTS ---")
    bf_alerts = detect_brute_force(events)
    if bf_alerts:
        for a in bf_alerts:
            print(json.dumps(a, indent=2))
    else:
        print("No brute force detected")

    print("\n--- MULTIPLE USERNAME ALERTS ---")
    mu_alerts = detect_multiple_users(events)
    if mu_alerts:
        for a in mu_alerts:
            print(json.dumps(a, indent=2))
    else:
        print("No multiple username attempts detected") 
