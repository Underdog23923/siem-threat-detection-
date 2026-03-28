import json
import sys
import os
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'parser'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'detector'))

from log_parser import parse_auth_log
from threat_detector import detect_brute_force, detect_multiple_users
from elasticsearch import Elasticsearch

LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'auth.log')

ELASTIC_URL = os.getenv("ELASTIC_URL")
ELASTIC_USER = os.getenv("ELASTIC_USER")
ELASTIC_PASS = os.getenv("ELASTIC_PASS")

es = Elasticsearch( 
    ELASTIC_URL,
    basic_auth=(ELASTIC_USER, ELASTIC_PASS)
)

def check_connection():
    if es.ping():
        print(" Connected to Elastic Cloud")
        return True
    else:
        print(" Cannot connect — check your URL and password")
        return False

def forward_events(events):
    print(f"\n--- FORWARDING {len(events)} EVENTS ---")
    for event in events:
        event['ingested_at'] = datetime.now().isoformat()
        res = es.index(index="auth-logs", document=event)
        print(f"Indexed: {event['source_ip']} | {event['event_type']} | ID: {res['_id']}")

def forward_alerts(alerts, alert_type):
    print(f"\n--- FORWARDING {len(alerts)} {alert_type} ALERTS ---")
    for alert in alerts:
        alert['ingested_at'] = datetime.now().isoformat()
        res = es.index(index="siem-alerts", document=alert)
        print(f"Indexed alert: {alert['alert']} | {alert['source_ip']} | ID: {res['_id']}")

if __name__ == "__main__":
    if not check_connection():
        sys.exit(1)

    events = parse_auth_log(LOG_FILE)
    bf_alerts = detect_brute_force(events)
    mu_alerts = detect_multiple_users(events)

    forward_events(events)
    forward_alerts(bf_alerts, "BRUTE FORCE")
    forward_alerts(mu_alerts, "MULTIPLE USERNAME")

    print("\n All data forwarded to Elastic Cloud!")
    print(" Open Kibana to visualize your data")  