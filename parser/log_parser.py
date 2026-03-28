import re
import json

LOG_FILE = "../logs/auth.log"

def parse_auth_log(filepath):
    events = []
    pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)'

    with open(filepath, 'r') as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                events.append({
                    "timestamp": match.group(1),
                    "user": match.group(2),
                    "source_ip": match.group(3),
                    "event_type": "failed_login"
                })
    return events

if __name__ == "__main__":
    events = parse_auth_log(LOG_FILE)
    for e in events:
        print(json.dumps(e)) 