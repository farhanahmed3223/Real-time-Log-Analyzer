#!/usr/bin/env python3
import re
import sys
import time
import threading
import curses
import argparse
from collections import defaultdict, deque
from datetime import datetime

class LogParser:
    def __init__(self):
        self.patterns = {
            'syslog': re.compile(r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+(?P<service>\w+)\[?\d*\]?:\s+(?P<level>\w+):?\s+(?P<message>.*)'),
            'apache': re.compile(r'\[(?P<timestamp>.*?)\]\s+\[(?P<level>.*?)\]\s+\[pid \d+\]\s+\[client .*?\]\s+(?P<message>.*)'),
            'nginx':  re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>.*?)\]\s+\d+#\d+:\s+\*\d+\s+(?P<message>.*)'),
            'custom': re.compile(r'(?P<timestamp>.*?)\s+-\s+(?P<level>\w+)\s+-\s+(?P<service>\w+)\s+-\s+(?P<message>.*)')
        }

    def parse_line(self, line, log_type='syslog'):
        pat = self.patterns.get(log_type)
        if pat:
            m = pat.match(line.strip())
            if m:
                return m.groupdict()
        for level in ['EMERGENCY','ALERT','CRITICAL','ERROR','WARNING','NOTICE','INFO','DEBUG']:
            if level in line.upper():
                return {'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'level': level, 'service': 'unknown', 'message': line.strip()}
        return None

def main():
    ap = argparse.ArgumentParser(description='Real-time Log Analyzer')
    ap.add_argument('log_file', help='Path to log file')
    ap.add_argument('-t', '--type', choices=['syslog','apache','nginx','custom'], default='syslog')
    ap.add_argument('--severity', choices=['DEBUG','INFO','WARNING','ERROR','CRITICAL'], default='DEBUG')
    args = ap.parse_args()

    import os
    if not os.path.exists(args.log_file):
        print(f"Error: '{args.log_file}' not found")
        sys.exit(1)

    print(f"Monitoring {args.log_file} [{args.type}] min severity={args.severity}")
    parser = LogParser()
    with open(args.log_file, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                parsed = parser.parse_line(line, args.type)
                if parsed:
                    print(f"[{parsed.get('level','?'):8}] {parsed.get('service','?'):12} {parsed.get('message','')}")
            else:
                time.sleep(0.1)

if __name__ == '__main__':
    main()
