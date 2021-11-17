#!/usr/bin/env python3
import re
import sys
import time
import threading
import curses
import argparse
import os
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

class PerformanceStats:
    def __init__(self):
        self.log_count = 0
        self.error_count = 0
        self.warning_count = 0
        self.level_stats = defaultdict(int)
        self.service_stats = defaultdict(int)
        self.recent_logs = deque(maxlen=1000)
        self.start_time = time.time()

    def update(self, entry):
        self.log_count += 1
        self.recent_logs.append(entry)
        level = entry.get('level', 'INFO').upper()
        service = entry.get('service', 'unknown')
        self.level_stats[level] += 1
        self.service_stats[service] += 1
        if level in ['ERROR','CRITICAL','ALERT','EMERGENCY']:
            self.error_count += 1
        elif level == 'WARNING':
            self.warning_count += 1

    # TODO: add throughput calculation
    def get_error_rate(self):
        if self.log_count == 0:
            return 0
        return (self.error_count / self.log_count) * 100

def main():
    ap = argparse.ArgumentParser(description='Real-time Log Analyzer')
    ap.add_argument('log_file')
    ap.add_argument('-t', '--type', choices=['syslog','apache','nginx','custom'], default='syslog')
    ap.add_argument('--severity', default='DEBUG')
    args = ap.parse_args()

    if not os.path.exists(args.log_file):
        print(f"Error: '{args.log_file}' not found"); sys.exit(1)

    parser = LogParser()
    stats = PerformanceStats()
    with open(args.log_file, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                parsed = parser.parse_line(line, args.type)
                if parsed:
                    stats.update(parsed)
                    print(f"[{parsed.get('level','?'):8}] {parsed.get('message','')}")
            else:
                time.sleep(0.1)

if __name__ == '__main__':
    main()
