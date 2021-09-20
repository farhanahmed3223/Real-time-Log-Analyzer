#!/usr/bin/env python3
import sys
import time
import re
from collections import defaultdict

COLORS = {
    'ERROR':    '\033[91m', 'CRITICAL': '\033[91m', 'ALERT': '\033[91m',
    'WARNING':  '\033[93m', 'INFO':     '\033[92m', 'DEBUG': '\033[94m',
    'RESET':    '\033[0m',
}

SYSLOG_RE = re.compile(
    r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<service>\w+)\[?(\d*)\]?:\s+(?P<message>.*)'
)

def parse_syslog(line):
    m = SYSLOG_RE.match(line.strip())
    if m:
        d = m.groupdict()
        for level in ['ERROR', 'CRITICAL', 'WARNING', 'INFO', 'DEBUG', 'ALERT']:
            if level in d['message'].upper():
                d['level'] = level
                break
        else:
            d['level'] = 'INFO'
        return d
    return None

def colorize(level, line):
    color = COLORS.get(level, '')
    return f"{color}{line}{COLORS['RESET']}" if color else line

def tail(filename):
    counts = defaultdict(int)
    with open(filename, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                parsed = parse_syslog(line)
                if parsed:
                    counts[parsed['level']] += 1
                    print(colorize(parsed['level'], line.rstrip()))
                else:
                    print(line.rstrip())
            else:
                time.sleep(0.1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("usage: log_analyzer.py <logfile>")
        sys.exit(1)
    tail(sys.argv[1])
