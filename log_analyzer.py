#!/usr/bin/env python3
import sys
import time
import re

COLORS = {
    'ERROR':    '\033[91m',
    'CRITICAL': '\033[91m',
    'WARNING':  '\033[93m',
    'INFO':     '\033[92m',
    'DEBUG':    '\033[94m',
    'RESET':    '\033[0m',
}

def colorize(line):
    for level, color in COLORS.items():
        if level in line.upper():
            return f"{color}{line}{COLORS['RESET']}"
    return line

def tail(filename):
    with open(filename, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                print(colorize(line.rstrip()))
            else:
                time.sleep(0.1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("usage: log_analyzer.py <logfile>")
        sys.exit(1)
    tail(sys.argv[1])
