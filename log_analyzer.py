#!/usr/bin/env python3
import sys
import time

def tail(filename):
    """Tail a log file and print new lines."""
    with open(filename, 'r') as f:
        f.seek(0, 2)  # go to end
        while True:
            line = f.readline()
            if line:
                print(line, end='')
            else:
                time.sleep(0.1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("usage: log_analyzer.py <logfile>")
        sys.exit(1)
    tail(sys.argv[1])
