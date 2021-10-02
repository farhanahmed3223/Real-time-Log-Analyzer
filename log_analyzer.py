#!/usr/bin/env python3
import sys
import time
import re
import curses
import threading
from collections import defaultdict, deque

SYSLOG_RE = re.compile(
    r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<service>\w+)\[?(\d*)\]?:\s+(?P<message>.*)'
)

recent_logs = deque(maxlen=500)
running = True

def parse_line(line):
    m = SYSLOG_RE.match(line.strip())
    if m:
        d = m.groupdict()
        for level in ['ERROR','CRITICAL','WARNING','INFO','DEBUG']:
            if level in d['message'].upper():
                d['level'] = level
                break
        else:
            d['level'] = 'INFO'
        return d
    return None

def tail_thread(filename):
    global running
    with open(filename, 'r') as f:
        f.seek(0, 2)
        while running:
            line = f.readline()
            if line:
                parsed = parse_line(line)
                if parsed:
                    recent_logs.append(parsed)
            else:
                time.sleep(0.05)

def main(stdscr, filename):
    global running
    curses.curs_set(0)
    curses.start_color()
    curses.init_pair(1, curses.COLOR_RED, -1)
    curses.init_pair(2, curses.COLOR_YELLOW, -1)
    curses.init_pair(3, curses.COLOR_GREEN, -1)

    t = threading.Thread(target=tail_thread, args=(filename,), daemon=True)
    t.start()

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        logs = list(recent_logs)[-(h-2):]
        for i, log in enumerate(logs):
            level = log.get('level', 'INFO')
            pair = {
                'ERROR': curses.color_pair(1), 'CRITICAL': curses.color_pair(1),
                'WARNING': curses.color_pair(2),
            }.get(level, curses.color_pair(3))
            line = f"{log.get('timestamp',''):20} {log.get('service',''):12} {level:8} {log.get('message','')}".ljust(w)
            stdscr.attron(pair)
            stdscr.addstr(i, 0, line[:w-1])
            stdscr.attroff(pair)
        stdscr.refresh()
        stdscr.timeout(100)
        key = stdscr.getch()
        if key == ord('q'):
            running = False
            break

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("usage: log_analyzer.py <logfile>")
        sys.exit(1)
    curses.wrapper(main, sys.argv[1])
