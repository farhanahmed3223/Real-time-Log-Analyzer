#!/usr/bin/env python3
import re
import sys
import time
import threading
import curses
from collections import defaultdict, deque

class LogParser:
    def __init__(self):
        self.patterns = {
            'syslog': re.compile(r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+(?P<service>\w+)\[?\d*\]?:\s+(?P<level>\w+):?\s+(?P<message>.*)'),
            'apache': re.compile(r'\[(?P<timestamp>.*?)\]\s+\[(?P<level>.*?)\]\s+\[pid \d+\]\s+\[client .*?\]\s+(?P<message>.*)'),
            'nginx':  re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>.*?)\]\s+\d+#\d+:\s+\*\d+\s+(?P<message>.*)'),
            'custom': re.compile(r'(?P<timestamp>.*?)\s+-\s+(?P<level>\w+)\s+-\s+(?P<service>\w+)\s+-\s+(?P<message>.*)')
        }
        self.severity_levels = {
            'EMERGENCY': 0, 'ALERT': 1, 'CRITICAL': 2, 'ERROR': 3,
            'WARNING': 4, 'NOTICE': 5, 'INFO': 6, 'DEBUG': 7
        }

    def parse_line(self, line, log_type='syslog'):
        if log_type in self.patterns:
            match = self.patterns[log_type].match(line.strip())
            if match:
                return match.groupdict()
        for level in self.severity_levels:
            if level in line.upper():
                from datetime import datetime
                return {'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'level': level, 'service': 'unknown', 'message': line.strip()}
        return None

recent_logs = deque(maxlen=1000)
running = True

def tail_thread(filename, parser, log_type):
    with open(filename, 'r') as f:
        f.seek(0, 2)
        while running:
            line = f.readline()
            if line:
                parsed = parser.parse_line(line, log_type)
                if parsed:
                    recent_logs.append(parsed)
            else:
                time.sleep(0.05)

def main_ui(stdscr, filename, log_type):
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, -1)
    curses.init_pair(2, curses.COLOR_YELLOW, -1)
    curses.init_pair(3, curses.COLOR_GREEN, -1)
    curses.init_pair(4, curses.COLOR_CYAN, -1)

    parser = LogParser()
    t = threading.Thread(target=tail_thread, args=(filename, parser, log_type), daemon=True)
    t.start()

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        logs = list(recent_logs)[-(h-2):]
        for i, log in enumerate(logs):
            level = log.get('level', 'INFO').upper()
            pair = {'ERROR': 1, 'CRITICAL': 1, 'ALERT': 1,
                    'WARNING': 2, 'INFO': 3}.get(level, 4)
            line = f"{log.get('timestamp',''):20} {log.get('service','unknown'):12} {level:8} {log.get('message','')}"
            stdscr.attron(curses.color_pair(pair))
            stdscr.addstr(i, 0, line[:w-1])
            stdscr.attroff(curses.color_pair(pair))
        stdscr.refresh()
        stdscr.timeout(100)
        if stdscr.getch() == ord('q'):
            break

if __name__ == '__main__':
    lt = sys.argv[2] if len(sys.argv) > 2 else 'syslog'
    curses.wrapper(main_ui, sys.argv[1], lt)
