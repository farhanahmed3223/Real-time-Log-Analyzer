#!/usr/bin/env python3
"""Real-time Log Analyzer — monitors log files with a curses TUI."""
import re, sys, time, threading, curses, argparse, os, json
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

CONFIG_PATHS = [Path.home()/'.config'/'log-analyzer'/'config.json', Path('config.json')]

def load_config():
    for p in CONFIG_PATHS:
        if p.exists():
            with open(p) as f:
                return json.load(f)
    return {}

class LogParser:
    def __init__(self, extra_patterns=None):
        self.patterns = {
            'syslog': re.compile(r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+(?P<service>\w+)\[?\d*\]?:\s+(?P<level>\w+):?\s+(?P<message>.*)'),
            'apache': re.compile(r'\[(?P<timestamp>.*?)\]\s+\[(?P<level>.*?)\]\s+\[pid \d+\]\s+\[client .*?\]\s+(?P<message>.*)'),
            # fix: nginx pattern was too strict — now handles both access and error logs
            'nginx':  re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+(?:\d+#\d+:?\s*\*?\d*\s*)?(?P<message>.+)'),
            'custom': re.compile(r'(?P<timestamp>.*?)\s+-\s+(?P<level>\w+)\s+-\s+(?P<service>\w+)\s+-\s+(?P<message>.*)')
        }
        self.severity_levels = {'EMERGENCY':0,'ALERT':1,'CRITICAL':2,'ERROR':3,'WARNING':4,'NOTICE':5,'INFO':6,'DEBUG':7}
        if extra_patterns:
            for name, pat in extra_patterns.items():
                try:
                    self.patterns[name] = re.compile(pat)
                except re.error:
                    pass

    def parse_line(self, line, log_type='syslog'):
        pat = self.patterns.get(log_type)
        if pat:
            m = pat.match(line.strip())
            if m:
                d = m.groupdict()
                d.setdefault('service', 'unknown')
                return d
        for level in self.severity_levels:
            if level in line.upper():
                return {'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'level': level, 'service': 'unknown', 'message': line.strip()}
        return None

class PerformanceStats:
    def __init__(self, window_size=300):
        self.window_size = window_size
        self.log_count = 0
        self.error_count = 0
        self.warning_count = 0
        self.service_stats = defaultdict(int)
        self.level_stats = defaultdict(int)
        self.recent_logs = deque(maxlen=1000)
        self.throughput = deque(maxlen=window_size)
        self.start_time = time.time()

    def update(self, e):
        self.log_count += 1
        self.recent_logs.append(e)
        level = e.get('level','INFO').upper()
        self.level_stats[level] += 1
        self.service_stats[e.get('service','unknown')] += 1
        if level in ('ERROR','CRITICAL','ALERT','EMERGENCY'):
            self.error_count += 1
        elif level == 'WARNING':
            self.warning_count += 1
        self.throughput.append((time.time(), 1))

    def get_throughput(self):
        ct = time.time()
        r = [c for ts,c in self.throughput if ct-ts<=10]
        return sum(r)/10.0 if r else 0

    def get_error_rate(self):
        return (self.error_count/self.log_count)*100 if self.log_count else 0

class LogFilter:
    def __init__(self):
        self.severity_threshold = 'DEBUG'
        self.service_filter = None
        self.keyword_filter = None
        self.exclude_keywords = []

    def set_severity(self, level): self.severity_threshold = level.upper()
    def set_service(self, service): self.service_filter = service.lower() if service else None
    def set_keyword(self, keyword): self.keyword_filter = keyword.lower() if keyword else None

    def matches_filter(self, e):
        level = e.get('level','INFO').upper()
        message = e.get('message','').lower()
        sev = ['DEBUG','INFO','NOTICE','WARNING','ERROR','CRITICAL','ALERT','EMERGENCY']
        try:
            if sev.index(level) < sev.index(self.severity_threshold): return False
        except ValueError: pass
        if self.service_filter and self.service_filter not in e.get('service','').lower(): return False
        if self.keyword_filter and self.keyword_filter not in message: return False
        return all(ex not in message for ex in self.exclude_keywords)

class RealTimeLogAnalyzer:
    def __init__(self, log_file, log_type='syslog', config=None):
        self.log_file = log_file
        self.log_type = log_type
        self.config = config or {}
        self.parser = LogParser(extra_patterns=self.config.get('custom_patterns', {}))
        self.stats = PerformanceStats()
        self.filter = LogFilter()
        self.running = False
        self.paused = False
        self.current_view = 'logs'
        self.colors = {}

    def setup_colors(self):
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_YELLOW)
        curses.init_pair(3, curses.COLOR_RED, -1)
        curses.init_pair(4, curses.COLOR_RED, -1)
        curses.init_pair(5, curses.COLOR_YELLOW, -1)
        curses.init_pair(6, curses.COLOR_CYAN, -1)
        curses.init_pair(7, curses.COLOR_GREEN, -1)
        curses.init_pair(8, curses.COLOR_BLUE, -1)
        curses.init_pair(9, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(10, curses.COLOR_CYAN, -1)

    def init_colors(self):
        curses.start_color(); curses.use_default_colors()
        self.colors = {
            'EMERGENCY': curses.color_pair(1)|curses.A_BOLD,
            'ALERT':     curses.color_pair(2)|curses.A_BOLD,
            'CRITICAL':  curses.color_pair(3)|curses.A_BOLD,
            'ERROR':     curses.color_pair(4), 'WARNING': curses.color_pair(5),
            'NOTICE':    curses.color_pair(6), 'INFO':    curses.color_pair(7),
            'DEBUG':     curses.color_pair(8), 'HEADER':  curses.color_pair(9)|curses.A_BOLD,
            'STATS':     curses.color_pair(10),
        }

    def tail_log(self):
        try:
            with open(self.log_file, 'r') as f:
                f.seek(0, 2)
                while self.running:
                    if not self.paused:
                        line = f.readline()
                        if line:
                            parsed = self.parser.parse_line(line, self.log_type)
                            if parsed:
                                self.stats.update(parsed)
                    time.sleep(0.1)
        except FileNotFoundError:
            print(f"Error: Log file '{self.log_file}' not found!"); sys.exit(1)

    def start_monitoring(self):
        self.running = True
        self.monitor_thread = threading.Thread(target=self.tail_log, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=1)

    def draw_header(self, stdscr):
        h, w = stdscr.getmaxyx()
        hdr = f"Real-time Log Analyzer - {self.log_file} - {self.log_type.upper()} logs"
        if self.paused: hdr += " - PAUSED"
        stdscr.attron(self.colors['HEADER']); stdscr.addstr(0, 0, hdr.ljust(w)[:w-1]); stdscr.attroff(self.colors['HEADER'])
        fi = f"Filter: severity>={self.filter.severity_threshold}"
        if self.filter.service_filter: fi += f", service={self.filter.service_filter}"
        stdscr.addstr(1, 0, fi.ljust(w)[:w-1])

    def draw_footer(self, stdscr):
        h, w = stdscr.getmaxyx()
        footer = "Q:Quit | P:Pause | L:Logs | S:Stats | V:Services | F:Filter | C:Clear"
        stdscr.attron(curses.A_REVERSE); stdscr.addstr(h-1, 0, footer.ljust(w)[:w-1]); stdscr.attroff(curses.A_REVERSE)

    def draw_logs_view(self, stdscr):
        h, w = stdscr.getmaxyx(); sl, el = 2, h-2
        logs = [l for l in self.stats.recent_logs if self.filter.matches_filter(l)]
        for i, log in enumerate(reversed(logs[-(el-sl):])):
            ln = sl+i
            if ln >= el: break
            level = log.get('level','INFO').upper()
            line = f"{log.get('timestamp',''):20} {log.get('service','unknown'):15} {level:8} {log.get('message','')}"
            color = self.colors.get(level, self.colors['INFO'])
            stdscr.attron(color); stdscr.addstr(ln, 0, line[:w-1]); stdscr.attroff(color)

    def draw_stats_view(self, stdscr):
        h, w = stdscr.getmaxyx()
        lines = [
            f"Total Logs:   {self.stats.log_count}", f"Errors:       {self.stats.error_count}",
            f"Warnings:     {self.stats.warning_count}", f"Throughput:   {self.stats.get_throughput():.1f} logs/sec",
            f"Error Rate:   {self.stats.get_error_rate():.1f}%", f"Uptime:       {int(time.time()-self.stats.start_time)}s",
            "", "Severity Distribution:",
        ]
        for level, count in sorted(self.stats.level_stats.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                lines.append(f"  {level:10}: {count:6} ({(count/self.stats.log_count)*100:5.1f}%)")
        for i, line in enumerate(lines):
            if 2+i >= h-2: break
            stdscr.attron(self.colors['STATS']); stdscr.addstr(2+i, 0, line[:w-1]); stdscr.attroff(self.colors['STATS'])

    def draw_services_view(self, stdscr):
        h, w = stdscr.getmaxyx()
        stdscr.attron(self.colors['HEADER']); stdscr.addstr(2, 0, "Service Statistics:"); stdscr.attroff(self.colors['HEADER'])
        for i, (svc, count) in enumerate(sorted(self.stats.service_stats.items(), key=lambda x: x[1], reverse=True)):
            ln = 4+i
            if ln >= h-2: break
            pct = (count/self.stats.log_count)*100 if self.stats.log_count else 0
            stdscr.addstr(ln, 0, f"  {svc:20}: {count:6} ({pct:5.1f}%)"[:w-1])

    def handle_filter_input(self, stdscr):
        h, w = stdscr.getmaxyx(); il = h-2
        stdscr.move(il, 0); stdscr.clrtoeol()
        stdscr.addstr(il, 0, "Set severity [DEBUG/INFO/WARNING/ERROR]: "); stdscr.refresh()
        curses.echo(); sev = stdscr.getstr(il, 40, 10).decode().strip().upper(); curses.noecho()
        if sev in ('DEBUG','INFO','NOTICE','WARNING','ERROR','CRITICAL','ALERT','EMERGENCY'):
            self.filter.set_severity(sev)

    def run_ui(self, stdscr):
        curses.curs_set(0); self.setup_colors(); self.init_colors(); self.start_monitoring()
        while self.running:
            stdscr.clear(); self.draw_header(stdscr)
            if self.current_view == 'logs': self.draw_logs_view(stdscr)
            elif self.current_view == 'stats': self.draw_stats_view(stdscr)
            elif self.current_view == 'services': self.draw_services_view(stdscr)
            self.draw_footer(stdscr); stdscr.refresh()
            try:
                key = stdscr.getch()
                if key in (ord('q'),ord('Q')): break
                elif key in (ord('p'),ord('P')): self.paused = not self.paused
                elif key in (ord('l'),ord('L')): self.current_view = 'logs'
                elif key in (ord('s'),ord('S')): self.current_view = 'stats'
                elif key in (ord('v'),ord('V')): self.current_view = 'services'
                elif key in (ord('f'),ord('F')): self.handle_filter_input(stdscr)
                elif key in (ord('c'),ord('C')): self.filter = LogFilter()
            except curses.error: pass
            time.sleep(0.1)
        self.stop_monitoring()

def main():
    config = load_config()
    ap = argparse.ArgumentParser(description='Real-time Log Analyzer')
    ap.add_argument('log_file', help='Path to the log file to monitor')
    ap.add_argument('-t','--type', choices=['syslog','apache','nginx','custom']+list(config.get('custom_patterns',{}).keys()),
                    default=config.get('default_log_type','syslog'))
    ap.add_argument('--severity', choices=['DEBUG','INFO','WARNING','ERROR','CRITICAL'],
                    default=config.get('default_severity','DEBUG'))
    args = ap.parse_args()
    if not os.path.exists(args.log_file):
        print(f"Error: Log file '{args.log_file}' not found!"); sys.exit(1)
    analyzer = RealTimeLogAnalyzer(args.log_file, args.type, config=config)
    analyzer.filter.set_severity(args.severity)
    try:
        curses.wrapper(analyzer.run_ui)
    except KeyboardInterrupt:
        analyzer.stop_monitoring(); print("\nLog analyzer stopped.")

if __name__ == '__main__':
    main()
