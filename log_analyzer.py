#!/usr/bin/env python3
import re
import sys
import time
import threading
import curses
from collections import defaultdict, deque
from datetime import datetime
import argparse
import os
from pathlib import Path

class LogParser:
    def __init__(self):
        # Common log patterns
        self.patterns = {
            'syslog': re.compile(r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+(?P<service>\w+)\[?\d*\]?:\s+(?P<level>\w+):?\s+(?P<message>.*)'),
            'apache': re.compile(r'\[(?P<timestamp>.*?)\]\s+\[(?P<level>.*?)\]\s+\[pid \d+\]\s+\[client .*?\]\s+(?P<message>.*)'),
            'nginx': re.compile(r'(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>.*?)\]\s+\d+#\d+:\s+\*\d+\s+(?P<message>.*)'),
            'custom': re.compile(r'(?P<timestamp>.*?)\s+-\s+(?P<level>\w+)\s+-\s+(?P<service>\w+)\s+-\s+(?P<message>.*)')
        }
        
        self.severity_levels = {
            'EMERGENCY': 0,
            'ALERT': 1,
            'CRITICAL': 2,
            'ERROR': 3,
            'WARNING': 4,
            'NOTICE': 5,
            'INFO': 6,
            'DEBUG': 7
        }

    def parse_line(self, line, log_type='syslog'):
        """Parse a log line and extract structured data"""
        if log_type in self.patterns:
            match = self.patterns[log_type].match(line.strip())
            if match:
                return match.groupdict()
        
        # Fallback: try to extract severity level
        for level in self.severity_levels:
            if level in line.upper():
                return {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'level': level,
                    'service': 'unknown',
                    'message': line.strip()
                }
        
        return None

class PerformanceStats:
    def __init__(self, window_size=300):  # 5 minutes default
        self.window_size = window_size
        self.log_count = 0
        self.error_count = 0
        self.warning_count = 0
        self.service_stats = defaultdict(int)
        self.level_stats = defaultdict(int)
        self.recent_logs = deque(maxlen=1000)
        self.throughput = deque(maxlen=window_size)
        self.start_time = time.time()
        
    def update(self, log_entry):
        """Update statistics with new log entry"""
        self.log_count += 1
        self.recent_logs.append(log_entry)
        
        level = log_entry.get('level', 'INFO').upper()
        service = log_entry.get('service', 'unknown')
        
        self.level_stats[level] += 1
        self.service_stats[service] += 1
        
        if level in ['ERROR', 'CRITICAL', 'ALERT', 'EMERGENCY']:
            self.error_count += 1
        elif level == 'WARNING':
            self.warning_count += 1
            
        # Update throughput (logs per second)
        current_time = time.time()
        self.throughput.append((current_time, 1))
        
    def get_throughput(self):
        """Calculate current throughput (logs per second)"""
        if not self.throughput:
            return 0
            
        current_time = time.time()
        # Count logs in last 10 seconds
        recent_logs = [count for ts, count in self.throughput if current_time - ts <= 10]
        return sum(recent_logs) / 10.0 if recent_logs else 0
        
    def get_error_rate(self):
        """Calculate error rate percentage"""
        if self.log_count == 0:
            return 0
        return (self.error_count / self.log_count) * 100

class LogFilter:
    def __init__(self):
        self.severity_threshold = 'DEBUG'  # Show all by default
        self.service_filter = None
        self.keyword_filter = None
        self.exclude_keywords = []
        
    def set_severity(self, level):
        """Set minimum severity level to display"""
        self.severity_threshold = level.upper()
        
    def set_service(self, service):
        """Filter by specific service"""
        self.service_filter = service.lower() if service else None
        
    def set_keyword(self, keyword):
        """Filter by keyword in message"""
        self.keyword_filter = keyword.lower() if keyword else None
        
    def add_exclude_keyword(self, keyword):
        """Exclude logs containing specific keyword"""
        if keyword and keyword not in self.exclude_keywords:
            self.exclude_keywords.append(keyword.lower())
            
    def matches_filter(self, log_entry):
        """Check if log entry matches current filters"""
        level = log_entry.get('level', 'INFO').upper()
        service = log_entry.get('service', '').lower()
        message = log_entry.get('message', '').lower()
        
        # Severity filter
        severity_levels = ['DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERROR', 'CRITICAL', 'ALERT', 'EMERGENCY']
        try:
            if severity_levels.index(level) > severity_levels.index(self.severity_threshold):
                return False
        except ValueError:
            # If level not found, include it
            pass
            
        # Service filter
        if self.service_filter and self.service_filter not in service:
            return False
            
        # Keyword filter
        if self.keyword_filter and self.keyword_filter not in message:
            return False
            
        # Exclude keywords
        for exclude in self.exclude_keywords:
            if exclude in message:
                return False
                
        return True

class RealTimeLogAnalyzer:
    def __init__(self, log_file, log_type='syslog'):
        self.log_file = log_file
        self.log_type = log_type
        self.parser = LogParser()
        self.stats = PerformanceStats()
        self.filter = LogFilter()
        self.running = False
        self.paused = False
        self.current_view = 'logs'  # 'logs', 'stats', 'services'
        self.colors = {}
        
    def init_colors(self):
        """Initialize color pairs for curses"""
        curses.start_color()
        curses.use_default_colors()
        
        # Define color pairs
        self.colors = {
            'EMERGENCY': curses.color_pair(1) | curses.A_BOLD,
            'ALERT': curses.color_pair(2) | curses.A_BOLD,
            'CRITICAL': curses.color_pair(3) | curses.A_BOLD,
            'ERROR': curses.color_pair(4),
            'WARNING': curses.color_pair(5),
            'NOTICE': curses.color_pair(6),
            'INFO': curses.color_pair(7),
            'DEBUG': curses.color_pair(8),
            'HEADER': curses.color_pair(9) | curses.A_BOLD,
            'STATS': curses.color_pair(10)
        }
        
    def setup_colors(self):
        """Setup color pairs"""
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)     # EMERGENCY
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_YELLOW)    # ALERT
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)     # CRITICAL
        curses.init_pair(4, curses.COLOR_RED, -1)                     # ERROR
        curses.init_pair(5, curses.COLOR_YELLOW, -1)                  # WARNING
        curses.init_pair(6, curses.COLOR_CYAN, -1)                    # NOTICE
        curses.init_pair(7, curses.COLOR_GREEN, -1)                   # INFO
        curses.init_pair(8, curses.COLOR_BLUE, -1)                    # DEBUG
        curses.init_pair(9, curses.COLOR_WHITE, curses.COLOR_BLUE)    # HEADER
        curses.init_pair(10, curses.COLOR_CYAN, -1)                   # STATS
        
    def tail_log(self):
        """Tail the log file for new entries"""
        try:
            with open(self.log_file, 'r') as file:
                # Go to end of file
                file.seek(0, 2)
                
                while self.running:
                    if not self.paused:
                        line = file.readline()
                        if line:
                            parsed = self.parser.parse_line(line, self.log_type)
                            if parsed:
                                self.stats.update(parsed)
                    time.sleep(0.1)
        except FileNotFoundError:
            print(f"Error: Log file '{self.log_file}' not found!")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading log file: {e}")
            sys.exit(1)
            
    def start_monitoring(self):
        """Start the log monitoring thread"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self.tail_log)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        """Stop the log monitoring"""
        self.running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=1)
            
    def draw_header(self, stdscr):
        """Draw the application header"""
        height, width = stdscr.getmaxyx()
        
        # Header with application info
        header = f"Real-time Log Analyzer - {self.log_file} - {self.log_type.upper()} logs"
        if self.paused:
            header += " - PAUSED"
            
        stdscr.attron(self.colors['HEADER'])
        stdscr.addstr(0, 0, header.ljust(width)[:width-1])
        stdscr.attroff(self.colors['HEADER'])
        
        # Filter info
        filter_info = f"Filter: severity>={self.filter.severity_threshold}"
        if self.filter.service_filter:
            filter_info += f", service={self.filter.service_filter}"
        if self.filter.keyword_filter:
            filter_info += f", keyword={self.filter.keyword_filter}"
            
        stdscr.addstr(1, 0, filter_info.ljust(width)[:width-1])
        
    def draw_footer(self, stdscr):
        """Draw the application footer with controls"""
        height, width = stdscr.getmaxyx()
        
        controls = [
            "Q:Quit",
            "P:Pause/Resume",
            "L:Logs View",
            "S:Stats View",
            "V:Services View",
            "F:Set Filter",
            "C:Clear Filters"
        ]
        
        footer = " | ".join(controls)
        stdscr.attron(curses.A_REVERSE)
        stdscr.addstr(height-1, 0, footer.ljust(width)[:width-1])
        stdscr.attroff(curses.A_REVERSE)
        
    def draw_logs_view(self, stdscr):
        """Display the logs view"""
        height, width = stdscr.getmaxyx()
        start_line = 2  # Below header
        end_line = height - 2  # Above footer
        
        # Display recent logs (filtered)
        display_logs = [log for log in self.stats.recent_logs 
                       if self.filter.matches_filter(log)]
        
        for i, log_entry in enumerate(reversed(display_logs[- (end_line - start_line):])):
            line_num = start_line + i
            if line_num >= end_line:
                break
                
            level = log_entry.get('level', 'INFO').upper()
            timestamp = log_entry.get('timestamp', '')[:20]
            service = log_entry.get('service', 'unknown')[:15]
            message = log_entry.get('message', '')[:width-40]
            
            # Format log line
            log_line = f"{timestamp:20} {service:15} {level:8} {message}"
            log_line = log_line[:width-1]
            
            # Color by severity
            color = self.colors.get(level, self.colors['INFO'])
            stdscr.attron(color)
            stdscr.addstr(line_num, 0, log_line)
            stdscr.attroff(color)
            
    def draw_stats_view(self, stdscr):
        """Display statistics view"""
        height, width = stdscr.getmaxyx()
        start_line = 2
        
        stats_lines = [
            f"Total Logs: {self.stats.log_count}",
            f"Errors: {self.stats.error_count}",
            f"Warnings: {self.stats.warning_count}",
            f"Throughput: {self.stats.get_throughput():.1f} logs/sec",
            f"Error Rate: {self.stats.get_error_rate():.1f}%",
            f"Uptime: {int(time.time() - self.stats.start_time)}s",
            "",
            "Severity Distribution:"
        ]
        
        # Add level statistics
        for level, count in sorted(self.stats.level_stats.items(), 
                                 key=lambda x: x[1], reverse=True):
            if count > 0:
                percentage = (count / self.stats.log_count) * 100
                stats_lines.append(f"  {level:10}: {count:6} ({percentage:5.1f}%)")
                
        for i, line in enumerate(stats_lines):
            if start_line + i >= height - 2:
                break
            stdscr.attron(self.colors['STATS'])
            stdscr.addstr(start_line + i, 0, line[:width-1])
            stdscr.attroff(self.colors['STATS'])
            
    def draw_services_view(self, stdscr):
        """Display services view"""
        height, width = stdscr.getmaxyx()
        start_line = 2
        
        stdscr.attron(self.colors['HEADER'])
        stdscr.addstr(start_line, 0, "Service Statistics:")
        stdscr.attroff(self.colors['HEADER'])
        
        # Display service statistics
        services = sorted(self.stats.service_stats.items(), 
                         key=lambda x: x[1], reverse=True)
        
        for i, (service, count) in enumerate(services):
            line_num = start_line + 2 + i
            if line_num >= height - 2:
                break
                
            percentage = (count / self.stats.log_count) * 100 if self.stats.log_count > 0 else 0
            service_line = f"  {service:20}: {count:6} ({percentage:5.1f}%)"
            stdscr.addstr(line_num, 0, service_line[:width-1])
            
    def handle_filter_input(self, stdscr):
        """Handle filter configuration input"""
        height, width = stdscr.getmaxyx()
        
        # Clear input area
        input_line = height - 2
        stdscr.move(input_line, 0)
        stdscr.clrtoeol()
        
        stdscr.addstr(input_line, 0, "Set severity level [DEBUG/INFO/WARNING/ERROR]: ")
        stdscr.refresh()
        
        curses.echo()
        severity = stdscr.getstr(input_line, 45, 10).decode('utf-8').strip().upper()
        curses.noecho()
        
        if severity in self.parser.severity_levels:
            self.filter.set_severity(severity)
            
        stdscr.move(input_line, 0)
        stdscr.clrtoeol()
        stdscr.addstr(input_line, 0, "Filter by service (Enter to skip): ")
        stdscr.refresh()
        
        curses.echo()
        service = stdscr.getstr(input_line, 35, 20).decode('utf-8').strip()
        curses.noecho()
        
        if service:
            self.filter.set_service(service)
            
    def run_ui(self, stdscr):
        """Main UI loop"""
        curses.curs_set(0)
        self.setup_colors()
        self.init_colors()
        
        self.start_monitoring()
        
        while self.running:
            stdscr.clear()
            self.draw_header(stdscr)
            
            # Draw current view
            if self.current_view == 'logs':
                self.draw_logs_view(stdscr)
            elif self.current_view == 'stats':
                self.draw_stats_view(stdscr)
            elif self.current_view == 'services':
                self.draw_services_view(stdscr)
                
            self.draw_footer(stdscr)
            stdscr.refresh()
            
            # Handle input
            try:
                key = stdscr.getch()
                
                if key == ord('q') or key == ord('Q'):
                    break
                elif key == ord('p') or key == ord('P'):
                    self.paused = not self.paused
                elif key == ord('l') or key == ord('L'):
                    self.current_view = 'logs'
                elif key == ord('s') or key == ord('S'):
                    self.current_view = 'stats'
                elif key == ord('v') or key == ord('V'):
                    self.current_view = 'services'
                elif key == ord('f') or key == ord('F'):
                    self.handle_filter_input(stdscr)
                elif key == ord('c') or key == ord('C'):
                    self.filter = LogFilter()  # Reset filters
                    
            except curses.error:
                pass
                
            time.sleep(0.1)
            
        self.stop_monitoring()

def main():
    parser = argparse.ArgumentParser(description='Real-time Log Analyzer')
    parser.add_argument('log_file', help='Path to the log file to monitor')
    parser.add_argument('-t', '--type', choices=['syslog', 'apache', 'nginx', 'custom'], 
                       default='syslog', help='Log format type')
    parser.add_argument('--severity', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       default='DEBUG', help='Minimum severity level to display')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.log_file):
        print(f"Error: Log file '{args.log_file}' not found!")
        sys.exit(1)
        
    analyzer = RealTimeLogAnalyzer(args.log_file, args.type)
    analyzer.filter.set_severity(args.severity)
    
    try:
        curses.wrapper(analyzer.run_ui)
    except KeyboardInterrupt:
        analyzer.stop_monitoring()
        print("\nLog analyzer stopped.")

if __name__ == "__main__":
    main()
