# Make executable
chmod +x log_analyzer.py
chmod +x install.sh

# Install
./install.sh

# Basic usage
log-analyzer /var/log/syslog

# With specific log type and severity filter
log-analyzer /var/log/apache2/access.log -t apache --severity ERROR

# Monitor custom application logs
log-analyzer /path/to/app.log -t custom
