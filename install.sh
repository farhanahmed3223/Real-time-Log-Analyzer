#!/bin/bash
echo "Installing Real-time Log Analyzer..."

if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

INSTALL_DIR="$HOME/.local/bin"
CONFIG_DIR="$HOME/.config/log-analyzer"

mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"

cp log_analyzer.py "$INSTALL_DIR/log-analyzer"
chmod +x "$INSTALL_DIR/log-analyzer"

# Copy default config if none exists
if [ ! -f "$CONFIG_DIR/config.json" ]; then
    cp config.json "$CONFIG_DIR/config.json"
    echo "Default config written to $CONFIG_DIR/config.json"
fi

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$HOME/.bashrc"
    echo "Added $INSTALL_DIR to PATH in .bashrc"
fi

echo "Installation complete!"
echo "Usage: log-analyzer /path/to/logfile.log"
echo "       log-analyzer /var/log/syslog -t syslog --severity WARNING"
echo ""
echo "Edit $CONFIG_DIR/config.json to add custom log patterns."
