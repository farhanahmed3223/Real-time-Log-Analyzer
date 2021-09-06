#!/bin/bash
echo "Installing Real-time Log Analyzer..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Create installation directory
INSTALL_DIR="$HOME/.local/bin"
CONFIG_DIR="$HOME/.config/log-analyzer"

mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"

# Copy the main script
cp log_analyzer.py "$INSTALL_DIR/log-analyzer"
chmod +x "$INSTALL_DIR/log-analyzer"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$HOME/.bashrc"
    echo "Added $INSTALL_DIR to PATH in .bashrc"
fi

echo "Installation complete!"
echo "Usage: log-analyzer /path/to/logfile.log"
echo "       log-analyzer /var/log/syslog -t syslog --severity WARNING"
