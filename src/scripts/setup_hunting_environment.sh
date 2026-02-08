#!/bin/bash
# BBHK Environment Setup Script
# Prepares Kali Linux for personal bug bounty hunting

set -e

echo "🎯 BBHK Personal Hunting Environment Setup"
echo "=========================================="

# Update system
echo "[1/8] Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install essential tools
echo "[2/8] Installing hunting tools..."
sudo apt install -y \
    python3 python3-pip \
    curl wget git \
    nmap masscan \
    gobuster dirb \
    sqlmap \
    nikto \
    whatweb \
    sublist3r \
    amass \
    subfinder \
    nuclei \
    httpx \
    jq \
    burpsuite

# Install Python requirements
echo "[3/8] Installing Python dependencies..."
pip3 install --user \
    requests \
    aiohttp \
    beautifulsoup4 \
    pyyaml \
    dnspython \
    shodan \
    censys

# Create wordlist directory
echo "[4/8] Setting up wordlists..."
mkdir -p /home/kali/bbhk/data/wordlists

# Download common wordlists
cd /home/kali/bbhk/data/wordlists

# SecLists (if not already present)
if [ ! -d "SecLists" ]; then
    echo "Downloading SecLists..."
    git clone https://github.com/danielmiessler/SecLists.git
fi

# Create symbolic links to commonly used lists
ln -sf SecLists/Discovery/Web-Content/common.txt common-dirs.txt
ln -sf SecLists/Discovery/DNS/subdomains-top1million-5000.txt subdomains-top5k.txt
ln -sf SecLists/Usernames/top-usernames-shortlist.txt usernames.txt

# Set up Burp Suite configuration
echo "[5/8] Configuring Burp Suite..."
mkdir -p /home/kali/.java/.userPrefs/burp
cat > /home/kali/.java/.userPrefs/burp/prefs.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE map SYSTEM "http://java.sun.com/dtd/preferences.dtd">
<map MAP_XML_VERSION="1.0">
  <entry key="free_suite_form_feeds_status" value="2"/>
  <entry key="suite_settings_theme" value="dark"/>
  <entry key="suite_settings_throttling_enabled" value="true"/>
  <entry key="suite_settings_throttling_delay" value="5000"/>
</map>
EOF

# Set up log directories
echo "[6/8] Creating log structure..."
mkdir -p /home/kali/bbhk/logs/{recon,scans,targets,findings}
touch /home/kali/bbhk/logs/daily_progress.log
touch /home/kali/bbhk/logs/bbhk_activity.log

# Set up initial data files
echo "[7/8] Initializing data files..."
echo '{"hackerone": {}, "bugcrowd": {}, "intigriti": {}}' > /home/kali/bbhk/data/known_programs.json

# Set up Git (if not already configured)
echo "[8/8] Finalizing setup..."
if [ ! -f /home/kali/.gitconfig ]; then
    echo "Setting up Git configuration..."
    read -p "Enter your Git username: " git_username
    read -p "Enter your Git email: " git_email
    git config --global user.name "$git_username"
    git config --global user.email "$git_email"
fi

# Make scripts executable
chmod +x /home/kali/bbhk/src/tools/*.py
chmod +x /home/kali/bbhk/src/scripts/*.sh

# Create desktop shortcuts
echo "[Desktop] Creating hunting shortcuts..."
mkdir -p /home/kali/Desktop

cat > /home/kali/Desktop/BBHK-Terminal.desktop << EOF
[Desktop Entry]
Version=1.0
Name=BBHK Terminal
Comment=Bug Bounty Hunting Terminal
Exec=gnome-terminal --working-directory=/home/kali/bbhk --title="BBHK Hunting"
Icon=utilities-terminal
Terminal=false
Type=Application
Categories=Development;Security;
EOF

chmod +x /home/kali/Desktop/BBHK-Terminal.desktop

# Final summary
echo ""
echo "✅ BBHK Environment Setup Complete!"
echo ""
echo "🎯 Next Steps:"
echo "1. Review your hunting strategy: cat docs/personal-hunting-strategy-analysis.md"
echo "2. Configure target programs: nano configs/programs.json"
echo "3. Start hunting: python3 src/frameworks/bbhk_core.py"
echo "4. Read the quick start guide: cat QUICKSTART.md"
echo ""
echo "💰 Target: First bug within 14 days!"
echo "📊 Goal: $96K-600K annual income from bug bounties"
echo ""
echo "🚀 Happy Hunting!"