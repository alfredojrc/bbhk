#!/bin/bash
# Install Additional Bug Bounty Tools
# Essential tools for comprehensive reconnaissance and vulnerability discovery

echo "================================================"
echo "Installing Additional Bug Bounty Tools"
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create tools directory
TOOLS_DIR="/home/kali/bbhk/tools"
mkdir -p "$TOOLS_DIR"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Go if not present
if ! command_exists go; then
    echo -e "${YELLOW}Installing Go...${NC}"
    sudo apt update
    sudo apt install -y golang-go
fi

# Update PATH for Go binaries
export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin

# 1. Install Subfinder (ProjectDiscovery)
echo -e "${GREEN}[1/5] Installing Subfinder...${NC}"
if command_exists subfinder; then
    echo "Subfinder already installed, updating..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
else
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
fi

# 2. Install Katana (ProjectDiscovery)
echo -e "${GREEN}[2/5] Installing Katana...${NC}"
if command_exists katana; then
    echo "Katana already installed, updating..."
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
else
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
fi

# 3. Install gau (GetAllUrls)
echo -e "${GREEN}[3/5] Installing gau...${NC}"
if command_exists gau; then
    echo "gau already installed, updating..."
    go install -v github.com/lc/gau/v2/cmd/gau@latest
else
    go install -v github.com/lc/gau/v2/cmd/gau@latest
fi

# 4. Install waybackurls
echo -e "${GREEN}[4/5] Installing waybackurls...${NC}"
if command_exists waybackurls; then
    echo "waybackurls already installed, updating..."
    go install -v github.com/tomnomnom/waybackurls@latest
else
    go install -v github.com/tomnomnom/waybackurls@latest
fi

# 5. Install BBOT (via pip)
echo -e "${GREEN}[5/5] Installing BBOT...${NC}"
if command_exists bbot; then
    echo "BBOT already installed, updating..."
    pipx upgrade bbot
else
    pipx install bbot
fi

# Additional useful tools for bug bounty
echo -e "${YELLOW}Installing additional reconnaissance tools...${NC}"

# anew - Append lines to file, only if they don't already exist
go install -v github.com/tomnomnom/anew@latest

# qsreplace - Query string replacer
go install -v github.com/tomnomnom/qsreplace@latest

# unfurl - Extract and decode URLs
go install -v github.com/tomnomnom/unfurl@latest

# httprobe - Probe for working HTTP/HTTPS servers
go install -v github.com/tomnomnom/httprobe@latest

# meg - Fetch many paths for many hosts
go install -v github.com/tomnomnom/meg@latest

# gf - Pattern matching for common parameters
go install -v github.com/tomnomnom/gf@latest

# Create configuration files
echo -e "${YELLOW}Creating configuration files...${NC}"

# Subfinder provider config
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/provider-config.yaml << 'EOF'
# Subfinder Configuration
# Add your API keys here for better results
# Free API keys available from:
# - https://censys.io/register
# - https://shodan.io/register
# - https://virustotal.com/gui/sign-in
# - https://securitytrails.com/

# Example (uncomment and add your keys):
# censys:
#   - <API_KEY>:<SECRET>
# shodan:
#   - <API_KEY>
# virustotal:
#   - <API_KEY>
# securitytrails:
#   - <API_KEY>
EOF

# gf patterns setup
if [ ! -d ~/.gf ]; then
    echo "Setting up gf patterns..."
    git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
fi

# Update PATH in .bashrc if not already present
if ! grep -q "export PATH=\$PATH:\$HOME/go/bin" ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# Go binaries path for bug bounty tools" >> ~/.bashrc
    echo "export PATH=\$PATH:\$HOME/go/bin:/usr/local/go/bin" >> ~/.bashrc
fi

# Verify installations
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}Installation Complete! Verifying tools...${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""

# Check each tool
tools=("subfinder" "katana" "gau" "waybackurls" "bbot" "anew" "qsreplace" "unfurl" "httprobe" "meg" "gf")
for tool in "${tools[@]}"; do
    if command_exists "$tool"; then
        version=$($tool -version 2>/dev/null || $tool --version 2>/dev/null || echo "installed")
        echo -e "${GREEN}✓${NC} $tool: $version"
    else
        echo -e "${RED}✗${NC} $tool: not found"
    fi
done

echo ""
echo -e "${YELLOW}Tool Locations:${NC}"
echo "Go tools: $HOME/go/bin/"
echo "BBOT: $(which bbot)"

echo ""
echo -e "${YELLOW}Configuration Files:${NC}"
echo "Subfinder: ~/.config/subfinder/provider-config.yaml"
echo "gf patterns: ~/.gf/"

echo ""
echo -e "${GREEN}Quick Usage Examples:${NC}"
echo "# Subdomain enumeration"
echo "subfinder -d target.com -all -recursive"
echo ""
echo "# JavaScript crawling"
echo "katana -u https://target.com -jc -d 5"
echo ""
echo "# Historical URLs"
echo "echo target.com | gau --blacklist png,jpg,gif --o urls.txt"
echo "echo target.com | waybackurls | anew urls.txt"
echo ""
echo "# BBOT comprehensive scan"
echo "bbot -t target.com -f subdomain-enum web-basic"
echo ""
echo -e "${YELLOW}Remember to source ~/.bashrc or restart terminal for PATH updates${NC}"