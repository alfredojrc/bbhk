#!/bin/bash

# Automated Bug Bounty Reconnaissance Workflow
# Uses ProjectDiscovery tools for comprehensive asset discovery and vulnerability scanning
# Author: BBHK Project
# Date: 2025-08-20

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }

# Check if domain is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain> [output_dir]"
    echo "Example: $0 example.com ./recon_results"
    exit 1
fi

# Variables
DOMAIN=$1
OUTPUT_DIR=${2:-"./recon_$DOMAIN_$(date +%Y%m%d_%H%M%S)"}
TOOLS_PATH="$HOME/go/bin"

# Add tools to PATH
export PATH=$PATH:$TOOLS_PATH

# Create output directory structure
mkdir -p "$OUTPUT_DIR"/{subdomains,ports,http,vulnerabilities,screenshots,js_files,api_endpoints}
cd "$OUTPUT_DIR"

print_info "Starting reconnaissance for: $DOMAIN"
print_info "Output directory: $OUTPUT_DIR"

# ====================
# PHASE 1: Asset Discovery
# ====================
print_info "Phase 1: Asset Discovery"

# 1.1 ASN Discovery
print_success "Finding ASN information..."
asnmap -org "$DOMAIN" -json 2>/dev/null | tee asn_info.json | jq -r '.[] | .asn' > asns.txt || true

# 1.2 Subdomain Enumeration
print_success "Enumerating subdomains..."
subfinder -d "$DOMAIN" -all -recursive -o subdomains/subfinder.txt 2>/dev/null

# Additional subdomain sources
if command -v assetfinder &> /dev/null; then
    assetfinder --subs-only "$DOMAIN" 2>/dev/null >> subdomains/assetfinder.txt
fi

# Combine and deduplicate subdomains
cat subdomains/*.txt 2>/dev/null | sort -u > subdomains/all_subdomains.txt
SUBDOMAIN_COUNT=$(wc -l < subdomains/all_subdomains.txt)
print_success "Found $SUBDOMAIN_COUNT unique subdomains"

# 1.3 DNS Resolution
print_success "Resolving DNS records..."
dnsx -l subdomains/all_subdomains.txt -a -aaaa -cname -mx -txt -resp -json -o dns_records.json 2>/dev/null

# Extract live hosts
dnsx -l subdomains/all_subdomains.txt -silent > live_hosts.txt 2>/dev/null

# ====================
# PHASE 2: Service Discovery
# ====================
print_info "Phase 2: Service Discovery"

# 2.1 Port Scanning
print_success "Scanning for open ports..."
naabu -list live_hosts.txt -top-ports 1000 -json -o ports/port_scan.json 2>/dev/null

# Extract host:port format
cat ports/port_scan.json | jq -r '"\(.host):\(.port)"' 2>/dev/null > hosts_with_ports.txt

# 2.2 HTTP Probing
print_success "Probing HTTP services..."
httpx -list hosts_with_ports.txt \
    -sc -cl -ct -rt -title -web-server -tech-detect -ip \
    -json -o http/httpx_results.json 2>/dev/null

# Extract live HTTP services
cat http/httpx_results.json | jq -r '.url' 2>/dev/null > live_http_services.txt

# 2.3 TLS Information
print_success "Gathering TLS information..."
tlsx -l live_http_services.txt -san -cn -so -expired -json -o tls_info.json 2>/dev/null || true

# ====================
# PHASE 3: Content Discovery
# ====================
print_info "Phase 3: Content Discovery"

# 3.1 Web Crawling
print_success "Crawling websites for endpoints..."
katana -list live_http_services.txt -d 3 -jc -silent -o endpoints.txt 2>/dev/null

# Filter for interesting endpoints
grep -E '\.(js|json|xml|config|env|bak|backup|old|log|sql|db|git|svn)' endpoints.txt > interesting_files.txt || true

# 3.2 API Endpoint Discovery
grep -E '/(api|v[0-9]|graphql|rest|swagger|openapi)' endpoints.txt > api_endpoints/potential_apis.txt || true

# 3.3 JavaScript File Analysis
grep '\.js$' endpoints.txt > js_files/js_urls.txt || true

# ====================
# PHASE 4: Vulnerability Scanning
# ====================
print_info "Phase 4: Vulnerability Scanning"

# 4.1 Nuclei Scanning - Critical & High
print_success "Running Nuclei scans (Critical & High severity)..."
nuclei -list live_http_services.txt \
    -severity critical,high \
    -json -o vulnerabilities/nuclei_critical_high.json 2>/dev/null

# 4.2 Nuclei Scanning - Exposures
print_success "Checking for exposures..."
nuclei -list live_http_services.txt \
    -t exposures/ \
    -json -o vulnerabilities/nuclei_exposures.json 2>/dev/null

# 4.3 Nuclei Scanning - Misconfigurations
print_success "Checking for misconfigurations..."
nuclei -list live_http_services.txt \
    -t misconfiguration/ \
    -json -o vulnerabilities/nuclei_misconfig.json 2>/dev/null

# 4.4 Subdomain Takeover Check
print_success "Checking for subdomain takeovers..."
nuclei -list subdomains/all_subdomains.txt \
    -t takeovers/ \
    -json -o vulnerabilities/subdomain_takeovers.json 2>/dev/null

# ====================
# PHASE 5: Reporting
# ====================
print_info "Phase 5: Generating Reports"

# Create summary report
cat > RECONNAISSANCE_REPORT.md << EOF
# Reconnaissance Report for $DOMAIN
Generated: $(date)

## Executive Summary
- Total Subdomains Found: $SUBDOMAIN_COUNT
- Live Hosts: $(wc -l < live_hosts.txt)
- HTTP Services: $(wc -l < live_http_services.txt)
- Endpoints Discovered: $(wc -l < endpoints.txt 2>/dev/null || echo 0)

## Findings

### Critical/High Vulnerabilities
\`\`\`
$(cat vulnerabilities/nuclei_critical_high.json 2>/dev/null | jq -r '"\(.info.severity): \(.info.name) - \(.matched)"' | sort -u || echo "None found")
\`\`\`

### Exposures
\`\`\`
$(cat vulnerabilities/nuclei_exposures.json 2>/dev/null | jq -r '"\(.info.name) - \(.matched)"' | head -10 || echo "None found")
\`\`\`

### Interesting Files
\`\`\`
$(head -20 interesting_files.txt 2>/dev/null || echo "None found")
\`\`\`

### API Endpoints
\`\`\`
$(head -20 api_endpoints/potential_apis.txt 2>/dev/null || echo "None found")
\`\`\`

## File Locations
- Subdomains: subdomains/all_subdomains.txt
- Live Hosts: live_hosts.txt
- HTTP Services: live_http_services.txt
- Vulnerabilities: vulnerabilities/
- Endpoints: endpoints.txt

## Next Steps
1. Review critical/high vulnerabilities for exploitation
2. Investigate exposed sensitive files
3. Test API endpoints for authorization issues
4. Manual testing of interesting parameters
5. Deep dive into JavaScript files for secrets

EOF

print_success "Report generated: RECONNAISSANCE_REPORT.md"

# ====================
# PHASE 6: Optional Advanced Scans
# ====================
print_info "Phase 6: Advanced Analysis (Optional)"

# 6.1 Screenshot capture (if enabled)
if command -v gowitness &> /dev/null; then
    print_success "Taking screenshots..."
    gowitness file -f live_http_services.txt -P screenshots/ 2>/dev/null || true
fi

# 6.2 Parameter discovery
if [ -f endpoints.txt ]; then
    print_success "Extracting parameters..."
    cat endpoints.txt | grep -oP '\?[^#]*' | sed 's/&/\n/g' | grep -oP '[^?=]+(?==)' | sort -u > parameters.txt
fi

# Final summary
echo ""
print_success "Reconnaissance complete!"
print_info "Results saved to: $OUTPUT_DIR"
print_info "Review RECONNAISSANCE_REPORT.md for summary"

# Quick stats
echo ""
echo "Quick Statistics:"
echo "=================="
echo "Subdomains: $(wc -l < subdomains/all_subdomains.txt)"
echo "Live Hosts: $(wc -l < live_hosts.txt)"
echo "HTTP Services: $(wc -l < live_http_services.txt)"
echo "Endpoints: $(wc -l < endpoints.txt 2>/dev/null || echo 0)"
echo "Critical Vulns: $(cat vulnerabilities/nuclei_critical_high.json 2>/dev/null | jq -r '.info.severity' | grep -c critical || echo 0)"
echo "High Vulns: $(cat vulnerabilities/nuclei_critical_high.json 2>/dev/null | jq -r '.info.severity' | grep -c high || echo 0)"

exit 0