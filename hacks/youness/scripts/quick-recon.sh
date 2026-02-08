#!/bin/bash
################################################################################
# Quick Reconnaissance Script for Youness Pentest
#
# Purpose: Automated reconnaissance with three modes
# Usage: ./quick-recon.sh [passive|active|full]
# Author: BBHK AI Research Team
# Date: 2025-11-20
################################################################################

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_DIR="/home/kali/bbhk/hacks/youness"
EVIDENCE_DIR="${PROJECT_DIR}/evidence_$(date +%Y%m%d_%H%M%S)"
RESOURCES_DIR="${PROJECT_DIR}/resources"

# Targets
DOMAINS_IHGROUP=("test.ihgroup.to" "prod.ihgroup.to" "dev.ihgroup.to")
DOMAINS_HPCH=("dev.hpch.ch" "test.hpch.ch" "prod.hpch.ch")
IP_IHGROUP="136.110.148.157"
IP_HPCH="34.8.134.55"

# Tool check flags
TOOLS_OK=true

################################################################################
# Helper Functions
################################################################################

print_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║     Youness Pentest - Quick Reconnaissance Script     ║"
    echo "║                  BBHK Research Team                   ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

log_section() {
    echo -e "\n${BLUE}═══ $1 ═══${NC}\n"
}

check_tools() {
    log_section "Checking Required Tools"

    local required_tools=("dig" "subfinder" "httpx" "wafw00f" "nmap" "nuclei" "whatweb" "curl")
    local missing_tools=()

    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log_info "$tool: Installed ✓"
        else
            log_error "$tool: Missing ✗"
            missing_tools+=("$tool")
            TOOLS_OK=false
        fi
    done

    if [ "$TOOLS_OK" = false ]; then
        log_error "Missing tools: ${missing_tools[*]}"
        log_warn "Install missing tools before proceeding"
        return 1
    fi

    log_info "All required tools are installed"
    return 0
}

create_directories() {
    log_info "Creating evidence directory: $EVIDENCE_DIR"
    mkdir -p "$EVIDENCE_DIR"/{passive,active,screenshots,scan_results}
    mkdir -p "$RESOURCES_DIR"
    log_info "Evidence directory created successfully"
}

confirm_authorization() {
    log_section "Authorization Confirmation"
    echo -e "${YELLOW}⚠️  IMPORTANT: This script will perform security testing${NC}"
    echo -e "${YELLOW}   Target: Youness Infrastructure (ihgroup.to, hpch.ch)${NC}"
    echo -e "${YELLOW}   Authorization: Required before proceeding${NC}\n"

    read -p "Do you have written authorization to test these targets? (yes/no): " auth

    if [[ "$auth" != "yes" ]]; then
        log_error "Authorization not confirmed. Exiting."
        exit 1
    fi

    log_info "Authorization confirmed. Proceeding with reconnaissance."
}

show_usage() {
    cat << EOF
Usage: $0 [MODE]

MODES:
  passive   - Passive reconnaissance only (ZERO detection risk)
              DNS, subdomains, SSL, tech fingerprinting
              Duration: ~30-60 minutes

  active    - Active reconnaissance (LOW detection risk)
              WAF detection, port scanning, service enumeration
              Duration: ~2-3 hours
              Requires: passive mode completion

  full      - Complete reconnaissance (MODERATE detection risk)
              Passive + Active + Initial vulnerability scanning
              Duration: ~4-5 hours
              Requires: Authorization confirmation

EXAMPLES:
  $0 passive    # Start with passive recon
  $0 active     # Run active scans (after passive)
  $0 full       # Complete automated recon

OUTPUT:
  Results saved to: $EVIDENCE_DIR/

EOF
    exit 1
}

################################################################################
# Passive Reconnaissance Functions
################################################################################

dns_enumeration() {
    log_section "DNS Enumeration"

    local dns_dir="$EVIDENCE_DIR/passive/dns"
    mkdir -p "$dns_dir"

    # ihgroup.to
    log_info "Enumerating ihgroup.to..."
    for domain in "${DOMAINS_IHGROUP[@]}"; do
        log_info "  Querying $domain"
        dig "$domain" ANY +noall +answer > "$dns_dir/${domain}_ANY.txt" 2>&1 || true
        dig "$domain" A +short > "$dns_dir/${domain}_A.txt" 2>&1 || true
    done

    # hpch.ch
    log_info "Enumerating hpch.ch..."
    for domain in "${DOMAINS_HPCH[@]}"; do
        log_info "  Querying $domain"
        dig "$domain" ANY +noall +answer > "$dns_dir/${domain}_ANY.txt" 2>&1 || true
        dig "$domain" A +short > "$dns_dir/${domain}_A.txt" 2>&1 || true
    done

    # Name servers
    log_info "Querying name servers..."
    dig ihgroup.to NS +short > "$dns_dir/ihgroup_nameservers.txt" 2>&1 || true
    dig hpch.ch NS +short > "$dns_dir/hpch_nameservers.txt" 2>&1 || true

    log_info "DNS enumeration complete"
}

subdomain_discovery() {
    log_section "Subdomain Discovery (Passive)"

    local subdomain_dir="$EVIDENCE_DIR/passive/subdomains"
    mkdir -p "$subdomain_dir"

    log_info "Discovering subdomains for ihgroup.to..."
    subfinder -d ihgroup.to -silent -o "$subdomain_dir/subdomains_ihgroup.txt" || log_warn "Subfinder failed for ihgroup.to"

    log_info "Discovering subdomains for hpch.ch..."
    subfinder -d hpch.ch -silent -o "$subdomain_dir/subdomains_hpch.txt" || log_warn "Subfinder failed for hpch.ch"

    # Count results
    local count_ihgroup=$(wc -l < "$subdomain_dir/subdomains_ihgroup.txt" 2>/dev/null || echo "0")
    local count_hpch=$(wc -l < "$subdomain_dir/subdomains_hpch.txt" 2>/dev/null || echo "0")

    log_info "Found $count_ihgroup subdomains for ihgroup.to"
    log_info "Found $count_hpch subdomains for hpch.ch"

    # Combine all subdomains
    cat "$subdomain_dir/subdomains_ihgroup.txt" "$subdomain_dir/subdomains_hpch.txt" > "$RESOURCES_DIR/all_subdomains.txt" 2>/dev/null || true
}

ssl_analysis() {
    log_section "SSL/TLS Certificate Analysis"

    local ssl_dir="$EVIDENCE_DIR/passive/ssl"
    mkdir -p "$ssl_dir"

    log_info "Analyzing SSL certificates..."

    for domain in "${DOMAINS_IHGROUP[@]}" "${DOMAINS_HPCH[@]}"; do
        log_info "  Checking $domain"

        # Get certificate chain
        echo | openssl s_client -connect "$domain:443" -showcerts 2>&1 | \
            tee "$ssl_dir/${domain}_cert_chain.txt" | \
            openssl x509 -text -noout > "$ssl_dir/${domain}_cert_details.txt" 2>&1 || true

        # Extract SANs
        echo | openssl s_client -connect "$domain:443" 2>&1 | \
            openssl x509 -text | \
            grep -A1 "Subject Alternative Name" > "$ssl_dir/${domain}_sans.txt" 2>&1 || true
    done

    log_info "SSL certificate analysis complete"
}

technology_fingerprinting() {
    log_section "Technology Fingerprinting"

    local tech_dir="$EVIDENCE_DIR/passive/technology"
    mkdir -p "$tech_dir"

    log_info "Fingerprinting web technologies..."

    for domain in "${DOMAINS_IHGROUP[@]}" "${DOMAINS_HPCH[@]}"; do
        log_info "  Scanning https://$domain"
        whatweb -v "https://$domain" > "$tech_dir/${domain}_whatweb.txt" 2>&1 || log_warn "whatweb failed for $domain"
    done

    log_info "Technology fingerprinting complete"
}

http_header_analysis() {
    log_section "HTTP Header Analysis"

    local header_dir="$EVIDENCE_DIR/passive/headers"
    mkdir -p "$header_dir"

    log_info "Capturing HTTP headers..."

    for domain in "${DOMAINS_IHGROUP[@]}" "${DOMAINS_HPCH[@]}"; do
        log_info "  Getting headers from https://$domain"
        curl -I "https://$domain" > "$header_dir/${domain}_headers.txt" 2>&1 || log_warn "curl failed for $domain"
    done

    # Check for GCP indicators
    log_info "Checking for GCP fingerprints..."
    grep -iE "(google|gcp|cloud-trace|goog)" "$header_dir"/*.txt > "$header_dir/gcp_indicators.txt" 2>&1 || true

    log_info "HTTP header analysis complete"
}

################################################################################
# Active Reconnaissance Functions
################################################################################

waf_detection() {
    log_section "WAF/IDS Detection"

    local waf_dir="$EVIDENCE_DIR/active/waf_detection"
    mkdir -p "$waf_dir"

    log_info "Detecting WAF/IDS with wafw00f..."

    for domain in "${DOMAINS_IHGROUP[@]}" "${DOMAINS_HPCH[@]}"; do
        log_info "  Testing https://$domain"
        wafw00f -v -a "https://$domain" -o "$waf_dir/${domain}_waf.json" -f json 2>&1 | \
            tee "$waf_dir/${domain}_waf.txt" || log_warn "wafw00f failed for $domain"
    done

    # Check if Cloud Armor detected
    if grep -qi "cloud armor\|google" "$waf_dir"/*.txt 2>/dev/null; then
        log_warn "Google Cloud Armor likely detected - Use conservative scan timing (-T2)"
        echo "CLOUD_ARMOR_DETECTED" > "$waf_dir/scan_timing_recommendation.txt"
        echo "Recommended nmap timing: -T2 (Polite)" >> "$waf_dir/scan_timing_recommendation.txt"
        echo "Recommended rate limit: 5-10 req/sec" >> "$waf_dir/scan_timing_recommendation.txt"
    else
        log_info "No WAF detected - Normal scan timing (-T3) acceptable"
        echo "NO_WAF_DETECTED" > "$waf_dir/scan_timing_recommendation.txt"
        echo "Recommended nmap timing: -T3 (Default)" >> "$waf_dir/scan_timing_recommendation.txt"
        echo "Recommended rate limit: 10-20 req/sec" >> "$waf_dir/scan_timing_recommendation.txt"
    fi

    log_info "WAF detection complete"
}

port_scanning() {
    log_section "Port Scanning"

    local scan_dir="$EVIDENCE_DIR/active/port_scans"
    mkdir -p "$scan_dir"

    # Determine timing based on WAF detection
    local timing="-T3"
    if [ -f "$EVIDENCE_DIR/active/waf_detection/scan_timing_recommendation.txt" ]; then
        if grep -q "CLOUD_ARMOR_DETECTED" "$EVIDENCE_DIR/active/waf_detection/scan_timing_recommendation.txt"; then
            timing="-T2"
            log_warn "Using conservative timing (-T2) due to WAF detection"
        fi
    fi

    log_info "Scanning $IP_IHGROUP (ihgroup.to) with timing $timing"
    nmap $timing -Pn --top-ports 1000 -oA "$scan_dir/nmap_ihgroup_initial" "$IP_IHGROUP" || log_warn "nmap scan failed for $IP_IHGROUP"

    log_info "Scanning $IP_HPCH (hpch.ch) with timing $timing"
    nmap $timing -Pn --top-ports 1000 -oA "$scan_dir/nmap_hpch_initial" "$IP_HPCH" || log_warn "nmap scan failed for $IP_HPCH"

    log_info "Port scanning complete"
}

service_enumeration() {
    log_section "Service Version Detection"

    local scan_dir="$EVIDENCE_DIR/active/service_enum"
    mkdir -p "$scan_dir"

    # Determine timing
    local timing="-T3"
    if [ -f "$EVIDENCE_DIR/active/waf_detection/scan_timing_recommendation.txt" ]; then
        if grep -q "CLOUD_ARMOR_DETECTED" "$EVIDENCE_DIR/active/waf_detection/scan_timing_recommendation.txt"; then
            timing="-T2"
        fi
    fi

    # Common web and database ports
    local ports="80,443,8080,8443,3000,3306,5432,27017,6379"

    log_info "Enumerating services on $IP_IHGROUP"
    nmap $timing -Pn -sV -p "$ports" -oA "$scan_dir/nmap_ihgroup_services" "$IP_IHGROUP" || log_warn "Service enum failed for $IP_IHGROUP"

    log_info "Enumerating services on $IP_HPCH"
    nmap $timing -Pn -sV -p "$ports" -oA "$scan_dir/nmap_hpch_services" "$IP_HPCH" || log_warn "Service enum failed for $IP_HPCH"

    log_info "Service enumeration complete"
}

http_probing() {
    log_section "HTTP Probing"

    local probe_dir="$EVIDENCE_DIR/active/http_probing"
    mkdir -p "$probe_dir"

    if [ ! -f "$RESOURCES_DIR/all_subdomains.txt" ]; then
        log_warn "No subdomains file found. Skipping HTTP probing."
        return
    fi

    log_info "Probing discovered HTTP services..."

    cat "$RESOURCES_DIR/all_subdomains.txt" | \
        httpx -status-code -tech-detect -title -content-length \
        -threads 10 -rate-limit 10 \
        -o "$probe_dir/httpx_results.txt" 2>&1 || log_warn "httpx probing failed"

    # Extract live URLs
    grep -E "(200|301|302|401|403)" "$probe_dir/httpx_results.txt" | \
        cut -d' ' -f1 > "$RESOURCES_DIR/live_urls.txt" 2>/dev/null || true

    local live_count=$(wc -l < "$RESOURCES_DIR/live_urls.txt" 2>/dev/null || echo "0")
    log_info "Found $live_count live HTTP services"

    log_info "HTTP probing complete"
}

################################################################################
# Full Reconnaissance (includes initial vuln scanning)
################################################################################

initial_vuln_scan() {
    log_section "Initial Vulnerability Scanning (Nuclei)"

    local vuln_dir="$EVIDENCE_DIR/scan_results/nuclei"
    mkdir -p "$vuln_dir"

    if [ ! -f "$RESOURCES_DIR/live_urls.txt" ]; then
        log_warn "No live URLs found. Skipping vulnerability scanning."
        return
    fi

    # Determine aggressiveness
    local rate_limit=10
    local delay=200
    if [ -f "$EVIDENCE_DIR/active/waf_detection/scan_timing_recommendation.txt" ]; then
        if grep -q "CLOUD_ARMOR_DETECTED" "$EVIDENCE_DIR/active/waf_detection/scan_timing_recommendation.txt"; then
            rate_limit=5
            delay=500
            log_warn "Using conservative nuclei settings due to WAF"
        fi
    fi

    log_info "Running nuclei with rate limit: $rate_limit req/sec, delay: ${delay}ms"

    nuclei -l "$RESOURCES_DIR/live_urls.txt" \
        -t ~/nuclei-templates/cves/2024/ \
        -t ~/nuclei-templates/vulnerabilities/generic/ \
        -severity critical,high \
        -rl "$rate_limit" -delay "${delay}ms" \
        -o "$vuln_dir/nuclei_results.txt" 2>&1 || log_warn "Nuclei scan completed with warnings"

    # Count findings
    local findings=$(grep -c "^\[" "$vuln_dir/nuclei_results.txt" 2>/dev/null || echo "0")
    log_info "Nuclei scan complete - $findings potential findings"

    log_info "Initial vulnerability scanning complete"
}

database_exposure_check() {
    log_section "Database Exposure Check"

    local db_dir="$EVIDENCE_DIR/scan_results/database_checks"
    mkdir -p "$db_dir"

    local timing="-T2"  # Always conservative for database checks

    log_info "Checking for exposed databases on $IP_IHGROUP"

    # MySQL
    nmap $timing -Pn -p 3306 --script mysql-info "$IP_IHGROUP" -oN "$db_dir/mysql_check_ihgroup.txt" || true

    # PostgreSQL
    nmap $timing -Pn -p 5432 --script postgresql-info "$IP_IHGROUP" -oN "$db_dir/postgresql_check_ihgroup.txt" || true

    # MongoDB
    nmap $timing -Pn -p 27017 --script mongodb-info "$IP_IHGROUP" -oN "$db_dir/mongodb_check_ihgroup.txt" || true

    log_info "Checking for exposed databases on $IP_HPCH"

    # Repeat for second IP
    nmap $timing -Pn -p 3306 --script mysql-info "$IP_HPCH" -oN "$db_dir/mysql_check_hpch.txt" || true
    nmap $timing -Pn -p 5432 --script postgresql-info "$IP_HPCH" -oN "$db_dir/postgresql_check_hpch.txt" || true
    nmap $timing -Pn -p 27017 --script mongodb-info "$IP_HPCH" -oN "$db_dir/mongodb_check_hpch.txt" || true

    # Check results
    if grep -qi "open" "$db_dir"/*.txt 2>/dev/null; then
        log_warn "⚠️  POTENTIAL DATABASE EXPOSURE DETECTED!"
        log_warn "Review: $db_dir/"
    else
        log_info "No publicly accessible databases detected"
    fi

    log_info "Database exposure check complete"
}

################################################################################
# Summary and Reporting
################################################################################

generate_summary() {
    log_section "Generating Reconnaissance Summary"

    local summary_file="$EVIDENCE_DIR/RECONNAISSANCE_SUMMARY.txt"

    cat > "$summary_file" << EOF
================================================================================
        Youness Pentest - Reconnaissance Summary
================================================================================

Date: $(date)
Mode: $MODE
Evidence Directory: $EVIDENCE_DIR

--------------------------------------------------------------------------------
TARGETS
--------------------------------------------------------------------------------
ihgroup.to Domains: ${DOMAINS_IHGROUP[*]}
hpch.ch Domains:    ${DOMAINS_HPCH[*]}
IP Addresses:       $IP_IHGROUP, $IP_HPCH

--------------------------------------------------------------------------------
PASSIVE RECONNAISSANCE RESULTS
--------------------------------------------------------------------------------
EOF

    if [ -d "$EVIDENCE_DIR/passive/subdomains" ]; then
        local count_ihgroup=$(wc -l < "$EVIDENCE_DIR/passive/subdomains/subdomains_ihgroup.txt" 2>/dev/null || echo "0")
        local count_hpch=$(wc -l < "$EVIDENCE_DIR/passive/subdomains/subdomains_hpch.txt" 2>/dev/null || echo "0")
        echo "Subdomains discovered (ihgroup.to): $count_ihgroup" >> "$summary_file"
        echo "Subdomains discovered (hpch.ch):    $count_hpch" >> "$summary_file"
    fi

    if [ -f "$EVIDENCE_DIR/passive/headers/gcp_indicators.txt" ]; then
        local gcp_count=$(wc -l < "$EVIDENCE_DIR/passive/headers/gcp_indicators.txt" 2>/dev/null || echo "0")
        echo "GCP fingerprints detected:          $gcp_count indicators" >> "$summary_file"
    fi

    if [ "$MODE" != "passive" ]; then
        cat >> "$summary_file" << EOF

--------------------------------------------------------------------------------
ACTIVE RECONNAISSANCE RESULTS
--------------------------------------------------------------------------------
EOF

        if [ -f "$EVIDENCE_DIR/active/waf_detection/scan_timing_recommendation.txt" ]; then
            echo "WAF Detection:" >> "$summary_file"
            cat "$EVIDENCE_DIR/active/waf_detection/scan_timing_recommendation.txt" >> "$summary_file"
        fi

        if [ -f "$RESOURCES_DIR/live_urls.txt" ]; then
            local live_count=$(wc -l < "$RESOURCES_DIR/live_urls.txt")
            echo -e "\nLive HTTP services:                 $live_count" >> "$summary_file"
        fi

        if [ -d "$EVIDENCE_DIR/active/port_scans" ]; then
            echo -e "\nPort scan results available in:     $EVIDENCE_DIR/active/port_scans/" >> "$summary_file"
        fi
    fi

    if [ "$MODE" == "full" ]; then
        cat >> "$summary_file" << EOF

--------------------------------------------------------------------------------
VULNERABILITY SCAN RESULTS
--------------------------------------------------------------------------------
EOF

        if [ -f "$EVIDENCE_DIR/scan_results/nuclei/nuclei_results.txt" ]; then
            local findings=$(grep -c "^\[" "$EVIDENCE_DIR/scan_results/nuclei/nuclei_results.txt" 2>/dev/null || echo "0")
            echo "Nuclei findings:                    $findings" >> "$summary_file"
        fi

        if [ -d "$EVIDENCE_DIR/scan_results/database_checks" ]; then
            if grep -qi "open" "$EVIDENCE_DIR/scan_results/database_checks"/*.txt 2>/dev/null; then
                echo "⚠️  Database exposure:               POTENTIAL EXPOSURE DETECTED" >> "$summary_file"
            else
                echo "Database exposure:                  None detected" >> "$summary_file"
            fi
        fi
    fi

    cat >> "$summary_file" << EOF

--------------------------------------------------------------------------------
NEXT STEPS
--------------------------------------------------------------------------------
1. Review all evidence in: $EVIDENCE_DIR/
2. Update RECONNAISSANCE.md with findings
3. Run T.K.V.F. verification: /home/kali/bbhk/verify-tech.sh
4. Proceed to manual vulnerability testing
5. Store findings in BBHK: /home/kali/bbhk/vuln store-quick

--------------------------------------------------------------------------------
SAFETY REMINDERS
--------------------------------------------------------------------------------
- All testing is authorized for these specific targets
- STOP immediately if 403/429 errors occur repeatedly
- Contact target owner (Youness) if issues arise
- Document all findings with timestamps and evidence

================================================================================
                        Reconnaissance Complete
================================================================================
EOF

    log_info "Summary generated: $summary_file"

    # Display summary
    cat "$summary_file"
}

################################################################################
# Main Execution Flow
################################################################################

main() {
    print_banner

    # Parse mode
    MODE="${1:-}"

    if [ -z "$MODE" ]; then
        show_usage
    fi

    case "$MODE" in
        passive)
            log_info "Mode: PASSIVE RECONNAISSANCE"
            ;;
        active)
            log_info "Mode: ACTIVE RECONNAISSANCE"
            ;;
        full)
            log_info "Mode: FULL RECONNAISSANCE"
            ;;
        *)
            log_error "Invalid mode: $MODE"
            show_usage
            ;;
    esac

    # Pre-flight checks
    check_tools || exit 1
    create_directories
    confirm_authorization

    # Execute based on mode
    if [ "$MODE" == "passive" ] || [ "$MODE" == "active" ] || [ "$MODE" == "full" ]; then
        dns_enumeration
        subdomain_discovery
        ssl_analysis
        technology_fingerprinting
        http_header_analysis
    fi

    if [ "$MODE" == "active" ] || [ "$MODE" == "full" ]; then
        waf_detection
        port_scanning
        service_enumeration
        http_probing
    fi

    if [ "$MODE" == "full" ]; then
        database_exposure_check
        initial_vuln_scan
    fi

    # Generate summary
    generate_summary

    log_section "Reconnaissance Complete"
    log_info "All evidence saved to: $EVIDENCE_DIR/"
    log_info "Summary available: $EVIDENCE_DIR/RECONNAISSANCE_SUMMARY.txt"

    if [ "$MODE" == "passive" ]; then
        log_warn "Next step: Run './quick-recon.sh active' for active reconnaissance"
    elif [ "$MODE" == "active" ]; then
        log_warn "Next step: Run './quick-recon.sh full' OR proceed with manual testing"
    else
        log_warn "Next step: Review findings and proceed with manual vulnerability testing"
    fi
}

# Execute main function
main "$@"
