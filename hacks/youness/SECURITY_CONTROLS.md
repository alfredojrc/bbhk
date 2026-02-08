# Security Controls Documentation - Youness Pentest

**Target**: ihgroup.to, hpch.ch infrastructure
**Date**: 2025-11-20
**Phase**: Passive Reconnaissance
**Status**: ✅ Security controls identified and documented

---

## Executive Summary

### Discovered Security Controls
1. ✅ **Google Cloud Armor WAF** - Enterprise-grade, actively filtering
2. ✅ **Google Cloud Firewall** - Inferred from GCP infrastructure
3. ✅ **HSTS** - HTTP Strict Transport Security with includeSubDomains
4. ✅ **Modern TLS** - Google Trust Services certificates, HTTP/2+HTTP/3
5. ⚠️ **Rate Limiting** - Expected (not yet tested)
6. ✅ **Google Frontend** - Load balancing and DDoS protection

### Overall Security Posture
**Rating**: 🟢 **STRONG** - Enterprise-grade security stack with active WAF

**Key Strengths**:
- Professional security infrastructure (Google Cloud Platform)
- Active behavioral WAF filtering (Cloud Armor)
- Strong SSL/TLS configuration
- Modern protocol support (HTTP/2, HTTP/3)

**Testing Implications**:
- Must use WAF-aware testing techniques
- Conservative scan timing required
- Browser-like User-Agent headers mandatory
- Rate limiting essential to avoid blocking

---

## 1. Web Application Firewall (WAF)

### Google Cloud Armor
**Detection Method**: wafw00f behavioral analysis
**Confidence**: 🟢 **HIGH** (confirmed via multiple tests)
**Status**: ✅ **ACTIVE** - Currently filtering requests

#### Technical Details
- **Product**: Google Cloud Armor
- **Provider**: Google Cloud Platform
- **Type**: Cloud-native WAF with machine learning
- **Detection Behavior**: Returns 403 for non-browser User-Agent requests
- **Response Time**: Immediate (< 1 second for blocking)

#### Observed Behavior

**Test 1: Normal Browser Request**
```bash
curl -I https://test.ihgroup.to
# Result: HTTP/2 200 OK
```

**Test 2: Scanner User-Agent**
```bash
curl -I -A "Scanner" https://test.ihgroup.to
# Result: HTTP/2 403 Forbidden
```

**Test 3: WAF Detection Tool**
```bash
wafw00f -a https://test.ihgroup.to
# Result: "Google Cloud Armor (Google Cloud)" detected
# Detection method: Response code changes (200 → 403)
# Number of requests: 4
```

#### WAF Capabilities (Google Cloud Armor)

**Known Features**:
- **Signature-based detection**: OWASP Top 10 patterns
- **Behavioral analysis**: Machine learning anomaly detection
- **User-Agent filtering**: Active inspection and blocking
- **Rate limiting**: Configurable per-IP and per-endpoint
- **Geo-blocking**: Can restrict by geographic location
- **Custom rules**: Allows custom security policy definitions
- **DDoS protection**: Layer 7 DDoS mitigation
- **IP allowlisting/blocklisting**: Granular access control

**Protection Level**: ⚠️ **ACTIVE** - Currently enforcing security policies

#### Testing Constraints

**MANDATORY Requirements**:
```bash
# ✅ REQUIRED: Browser-like User-Agent
curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" https://test.ihgroup.to

# ✅ REQUIRED: Rate limiting (example with nmap)
nmap -T2 --scan-delay 100ms --max-rate 10 136.110.148.157

# ✅ REQUIRED: Randomized delays
nuclei -rl 5 -delay 500ms https://test.ihgroup.to
```

**Bypass Strategies** (for authorized testing):
1. Use legitimate browser User-Agent headers
2. Implement jitter/randomization in request timing
3. Distribute scanning across multiple IPs (if available)
4. Use session persistence (cookies) when possible
5. Test during low-traffic periods to reduce detection likelihood

**Blocked Patterns to Avoid**:
- Scanner/tool User-Agents (Nmap, sqlmap, etc.)
- Rapid request bursts
- Known attack signatures (SQL injection patterns, XSS payloads without encoding)
- Unusual HTTP methods without proper context
- Missing or malformed headers

---

## 2. Transport Layer Security (TLS/SSL)

### SSL/TLS Configuration
**Status**: ✅ **STRONG** - Enterprise-grade configuration
**Certificate Authority**: Google Trust Services (WR3)
**Certificate Type**: Individual per-subdomain (not wildcard)

#### Certificate Details

**ihgroup.to Infrastructure**:
```
Subject: CN=test.ihgroup.to
Issuer: C=US, O=Google Trust Services, CN=WR3
Valid From: Nov 17 12:48:31 2025 GMT
Valid To: Feb 15 13:42:45 2026 GMT
Duration: 90 days (automated renewal)
SANs: DNS:test.ihgroup.to
```

**hpch.ch Infrastructure**:
```
Subject: CN=test.hpch.ch
Issuer: C=US, O=Google Trust Services, CN=WR3
Valid From: Nov 18 13:13:46 2025 GMT
Valid To: Feb 16 14:07:19 2026 GMT
Duration: 90 days (automated renewal)
SANs: DNS:test.hpch.ch
```

#### Protocol Support
- ✅ **TLS 1.2**: Supported (minimum)
- ✅ **TLS 1.3**: Likely supported (modern GCP default)
- ✅ **HTTP/2**: Confirmed active
- ✅ **HTTP/3** (QUIC): Confirmed via Alt-Svc header

#### Security Headers

**Strict-Transport-Security (HSTS)**:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
- **max-age**: 1 year (31536000 seconds)
- **includeSubDomains**: Protects all subdomains
- **Implication**: Browser will enforce HTTPS for 1 year after first visit

**Security Assessment**:
- ✅ **Certificate trust**: Valid chain to trusted CA
- ✅ **Certificate freshness**: Recently issued (within 4 days)
- ✅ **HSTS enabled**: Prevents downgrade attacks
- ✅ **Modern protocols**: HTTP/2 and HTTP/3 support
- ⚠️ **Individual certificates**: Each subdomain has separate cert (management overhead but more granular control)

---

## 3. Google Cloud Platform Infrastructure

### Identified GCP Services

#### 1. Google Frontend (Load Balancer)
**Evidence**: `Server: Google Frontend` header
**Purpose**: Global load balancing and DDoS protection

**Capabilities**:
- Global anycast IP addresses
- Automatic DDoS mitigation
- SSL/TLS termination
- Health checking and failover
- Cross-region traffic distribution

#### 2. Cloud Armor (WAF)
**Evidence**: wafw00f detection, behavioral filtering
**Purpose**: Web application firewall protection

**Configuration**: Active security policies enforcing User-Agent filtering

#### 3. Cloud Trace
**Evidence**: `X-Cloud-Trace-Context` header
**Purpose**: Distributed tracing and performance monitoring

**Observation**: Trace context present on all responses (monitoring enabled)

#### 4. Google Proxy Infrastructure
**Evidence**: `Via: 1.1 google` header
**Purpose**: Proxy layer for traffic routing

#### 5. HTTP/3 Support (QUIC)
**Evidence**: `Alt-Svc: h3=":443"; ma=2592000` header
**Purpose**: Modern protocol support for performance

### GCP Security Implications

**Positive Security Features**:
1. ✅ **Global DDoS protection**: Google's edge network absorbs attacks
2. ✅ **Automatic SSL management**: Google-managed certificates with auto-renewal
3. ✅ **Enterprise WAF**: Cloud Armor with ML-based detection
4. ✅ **Distributed tracing**: Monitoring and anomaly detection capabilities
5. ✅ **Modern protocols**: Performance optimizations (HTTP/2, HTTP/3)

**Testing Considerations**:
1. ⚠️ **Multi-layer filtering**: Traffic passes through Google Frontend → Cloud Armor → Backend
2. ⚠️ **Distributed architecture**: Requests may be handled by different regions
3. ⚠️ **Automated monitoring**: Cloud Trace may detect unusual patterns
4. ⚠️ **Rate limiting**: Multiple layers (Google Frontend, Cloud Armor, backend)

---

## 4. Firewall Configuration

### Google Cloud Firewall
**Status**: Inferred (not directly tested)
**Evidence**: GCP infrastructure, standard GCP security posture

**Expected Configuration**:
```
Ingress Rules (Assumed):
- HTTPS (443): ALLOW from 0.0.0.0/0 (public web service)
- HTTP (80): Likely REDIRECT to 443 (HSTS enforcement)
- All other ports: DENY (default deny-all for security)

Egress Rules (Assumed):
- Application-specific: ALLOW to backend services (databases, APIs)
- Internet: ALLOW for CDN, external APIs
```

**Testing Strategy**:
- Port scan with conservative timing to identify open ports
- Expect only HTTPS (443) to be accessible
- Database ports (3306, 5432, 27017) should be filtered/closed if properly configured

---

## 5. Rate Limiting Controls

### Expected Rate Limiting (Not Yet Tested)

**Cloud Armor Rate Limiting**:
- **Typical limits**: 100-1000 requests/minute per IP (configurable)
- **Enforcement**: 429 Too Many Requests response
- **Mitigation**: Exponential backoff, temporary IP blocking

**Testing Approach**:
```bash
# Conservative testing to detect rate limits
for i in {1..100}; do
  curl -s -o /dev/null -w "%{http_code}\n" https://test.ihgroup.to
  sleep 0.5  # 500ms delay = ~2 requests/second
done
```

**Indicators of rate limiting**:
- 429 Too Many Requests responses
- 503 Service Unavailable (overload)
- Connection timeouts
- Increasing response times

---

## 6. Content Delivery & Caching

### Google Cloud CDN (Inferred)
**Evidence**: Fast global response times, `Accept-Ranges: bytes` header
**Status**: Likely active (not confirmed)

**Observed Behavior**:
- Static content (Last-Modified: Sept 8, 2025)
- Accept-Ranges header (supports range requests)
- Consistent Content-Length across subdomains (21599 bytes)

**Implications for Testing**:
- ⚠️ **Cached responses**: May not reflect backend changes immediately
- ⚠️ **Cache poisoning**: Potential attack vector to explore
- ⚠️ **Cache busting**: Use unique parameters to bypass cache when needed

---

## Testing Strategy & Recommendations

### Phase 1: Passive Reconnaissance ✅ COMPLETE
- DNS enumeration: ✅ Done
- SSL/TLS analysis: ✅ Done
- WAF detection: ✅ Done
- Security header inspection: ✅ Done

### Phase 2: Active Reconnaissance (Upcoming)

#### 2.1 Port Scanning (Conservative)
```bash
# MANDATORY: T2 timing (polite scan, 0.4 second delay)
nmap -T2 -Pn --top-ports 1000 \
  --script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -oA nmap_ihgroup_T2 136.110.148.157

# Alternative: T3 with custom delays
nmap -T3 -Pn --scan-delay 200ms --max-rate 20 --top-ports 1000 \
  -oA nmap_ihgroup_T3 136.110.148.157
```

#### 2.2 Content Discovery
```bash
# Use browser User-Agent, rate limiting, and delays
ffuf -u https://test.ihgroup.to/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -rate 10 -p 0.5 \
  -o ffuf_ihgroup.json
```

#### 2.3 Vulnerability Scanning
```bash
# Conservative nuclei scan with rate limiting
nuclei -u https://test.ihgroup.to \
  -t nuclei-templates/cves/ \
  -severity critical,high,medium \
  -rl 5 -delay 500ms -timeout 15 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -o nuclei_ihgroup.txt
```

#### 2.4 Database Exposure Testing
```bash
# Test for MySQL (3306)
nmap -T2 -Pn -p 3306 --script mysql-info 136.110.148.157

# Test for PostgreSQL (5432)
nmap -T2 -Pn -p 5432 --script pgsql-brute 34.8.134.55

# Test for MongoDB (27017)
nmap -T2 -Pn -p 27017 --script mongodb-info 136.110.148.157
```

### Phase 3: Web Application Testing

#### 3.1 Input Validation (WAF-Aware)
```bash
# Test XSS with encoded payloads
curl -H "User-Agent: Mozilla/5.0" \
  "https://test.ihgroup.to/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

# Test SQL injection with time delays (low detection)
sqlmap -u "https://test.ihgroup.to/page?id=1" \
  --random-agent --delay=1 --time-sec=10 \
  --level 2 --risk 2
```

#### 3.2 Authentication Testing
```bash
# Test for default credentials (if login found)
# Test for authentication bypass
# Test for session management issues
```

---

## Security Control Summary

### Strengths
1. ✅ **Enterprise-grade WAF**: Google Cloud Armor actively protecting
2. ✅ **Strong TLS configuration**: Modern ciphers, HSTS enabled
3. ✅ **DDoS protection**: Google Frontend provides global protection
4. ✅ **Monitoring**: Cloud Trace indicates active monitoring
5. ✅ **Modern protocols**: HTTP/2 and HTTP/3 support

### Potential Weaknesses (To Investigate)
1. ⚠️ **Virtual hosting**: Shared IPs may allow host header attacks
2. ⚠️ **Static content**: Old last-modified date (Sept 2025) - outdated components?
3. ⚠️ **Individual certificates**: Subdomain enumeration via certificate transparency logs
4. ⚠️ **Backend exposure**: Database ports may be accessible (requires port scan)
5. ⚠️ **Application logic**: WAF may not protect against business logic flaws

### Testing Priorities (Risk-Based)
1. 🔴 **HIGH**: Database exposure testing (MySQL, PostgreSQL, MongoDB)
2. 🔴 **HIGH**: Business logic vulnerabilities (WAF bypass potential)
3. 🟡 **MEDIUM**: Input validation (XSS, SQLi with WAF-aware payloads)
4. 🟡 **MEDIUM**: Authentication mechanism testing
5. 🟡 **MEDIUM**: IDOR and authorization bypass
6. 🟢 **LOW**: Information disclosure (headers, error messages)
7. 🟢 **LOW**: Cache poisoning attacks

---

## Emergency Procedures

### If WAF Blocks Testing
1. 🛑 **STOP** all scanning immediately
2. ⏸️ **WAIT** 5-10 minutes for IP reputation to recover
3. 📉 **REDUCE** scan rate by 50%
4. 🔄 **RETRY** with more conservative timing (T1 or slower)
5. 📞 **CONTACT** target owner if blocking persists

### Signs of Being Blocked
- Consistent 403 Forbidden responses
- 429 Too Many Requests errors
- Connection timeouts or resets
- Captcha challenges
- Complete loss of connectivity

### Safe Testing Checklist
- [ ] Using browser User-Agent headers
- [ ] Rate limiting configured (≤ 10 requests/second)
- [ ] Scan delays implemented (≥ 100ms between requests)
- [ ] Conservative nmap timing (-T2 or slower)
- [ ] Monitoring for 403/429 responses
- [ ] Emergency stop procedure ready

---

**Last Updated**: 2025-11-20 18:20 UTC
**Next Review**: Before active reconnaissance phase
**Status**: ✅ Security controls documented - Ready for WAF-aware testing
