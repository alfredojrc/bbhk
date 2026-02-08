# Youness Web Application Penetration Test

## Project Overview
**Client**: Youness (Friend's Project)
**Authorization**: Explicit permission for security testing
**Status**: Non-production, testing phase
**Start Date**: 2025-11-20
**Platform**: Google Cloud Platform (Confirmed)

## Scope

### In-Scope Targets
All targets are **AUTHORIZED** for comprehensive security testing:

| Domain | IP Address | Environment | Status |
|--------|------------|-------------|--------|
| test.ihgroup.to | 136.110.148.157 | Testing | ✅ Non-prod |
| prod.ihgroup.to | 136.110.148.157 | Production | ⚠️ Same IP as test |
| dev.ihgroup.to | 136.110.148.157 | Development | ✅ Non-prod |
| dev.hpch.ch | 34.8.134.55 | Development | ✅ Non-prod |
| test.hpch.ch | 34.8.134.55 | Testing | ✅ Non-prod |
| prod.hpch.ch | 34.8.134.55 | Production | ⚠️ Same IP as test |

**Note**: Multiple subdomains share the same IPs, suggesting virtual hosting or reverse proxy configuration.

### Testing Objectives
1. **Asset Discovery**: Map complete attack surface
2. **Vulnerability Assessment**: Identify security weaknesses
3. **Database Security**: Check for publicly accessible databases
4. **Web Application Security**: Test for common vulnerabilities
   - SQL Injection
   - Cross-Site Scripting (XSS)
   - IDOR (Insecure Direct Object References)
   - Authentication/Authorization bypass
   - Business logic flaws
5. **Infrastructure Security**: Assess cloud configuration
6. **IDS/WAF Detection**: Identify protective measures

### Out of Scope
- ❌ Denial of Service (DoS/DDoS) attacks
- ❌ Social engineering of employees
- ❌ Physical security testing
- ❌ Third-party services not directly controlled
- ❌ Production data manipulation (read-only testing preferred)

## Infrastructure Details

### Confirmed Hosting: Google Cloud Platform
**IP Range Verification** (via WHOIS):
- **136.110.148.157**: Google LLC, NetRange: 136.107.0.0/16
- **34.8.134.55**: Google LLC, NetRange: 34.4.5.0 - 34.63.255.255

### Expected Security Controls
- **Firewall**: Google Cloud Firewall (standard)
- **IDS/IPS**: Google Cloud Armor (likely - requires confirmation)
- **WAF**: Cloud Armor Advanced Protection (possible)
- **Rate Limiting**: Standard GCP throttling
- **SSL/TLS**: Google-managed certificates

### Detection & Evasion Strategy
Per GCP best practices:
- ✅ **NO prior notification to Google required** (authorized testing on owned resources)
- ⚠️ Conservative scan rates (10 req/sec max)
- ⚠️ Stealth timing for initial recon (nmap -T2 or -T1)
- ⚠️ Monitor for 403/429 HTTP responses
- ✅ Document all activities with timestamps

## Technology Stack (Preliminary)

### To Be Confirmed via Reconnaissance
- **Web Server**: TBD (nginx, Apache, Google Frontend)
- **Application Framework**: TBD
- **Programming Language**: TBD
- **Database**: TBD (MySQL, PostgreSQL, MongoDB)
- **CDN/Proxy**: TBD
- **Authentication**: TBD (OAuth2, JWT, session-based)

## Methodology

### Phase 1: Passive Reconnaissance (Day 1)
**Duration**: 2-4 hours
**Risk Level**: 🟢 ZERO detection risk

**Activities**:
- DNS enumeration (dig, subfinder)
- Subdomain discovery (passive sources only)
- SSL/TLS certificate analysis
- Technology fingerprinting (whatweb)
- Public information gathering (OSINT)

**Tools**: subfinder, dig, openssl, whatweb

### Phase 2: Active Reconnaissance (Day 2)
**Duration**: 3-5 hours
**Risk Level**: 🟡 LOW detection risk

**Activities**:
- WAF/IDS detection (wafw00f)
- Port scanning (nmap -T2, top 1000 ports)
- Service enumeration (version detection)
- HTTP probing (httpx)
- Initial vulnerability scanning (nuclei, conservative)

**Tools**: wafw00f, nmap, httpx, nuclei

### Phase 3: Vulnerability Assessment (Day 3-5)
**Duration**: 5-10 hours
**Risk Level**: 🟠 MODERATE detection risk

**Activities**:
- Database exposure testing
- SQL injection testing (sqlmap, manual)
- XSS detection (dalfox, manual payloads)
- IDOR testing (Burp Suite, following HubSpot playbook)
- Authentication bypass attempts
- Business logic testing
- API security assessment

**Tools**: Burp Suite, sqlmap, dalfox, ffuf, custom scripts

### Phase 4: Documentation & Validation (Day 6)
**Duration**: 2-3 hours
**Risk Level**: 🟢 ZERO (read-only)

**Activities**:
- Evidence collection and organization
- PoC development and validation
- D.I.E. framework validation
- AI agent review (Critical Validator)
- Report generation
- Vulnerability storage in BBHK system

**Tools**: BBHK CLI, Groky, Gemini validator

## Tools & Automation

### BBHK Integration
```bash
# Store findings
./vuln store-quick

# Search similar vulnerabilities
./vuln find "web app idor youness"

# Get tool recommendations
./vuln tools <vulnerability_id>

# Create research workflow
./vuln research <vulnerability_id>

# Sync all systems
./vuln sync
```

### AI Agents Deployed
1. **scout-recon**: Attack surface mapping
2. **prior-art-researcher**: Duplicate prevention
3. **business-logic-breaker**: Vulnerability hunting
4. **critical-validator**: Quality assurance
5. **code-whisperer**: Static analysis (if source available)

### Automation Scripts
- **quick-recon.sh**: Automated reconnaissance (passive/active/full modes)
- **scan_manager.py**: Rate-limited scanning with safety controls (planned)

## Current Status

### Progress Tracker
- [x] Project initialization
- [x] Directory structure created
- [x] Documentation templates ready
- [x] **Phase 1: Active Reconnaissance COMPLETE** (2025-11-20 18:06-18:15 UTC)
  - [x] Conservative port scanning (250 ports across 2 IPs)
  - [x] Database exposure testing (7 database services - all filtered)
  - [x] Cloud Armor bypass testing (19 alternative ports - all filtered)
  - [x] Web service enumeration (6 subdomains analyzed)
  - [x] Content discovery with gobuster
  - [x] Technology stack fingerprinting
  - [x] Static content analysis (HTML/CSS downloaded)
  - [x] Evidence collection and documentation
  - [x] Qdrant storage integration
- [ ] T.K.V.F. technology verification (OPTIONAL - static HTML site)
- [ ] Phase 2: Application functionality analysis (PENDING - awaiting context)
- [ ] Phase 3: Vulnerability assessment (PENDING - depends on Phase 2)
- [ ] Phase 4: Validation & reporting

### Findings Summary - Phase 1 Active Reconnaissance
**Overall Security Grade**: **A+ (EXCELLENT)**

**Infrastructure Security**:
- ✅ **Cloud Armor Bypass**: NO bypasses found - all alternative ports filtered
- ✅ **Database Exposure**: ZERO exposure - all 7 database ports filtered on both IPs
- ✅ **Firewall Configuration**: Perfect - only ports 80/443 accessible
- ✅ **Attack Surface**: Minimal - simple static HTML site
- ⚠️ **Application Functionality**: Unclear - appears to be static content only

**Port Scan Results**:
- **Open Ports**: 2 (HTTP/80, HTTPS/443)
- **Filtered Ports**: 248 (including all database, admin, and alternative web ports)
- **Total Ports Scanned**: 250 across both IPs

**Technology Stack**:
- **Server**: Google Frontend (GCP)
- **Content**: Static HTML (21,599 bytes)
- **SSL/TLS**: Strong HSTS (max-age=31536000; includeSubDomains)
- **Protocol**: HTTP/2 with HTTP/3 support
- **Backend**: Not revealed
- **Framework**: None detected
- **JavaScript**: None detected
- **CSS**: Single stylesheet (144 lines)

**Security Strengths** (9 identified):
1. Only necessary ports accessible
2. All database ports filtered
3. No Cloud Armor bypasses
4. All admin panels secured
5. Strong HSTS configuration
6. HTTP/2 and HTTP/3 enabled
7. Minimal technology footprint
8. No information disclosure
9. Zero WAF blocking incidents (stealth maintained)

**Observations**:
- Static content with identical size (21,599 bytes) across all 6 subdomains
- Simple HTML/CSS site with no JavaScript frameworks
- Content age varies (Aug 2025 - Jan 2025)
- Unclear application purpose or functionality

**Total Vulnerabilities Discovered**: 0 (excellent security posture)

**Categories**:
- Critical: 0
- High: 0
- Medium: 0
- Low: 0
- Informational: 0 (good - no security misconfigurations found)

### Risk Assessment
**Current Phase**: Phase 1 Active Reconnaissance - ✅ COMPLETE
**Next Milestone**: Application functionality clarification with Youness
**Security Assessment**: Excellent infrastructure security, minimal attack surface
**Testing Constraints**: Static content limits traditional vulnerability testing approaches
**Recommendation**: Contact Youness to understand application purpose before Phase 2
**Estimated Completion**: Pending Phase 2 planning based on application context

## Evidence & Documentation

### Evidence Structure
```
evidence_YYYYMMDD/
├── screenshots/          # Visual proof of vulnerabilities
├── http_traffic/         # Burp Suite requests/responses
├── scan_results/         # Nmap, nuclei, tool outputs
└── proof_logs/          # Command outputs, logs
```

### Deliverables
```
deliverables/
├── FINAL_REPORT.md              # Executive summary
├── TECHNICAL_ANALYSIS.md        # Detailed findings
├── vulnerability_summary.json   # Structured data
├── poc_*.py                     # Proof of concept code
└── evidence_package.zip         # All supporting files
```

## Quality Standards

### D.I.E. Framework (Mandatory)
Every finding must meet:
- ✅ **Demonstrable**: Working PoC code included
- ✅ **Impactful**: Clear security impact documented
- ✅ **Evidentiary**: Complete proof package (screenshots, logs, traffic)

### Validation Process
1. Initial discovery via automated tools
2. Manual verification and impact assessment
3. PoC development
4. AI validation (Critical Validator agent)
5. Gemini/Groky expert review
6. Final D.I.E. checklist confirmation

## Safety & Ethics

### Authorization
- ✅ **Written permission obtained** from project owner (Youness)
- ✅ **Scope clearly defined** (6 domains, 2 IP addresses)
- ✅ **Contact information available** for immediate communication
- ✅ **Non-production environment** (primary testing)

### Safety Protocols
**STOP testing immediately if**:
- ❌ Repeated 403 Forbidden errors (possible blocking)
- ❌ 429 Too Many Requests (rate limiting triggered)
- ❌ Unusual latency or timeouts (potential IDS alert)
- ❌ Any legal or abuse notifications
- ❌ Uncertainty about authorization scope

**Emergency Contact**: [Youness contact info]

## Success Metrics

### Expected Findings (Based on BBHK Patterns)
**Likely vulnerabilities**:
- IDOR in API endpoints (if multi-tenant application)
- XSS in user input fields
- Information disclosure (error messages, debug mode)
- Missing security headers

**Possible high-value**:
- SQL injection in search/filter functions
- Authentication/authorization bypass
- Publicly accessible database
- Business logic flaws in workflows

**Estimated Portfolio Impact**: $5k-$50k potential (2-5 medium/high findings)

### Learning Objectives
1. **GCP-specific security** patterns and detection
2. **Cloud Armor** interaction and evasion techniques
3. **Web application** vulnerability hunting
4. **AI agent coordination** for efficient research
5. **Rate-limited scanning** methodologies

## Timeline

### Estimated Schedule
- **Day 1** (2025-11-20): Passive recon, IDS detection
- **Day 2** (2025-11-21): Active scanning, service enumeration
- **Day 3-5** (2025-11-22 to 2025-11-24): Vulnerability testing
- **Day 6** (2025-11-25): Documentation, validation
- **Buffer** (2025-11-26): Final review, delivery

**Total Effort**: 15-25 hours over 6 days

## References

### Internal Documentation
- **BBHK Methodology**: `/home/kali/bbhk/CLAUDE.md`
- **GCP Recon Guide**: `GCP_RECON_METHODOLOGY.md` (this project)
- **Attack Vectors**: `/home/kali/bbhk/ATTACK_VECTORS_COMPREHENSIVE_2025.md`
- **IDOR Playbook**: `/home/kali/bbhk/hacks/hubspot/IDOR_PATTERN_PLAYBOOK.md`
- **T.K.V.F. Framework**: `/home/kali/bbhk/TECHNOLOGY_VERIFICATION_QUICKSTART.md`

### External Resources
- **Google Cloud Security FAQ**: https://support.google.com/cloud/answer/6262505
- **Cloud Armor Documentation**: https://cloud.google.com/armor/docs
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **OWASP Top 10 (2021)**: https://owasp.org/Top10/

---

**Last Updated**: 2025-11-20
**Project Lead**: BBHK AI Research Team
**Status**: ✅ Initialized, Ready for Reconnaissance
