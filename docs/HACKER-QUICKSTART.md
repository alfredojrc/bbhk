# 🎯 Bug Bounty Hacker Quick Start Guide

**Get hunting in 5 minutes** - Simple setup for individual security researchers

## What is BBHK?

BBHK is a **personal reconnaissance toolkit** for bug bounty hunters. It helps you:
- Find and organize bug bounty programs 
- Automate target discovery and scope validation
- Track your findings and progress
- Stay within legal scope boundaries

**Perfect for**: Solo hackers, weekend warriors, and full-time bug bounty hunters

## ⚡ Super Quick Setup

### 1. Start the System (2 commands)
```bash
# Terminal 1: Start the API
cd /home/kali/bbhk/web/backend && python3 main_updated.py

# Terminal 2: Start the dashboard  
cd /home/kali/bbhk/web/frontend && npm start
```

### 2. Open Your Dashboard
```
http://localhost:3000  # Your hunting dashboard
http://localhost:8000/docs  # API reference
```

### 3. Start Hunting
- Browse available programs
- Filter by bounty amounts
- Export scope targets
- Begin reconnaissance

**That's it!** You're ready to hunt.

---

## 🛡️ Safety First - Legal Scope

### The Golden Rule
**ONLY test targets marked as IN-SCOPE (✅)**

### Visual Safety System
- **Green borders** = Safe to test
- **Red borders** = FORBIDDEN (legal trouble!)
- **"Safe Targets Only" filter** = Your best friend

### Quick Scope Check
```bash
# Get only safe targets for a program
curl "http://localhost:8000/api/programs/1/scope?scope_type=in_scope"

# Search for specific domain (safe only)
curl "http://localhost:8000/api/scope/search?q=example.com&eligible_for_bounty=1"
```

**Remember**: Out-of-scope testing can result in criminal charges, platform bans, and lawsuits.

---

## 🔍 Basic Reconnaissance Workflow

### 1. Find Programs
```bash
# Programs with bounties
curl "http://localhost:8000/api/programs?has_bounty=true&limit=10"

# High-value programs
curl "http://localhost:8000/api/programs" | jq '.programs[] | select(.maximum_bounty > 5000)'
```

### 2. Get Scope Targets
```bash
# All safe targets for a program
curl "http://localhost:8000/api/programs/123/scope?scope_type=in_scope"

# Export to file for tools
curl "http://localhost:8000/api/programs/123/scope?scope_type=in_scope" | jq -r '.scope[].target' > targets.txt
```

### 3. Start Reconnaissance
```bash
# Subdomain enumeration
subfinder -dL targets.txt -o subdomains.txt

# HTTP probing
cat subdomains.txt | httpx -o live_targets.txt

# Technology detection
cat live_targets.txt | httpx -tech-detect -o tech_stack.txt
```

### 4. Vulnerability Scanning
```bash
# Quick nuclei scan
nuclei -l live_targets.txt -t cves/ -o findings.txt

# Directory enumeration
ffuf -w /path/to/wordlist -u "FUZZ" -of html -o directory_scan.html
```

---

## 🎯 Quick API Reference

### Essential Endpoints
```bash
# System health
GET /health

# All programs
GET /api/programs

# Program details  
GET /api/programs/{id}

# Program scope (CRITICAL!)
GET /api/programs/{id}/scope

# Search programs
GET /api/search/programs?q={query}

# Platform stats
GET /api/stats
```

### Useful Filters
```bash
# Only programs with bounties
?has_bounty=true

# Only in-scope targets
?scope_type=in_scope

# Specific platform
?platform=hackerone

# Limit results
?limit=50&offset=0
```

---

## 🚀 Hacker Automation Examples

### Script 1: Find High-Value Programs
```bash
#!/bin/bash
# find-high-value.sh

echo "🎯 Finding high-value programs..."
curl -s "http://localhost:8000/api/programs?has_bounty=true" | \
jq '.programs[] | select(.maximum_bounty > 10000) | {name: .program_name, bounty: .maximum_bounty, handle: .handle}' | \
head -10

echo "💰 Top paying programs found!"
```

### Script 2: Export All Safe Targets
```bash
#!/bin/bash
# export-safe-targets.sh

PROGRAM_ID=$1
if [ -z "$PROGRAM_ID" ]; then
    echo "Usage: $0 <program_id>"
    exit 1
fi

echo "🔍 Exporting safe targets for program $PROGRAM_ID..."
curl -s "http://localhost:8000/api/programs/$PROGRAM_ID/scope?scope_type=in_scope" | \
jq -r '.scope[].target' > "program_${PROGRAM_ID}_targets.txt"

echo "✅ Safe targets saved to program_${PROGRAM_ID}_targets.txt"
echo "📊 $(wc -l < program_${PROGRAM_ID}_targets.txt) targets exported"
```

### Script 3: Quick Recon Pipeline
```bash
#!/bin/bash
# quick-recon.sh

TARGETS_FILE=$1
if [ -z "$TARGETS_FILE" ]; then
    echo "Usage: $0 <targets_file>"
    exit 1
fi

echo "🚀 Starting reconnaissance pipeline..."

# Subdomain enumeration
echo "🔍 Finding subdomains..."
subfinder -dL $TARGETS_FILE -silent | anew subdomains.txt

# HTTP probing
echo "🌐 Probing for live hosts..."
cat subdomains.txt | httpx -silent | anew live_hosts.txt

# Quick vulnerability scan
echo "🎯 Quick vulnerability scan..."
nuclei -l live_hosts.txt -t http/vulnerabilities/ -silent -o quick_findings.txt

echo "✅ Recon complete!"
echo "📊 $(wc -l < live_hosts.txt) live hosts found"
echo "🔍 $(wc -l < quick_findings.txt) potential findings"
```

---

## 🎛️ Dashboard Features for Hackers

### Programs Tab
- **Filter by bounty** - Find paying programs
- **Sort by max bounty** - Target high-value programs  
- **Program details** - Scope, rules, contact info

### Scope Targets Tab
- **Safety indicators** - Green=safe, Red=forbidden
- **Export options** - Save targets for tools
- **Target types** - URLs, domains, IPs, mobile apps

### Statistics Tab
- **Platform overview** - Total programs, bounties
- **Your progress** - Tracked findings and submissions

---

## 🛠️ Tool Integration

### Popular Bug Bounty Tools
```bash
# Reconnaissance
subfinder, amass, assetfinder  # Subdomain enumeration
httpx, httprobe               # HTTP probing
naabu                         # Port scanning

# Vulnerability Scanning  
nuclei                        # Template-based scanning
ffuf, gobuster               # Directory/file enumeration
sqlmap                       # SQL injection testing

# Manual Testing
burp, caido                  # Proxy tools
postman                      # API testing
```

### BBHK Integration
```bash
# Get targets from BBHK -> feed to tools
curl "http://localhost:8000/api/programs/123/scope?scope_type=in_scope" | \
jq -r '.scope[].target' | \
subfinder -dL stdin

# Chain tools together
curl -s "http://localhost:8000/api/programs/123/scope?scope_type=in_scope" | \
jq -r '.scope[].target' | \
subfinder -dL stdin | \
httpx | \
nuclei -t cves/
```

---

## 🚨 Legal & Safety Reminders

### Always Remember
1. **Check scope TWICE** - Use BBHK visual indicators + program page
2. **Start with passive reconnaissance** - OSINT, public data only
3. **Read program policies** - Each program has unique rules
4. **Report responsibly** - Follow disclosure guidelines
5. **Keep evidence** - Screenshots, requests, responses

### Red Flags (STOP!)
- Target shows red warning in BBHK
- Target not explicitly listed in scope
- Program says "DO NOT TEST" 
- You're unsure about scope boundaries

### When in Doubt
1. **Contact the program team** - Ask for clarification
2. **Skip the target** - Find something else
3. **Check platform forums** - Community guidance

**Your safety and legal standing come first!**

---

## 📚 Next Steps

### Level Up Your Skills
1. **Learn the tools** - Master nuclei, ffuf, burp
2. **Study methodologies** - OWASP, PortSwigger Academy
3. **Join communities** - Discord, Telegram groups
4. **Practice legally** - TryHackMe, HackTheBox, PortSwigger Labs

### Expand Your Arsenal
1. **Custom wordlists** - Build domain-specific lists
2. **Script automation** - Bash, Python, or Go
3. **Burp extensions** - Active Scan++, Param Miner
4. **API testing** - Postman collections, custom scripts

### Track Your Progress
1. **Maintain notes** - Document techniques that work
2. **Build templates** - Reusable report formats
3. **Learn from rejections** - Improve your methodology
4. **Share knowledge** - Help other hackers (when appropriate)

---

## 🤝 Community Resources

### Learning Platforms
- **PortSwigger Web Security Academy** - Free, comprehensive
- **HackerOne Hacktivity** - Real disclosed reports
- **Bugcrowd University** - Bug bounty fundamentals

### Tools & Resources
- **SecLists** - Wordlists and payloads
- **PayloadsAllTheThings** - Vulnerability payloads
- **OWASP Testing Guide** - Methodology reference

### Communities
- **Twitter/X** - Follow @bugbountytips, @NahamSec
- **YouTube** - STÖK, Insider PhD, PwnFunction  
- **Discord/Telegram** - Join hunting communities

---

## 🎯 Success Tips for Solo Hackers

### Start Small
- Pick 2-3 programs initially
- Focus on one target type (web apps)
- Master basic tools before advancing

### Be Methodical
- Use checklists and templates
- Document everything
- Follow a consistent process

### Stay Legal
- Triple-check scope
- Read program policies completely
- When in doubt, ask

### Keep Learning
- Every program teaches something
- Failed attempts are learning opportunities  
- Share knowledge with the community

**Happy hunting! 🎯**

---

*This guide gets you started quickly. For advanced features, see the full documentation in `/docs/`*

*Remember: BBHK keeps you safe by highlighting legal scope boundaries. Always verify before testing.*