# 🎯 Coinbase Bug Bounty Program - Complete Exploration

**Date**: August 17, 2025  
**API Used**: HackerOne HACKER API (`/v1/hackers/programs`)  
**Data Source**: 100% Real API Data (No Database, No Fake Data)

## 📊 Program Structure from HACKER API

### JSON Data Structure
```json
{
  "id": "104",                    // Unique program ID
  "type": "program",              // Resource type
  "attributes": {                 // All program data
    // Core fields
    "handle": "coinbase",         // URL identifier
    "name": "Coinbase",           // Display name
    "state": "public_mode",       // Publicly visible
    "submission_state": "open",   // Accepting reports
    
    // Bounty configuration
    "offers_bounties": true,
    "allows_bounty_splitting": true,
    "gold_standard_safe_harbor": true,
    "currency": "usd",
    
    // User-specific data
    "number_of_reports_for_user": 0,
    "bounty_earned_for_user": 0.0,
    "bookmarked": true,
    
    // Full policy text
    "policy": "...",              // Complete program policy
    
    // Metadata
    "started_accepting_at": "2014-03-28",
    "profile_picture": "AWS_S3_URL"
  }
}
```

## 💰 Reward Structure (From Policy)

### Bounty Tiers - UPDATED 2025

| Tier | Description | Reward |
|------|-------------|--------|
| **EXTREME** | Unauthorized access to hot/cold wallets, private keys | **Up to $1,000,000** |
| **CRITICAL** | RCE on staking nodes, 2FA bypass, MNPI exposure | **$50,000** |
| **HIGH** | Fee bypass, PII leaks <15% users, KYC bypass | **$15,000** |
| **MEDIUM** | Moderate fee bypass, semi-sensitive leaks | **$2,000** |
| **LOW** | <$100K loss, misconfigurations | **$200** |

### Special Programs
- **$5M Onchain Program**: For smart contract vulnerabilities
- **Base Network**: L2 blockchain vulnerabilities
- **CB-MPC Library**: Open source crypto library bugs

## 🎯 Detailed Scope Analysis

### In-Scope Assets

#### 1. Web Domains
```
*.coinbase.com          - All subdomains
*.cbhq.net             - Internal network
*.base.org             - L2 blockchain
*.tagomi.com           - Trading platform (critical only)
54.175.255.192/27      - IP block
```

#### 2. Critical Endpoints
- `api.coinbase.com` - Main API
- `custody.coinbase.com` - Institutional custody
- `prime.coinbase.com` - Prime trading
- `pro.coinbase.com` - Pro platform
- `institutional.coinbase.com` - Institutional services
- `international.coinbase.com` - International platform
- `nft.coinbase.com` - NFT marketplace
- `commerce.coinbase.com` - Commerce APIs
- `cloud.coinbase.com` - Cloud services

#### 3. Mobile Applications
- `com.coinbase.android` - Main Android app
- `com.coinbase.ios` - Main iOS app
- `com.coinbase.wallite` - Lite wallet
- `org.toshi` - Toshi wallet (Android)
- `org.toshi.distribution` - Toshi (iOS)

#### 4. Smart Contracts & Web3
- Base.org contracts
- Web3 Smart Contracts
- GitHub repositories:
  - `github.com/coinbase`
  - `github.com/base`
  - `github.com/coinbase/cb-mpc`

#### 5. Special Assets
- Coinbase WaaS (Wallet as a Service)
- Chrome Wallet Extension
- MPC Cryptography Library

### Out of Scope
- `blog.coinbase.com` - Blog
- `support.coinbase.com` - Support
- `status.coinbase.com` - Status page
- `developers.coinbase.com` - Dev docs
- `engineering.coinbase.com` - Engineering blog
- `*.blockspring.com` - Third-party
- `paradex.io` - Deprecated
- Social engineering attacks
- Physical security
- Rate limiting (non-critical)

## 🔍 Key Discoveries

### 1. Program Maturity
- **Started**: March 28, 2014 (10+ years old!)
- **One of the oldest** programs on HackerOne
- **Gold Standard Safe Harbor** - Best legal protection

### 2. Focus Areas
The policy emphasizes protecting:
- **Digital/fiat currency balances**
- **Customer information**

### 3. AI Report Warning
"Reports that are clearly automated with no meaningful human input will be immediately closed"

### 4. Risk Rating System
- Uses internal metrics for monetary impact
- PII leaks scored by internal system
- Focus on actual impact vs theoretical

### 5. Special Requirements
- Must be 14+ years old
- Cannot be Coinbase employee/family
- Must submit through HackerOne only
- Anonymous reports accepted but no bounty

## 📈 Strategic Insights for Hunters

### High-Value Targets
1. **Smart Contracts** ($5M maximum!)
   - Base.org contracts
   - CB-MPC library
   - Web3 integrations

2. **Critical Infrastructure**
   - Custody platform (institutional)
   - Prime trading systems
   - API endpoints

3. **Financial Systems**
   - Fee bypass mechanisms
   - Staking rewards
   - Trading systems

### What Coinbase Values Most
Based on policy analysis:
- **Extreme**: Wallet/key compromise ($1M)
- **Critical**: Mentioned 10 times in policy
- **Disclosure**: 7 mentions (coordinated disclosure)
- **Scope**: 8 mentions (clearly defined)

### Red Flags to Avoid
- ❌ Social engineering (banned)
- ❌ Extortion attempts (law enforcement)
- ❌ AI-only reports (immediate closure)
- ❌ Rate limiting issues (unless critical)
- ❌ Third-party integrations

## 🛠️ HACKER API Capabilities

### What We Retrieved
✅ Program identification (ID, handle, name)
✅ Status (open, public_mode)
✅ Bounty configuration
✅ User-specific stats
✅ Full policy text (4KB+)
✅ Legal protections status
✅ Program age/history

### What's Missing
❌ Specific asset details (need to parse policy)
❌ Exact bounty amounts per bug
❌ Other hackers' statistics
❌ Vulnerability trends
❌ Response time metrics

## 📝 Data Access Pattern

### How to Access Coinbase Data
```python
# Step 1: Fetch all programs
GET /v1/hackers/programs

# Step 2: Find Coinbase (ID: 104, handle: coinbase)
for program in programs:
    if program['attributes']['handle'] == 'coinbase':
        # Found it!

# Step 3: Extract data
- attributes.policy → Full program details
- attributes.offers_bounties → Payment status
- attributes.submission_state → Open/closed

# Note: Cannot get:
- /v1/hackers/programs/coinbase (404)
- /v1/programs/coinbase (Enterprise API - $15K)
```

## 🎯 Action Items for Bug Hunters

### Immediate Opportunities
1. **CB-MPC Library** - New open source target
2. **Base Network** - L2 blockchain bugs
3. **MEV Protection** - Memory pool leaks

### Preparation Checklist
- [ ] Read full policy (v4.2)
- [ ] Understand risk rating system
- [ ] Focus on monetary impact bugs
- [ ] Prepare clear PoCs
- [ ] Follow HackerOne Code of Conduct

### Best Practices
1. **Quality over Quantity** - No AI-only reports
2. **Clear Impact** - Show actual harm
3. **Responsible Disclosure** - Follow process
4. **No Demands** - No conditions/ransoms

## 🔮 Future Exploration

### Next Steps
1. **Monitor Policy Updates** - Track version changes (currently v4.2)
2. **Track Scope Changes** - New assets added regularly
3. **Watch Base Network** - Growing L2 ecosystem
4. **Study CB-MPC** - New crypto library opportunities

### API Monitoring Strategy
```bash
# Daily check for updates
curl https://api.hackerone.com/v1/hackers/programs \
  -u "<YOUR_H1_USERNAME>:TOKEN" | jq '.data[] | select(.attributes.handle=="coinbase")'
```

---

## Summary

**Coinbase offers one of the most comprehensive and well-funded bug bounty programs:**
- 10+ years of operation
- Up to $1M for critical bugs
- $5M for smart contract vulnerabilities
- Gold standard legal protection
- Clear scope and policies
- Open for submissions

**The HACKER API provides sufficient data to understand program structure, scope, and requirements without needing the expensive Enterprise API.**