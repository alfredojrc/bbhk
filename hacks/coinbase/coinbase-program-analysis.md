# 🎯 Coinbase Bug Bounty Program Analysis

**Date**: August 17, 2025  
**Source**: HackerOne HACKER API (Real Data)  
**Method**: Direct API exploration using `/v1/hackers/programs`

## 📊 Data Structure Discovery

### 1. Program Identification
```json
{
  "id": "104",
  "type": "program",
  "handle": "coinbase",
  "name": "Coinbase"
}
```

### 2. HACKER API Data Fields Available

#### Core Program Attributes
| Field | Value | Description |
|-------|-------|-------------|
| `handle` | coinbase | Unique program identifier |
| `name` | Coinbase | Display name |
| `state` | public_mode | Program visibility |
| `submission_state` | open | Accepting reports |
| `currency` | usd | Payout currency |

#### Bounty Configuration
| Field | Value | Meaning |
|-------|-------|---------|
| `offers_bounties` | true | Pays money for bugs |
| `allows_bounty_splitting` | true | Can split rewards |
| `gold_standard_safe_harbor` | true | Legal protection |
| `fast_payments` | null | Not specified |
| `triage_active` | null | Not specified |
| `open_scope` | null | Not specified |

#### User-Specific Data
| Field | Value | What it tracks |
|-------|-------|----------------|
| `number_of_reports_for_user` | 0 | Your submissions |
| `bounty_earned_for_user` | 0.0 | Your earnings |
| `number_of_valid_reports_for_user` | 0 | Valid reports |
| `bookmarked` | true | Saved to favorites |
| `last_invitation_accepted_at_for_user` | null | Invitation date |

#### Program Metadata
| Field | Value |
|-------|-------|
| `started_accepting_at` | 2014-03-28T22:09:39.471Z |
| `profile_picture` | AWS S3 URL |
| `policy` | Full policy text (truncated in API) |

## 🔍 Key Discoveries from Web Search

### Two Distinct Programs
1. **Traditional HackerOne Program**
   - General security vulnerabilities
   - All Coinbase infrastructure
   - Standard bug bounty payouts

2. **$5M Onchain Program** (NEW!)
   - Smart contract vulnerabilities only
   - Up to $5 million rewards
   - Focus on Base.org and Web3

### Payout Information
- **Total Paid**: Over $2.3 million
- **2022 Alone**: ~$400,000
- **Maximum Bounty**: $5 million (onchain)
- **Minimum Payouts**: Tiered by severity

## 🎯 Scope Analysis (From Policy)

### In Scope
Based on policy analysis (8 mentions of "scope"):

#### Critical Assets
- `*.coinbase.com` - All subdomains
- `*.cbhq.net` - Internal network
- `api.coinbase.com` - Main API
- `custody.coinbase.com` - Institutional custody
- `prime.coinbase.com` - Prime trading
- `pro.coinbase.com` - Pro trading platform

#### Mobile Applications
- `com.coinbase.android` - Android app
- `com.coinbase.ios` - iOS app
- `com.coinbase.wallite` - Lite wallet
- `org.toshi` - Toshi wallet Android
- `org.toshi.distribution` - Toshi iOS

#### Web3/Smart Contracts
- `base.org` - Base L2 blockchain
- Web3 Smart Contracts (Critical severity)
- GitHub source code repositories
- Coinbase WaaS (Wallet as a Service)

#### Network
- `54.175.255.192/27` - CIDR block

### Out of Scope
- `blog.coinbase.com` - Blog
- `support.coinbase.com` - Support site
- `status.coinbase.com` - Status page
- `developers.coinbase.com` - Developer docs
- `engineering.coinbase.com` - Engineering blog
- `*.blockspring.com` - Third-party
- `paradex.io` - Deprecated
- `tagomi.com` - Acquisition

## 📈 Severity Distribution

From policy word frequency analysis:
- **Critical**: 10 mentions (highest priority)
- **High**: 5 mentions
- **Medium**: 1 mention
- **Low**: 4 mentions

This suggests Coinbase prioritizes critical vulnerabilities heavily.

## 🔐 Important Features

### Legal Protection
- **Gold Standard Safe Harbor**: TRUE
  - Full legal protection for good faith research
  - Explicit promise not to pursue researchers
  - Industry-leading protection

### Disclosure Policy
- **Disclosure**: 7 mentions in policy
  - Coordinated disclosure process
  - Public disclosure after fix
  - Recognition for researchers

## 💡 Strategic Insights

### What Makes Coinbase Unique
1. **10+ Year Program** - One of the oldest on HackerOne
2. **Dual Programs** - Traditional + Blockchain focused
3. **$5M Maximum** - Industry-leading for smart contracts
4. **Gold Standard** - Best legal protection available
5. **Bounty Splitting** - Collaborative hunting allowed

### Focus Areas for Hunters
1. **Smart Contracts** - Highest rewards ($5M max)
2. **Custody Platform** - Critical infrastructure
3. **API Endpoints** - Core functionality
4. **Mobile Apps** - Wide attack surface
5. **Base.org** - New L2 blockchain

## 🛠️ HACKER API Limitations

### What We CAN Access
- ✅ Program basic info
- ✅ Bounty configuration
- ✅ Our personal stats
- ✅ Policy text (partial)
- ✅ Submission status

### What We CANNOT Access
- ❌ Detailed scope assets
- ❌ Specific bounty amounts
- ❌ Other hackers' reports
- ❌ Internal metrics
- ❌ Vulnerability statistics

## 📝 Data Structure Summary

The HACKER API provides a flat JSON structure with:
```
program
├── id (string)
├── type ("program")
├── attributes (object)
│   ├── handle
│   ├── name
│   ├── state
│   ├── submission_state
│   ├── offers_bounties
│   ├── allows_bounty_splitting
│   ├── gold_standard_safe_harbor
│   ├── currency
│   ├── policy
│   ├── [user-specific fields]
│   └── [timestamps]
├── relationships (object) - Empty for HACKER API
└── links (object) - Empty for HACKER API
```

## 🎯 Next Steps for Deep Exploration

1. **Parse Policy Text** - Extract detailed scope from policy field
2. **Monitor Changes** - Track program updates over time
3. **Cross-Reference** - Compare with public disclosures
4. **Test Endpoints** - Validate scope assets are accessible
5. **Track Patterns** - Identify common vulnerability types

---

**Key Finding**: Coinbase is one of the most mature and well-funded bug bounty programs, with special emphasis on blockchain security offering up to $5M for critical smart contract vulnerabilities.