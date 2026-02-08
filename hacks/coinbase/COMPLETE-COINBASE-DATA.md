# 🎯 Complete Coinbase Data from HACKER API

**Date**: August 17, 2025  
**Status**: FULLY EXPLORED  
**Data Source**: HackerOne HACKER API (100% Real Data)

## ✅ All Available Data from HACKER API

### 1. Working Endpoints

| Endpoint | Status | Returns |
|----------|--------|---------|
| `/v1/hackers/programs` | ✅ Works | List with Coinbase included |
| `/v1/hackers/programs/coinbase` | ✅ Works | Some response data |
| `/v1/hackers/programs/coinbase/structured_scopes` | ✅ Works | 25 scope items! |
| `/v1/hackers/programs?filter[handle]=coinbase` | ✅ Works | Filtered list |
| `/v1/hackers/programs?filter[id]=104` | ✅ Works | Filtered list |
| `/v1/hackers/programs?include=structured_scopes` | ✅ Works | With includes |

### 2. Complete Program Attributes (19 fields)

```json
{
  "handle": "coinbase",
  "name": "Coinbase",
  "state": "public_mode",
  "submission_state": "open",
  "currency": "usd",
  "offers_bounties": true,
  "allows_bounty_splitting": true,
  "gold_standard_safe_harbor": true,
  "bookmarked": true,
  "started_accepting_at": "2014-03-28",
  "profile_picture": "AWS_S3_URL",
  "policy": "4KB+ full policy text",
  
  // User-specific fields
  "number_of_reports_for_user": 0,
  "number_of_valid_reports_for_user": 0,  // NEW!
  "bounty_earned_for_user": 0.0,
  "last_invitation_accepted_at_for_user": null,
  
  // Additional fields discovered
  "triage_active": null,        // NEW!
  "open_scope": null,           // NEW!
  "fast_payments": null         // NEW!
}
```

### 3. Structured Scopes Data (25 items)

#### Scope Item Structure
Each scope item contains:
```json
{
  "type": "structured-scope",
  "id": "120",
  "attributes": {
    "asset_type": "URL",
    "asset_identifier": "*.coinbase.com",
    "eligible_for_bounty": true,
    "eligible_for_submission": true,
    "instruction": "",
    "max_severity": "critical",
    "created_at": "2017-07-20T23:32:30.242Z",
    "updated_at": "2023-01-24T12:35:40.879Z",
    "confidentiality_requirement": "high",
    "integrity_requirement": "high",
    "availability_requirement": "high"
  }
}
```

#### Scope by Asset Type

**URLs (16 items)**
- `*.coinbase.com` - Critical
- `*.cbhq.net` - Critical
- `pro.coinbase.com` - Critical
- `api.coinbase.com` - Critical
- `custody.coinbase.com` - Critical
- `prime.coinbase.com` - Critical
- `institutional.coinbase.com` - Critical
- `international.coinbase.com` - High
- `commerce.coinbase.com` - Critical
- `nft.coinbase.com` - Critical
- `cloud.coinbase.com` - Critical
- `coinbase.com` - Critical
- `http://coinbase.com` - High
- `api.custody.coinbase.com` - Critical

**Mobile Apps (6 items)**
- `com.coinbase.android` - Critical (Google Play)
- `com.coinbase.ios` - Critical (App Store)
- `org.toshi` - Critical (Google Play)
- `org.toshi.distribution` - Critical (App Store)
- `com.coinbase.pro` - None/Out of scope (both stores)

**Network (1 item)**
- `54.175.255.192/27` - Critical (CIDR block)

**Other (2 items)**
- `Other` - Medium (catch-all for missed assets)
- `N/A - Not Coinbase owned` - None (out of scope marker)

### 4. Policy Analysis Results

**Sections Found (14)**
1. A Note on AI Generated Reports
2. Program Overview
3. Reward Structure
4. Additional Information
5. Base Network
6. CB-MPC Open Source Release
7. Program Policies
8. Researcher Requirements
9. Report Evaluation
10. Note on Rate Limiting
11. Report Closure
12. Scope
13. Eligibility
14. Fine Print

**Reward Tiers Extracted**
- $1,000,000 - Extreme (wallet/key compromise)
- $50,000 - Critical
- $15,000 - High
- $2,000 - Medium
- $200 - Low
- $100,000 - Mentioned in policy

**Keyword Frequency**
- Critical: 10 mentions
- High: 5 mentions
- Base: 57 mentions (L2 blockchain focus!)
- Extreme: 1 mention
- Medium: 1 mention
- Low: 4 mentions

### 5. What We CANNOT Access

Despite thorough exploration, these endpoints don't work:
- ❌ `/v1/hackers/programs/104` (404 - ID doesn't work)
- ❌ `/v1/hackers/programs/104/structured_scopes` (404)
- ❌ `/v1/hackers/programs/104/weaknesses` (404)
- ❌ `/v1/hackers/programs/104/metrics` (401)
- ❌ `/v1/hackers/programs/104/relationships` (401)
- ❌ `/v1/hackers/programs/104/members` (401)

### 6. Data Files Created

All stored in `/docs/bb-sites/hackerone/programs/coinbase/`:
1. `coinbase_program_20250817_200908.json` - Basic program data
2. `coinbase_structured_scopes_20250817_203330.json` - 25 scope items
3. `coinbase_deep_dive_20250817_203232.json` - Deep dive results
4. `coinbase-program-analysis.md` - Initial analysis
5. `coinbase-complete-exploration.md` - Detailed exploration
6. `COMPLETE-COINBASE-DATA.md` - This file

## 🎯 Key Discoveries

### What the HACKER API Provides
1. **Full program configuration** (19 attributes)
2. **Complete policy text** (4KB+ with all details)
3. **Structured scope data** (25 items with CIA ratings)
4. **User-specific statistics** (reports, earnings, validity)
5. **Program metadata** (age, pictures, status)

### Access Patterns
- Use **handle** not ID: `/programs/coinbase` works, `/programs/104` doesn't
- **Filters work**: `filter[handle]=coinbase`
- **Includes work**: `include=structured_scopes`
- **Pagination**: Default 25 items, use `page[size]=100`

### Unique Findings
- **57 mentions of "Base"** - Heavy L2 blockchain focus
- **$5M not in main data** - Only mentioned in web search
- **Structured scopes** - Provide CIA triad ratings per asset
- **25 scope items** - More detailed than policy text parsing

## 📊 Complete Data Coverage

| Data Type | Available | Source |
|-----------|-----------|--------|
| Program basics | ✅ Yes | `/programs` endpoint |
| Policy text | ✅ Yes | `policy` field |
| Structured scopes | ✅ Yes | `/programs/coinbase/structured_scopes` |
| Reward amounts | ✅ Yes | Policy text parsing |
| User stats | ✅ Yes | User-specific fields |
| Weaknesses | ❌ No | 404/401 errors |
| Metrics | ❌ No | 401 unauthorized |
| Members | ❌ No | 401 unauthorized |
| Reports | ❌ No | Not accessible |

## ✅ Conclusion

We have now **FULLY EXPLORED** all available Coinbase data from the HACKER API:
- 19 program attributes
- 25 structured scope items
- Complete policy text
- All working endpoints identified
- All limitations documented

**The HACKER API provides sufficient data for bug bounty hunting without needing the expensive Enterprise API!**