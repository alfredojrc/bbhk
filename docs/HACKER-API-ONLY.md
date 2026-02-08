# 🚨 CRITICAL: Use HACKER API Only!

**Date**: August 17, 2025  
**Status**: ✅ CONFIRMED WORKING - 570 Programs Retrieved

## ⚠️ MOST IMPORTANT RULE

**ALWAYS use HackerOne HACKER API** (`/v1/hackers/*`)  
**NEVER use Enterprise API** (`/v1/programs`, `/v1/me`, etc.)

## Why This Matters

### ✅ HACKER API = FREE
- Designed for bug hunters
- No subscription required
- Access to YOUR data (programs, reports, earnings)
- 570+ programs available

### ❌ Enterprise API = $15,000-$50,000/year
- For companies running programs
- Requires expensive subscription
- Organization management features
- NOT for individual hackers

## The Critical Pattern

### ✅ CORRECT URLs (Hacker API)
```bash
https://api.hackerone.com/v1/hackers/programs     # Your programs
https://api.hackerone.com/v1/hackers/me          # Your profile
https://api.hackerone.com/v1/hackers/reports     # Your reports
https://api.hackerone.com/v1/hackers/earnings    # Your earnings
```

### ❌ WRONG URLs (Enterprise API)
```bash
https://api.hackerone.com/v1/programs     # DON'T USE - Costs $15K+
https://api.hackerone.com/v1/me          # DON'T USE - Enterprise only
https://api.hackerone.com/v1/organizations # DON'T USE - Enterprise only
https://api.hackerone.com/v1/reports     # DON'T USE - Company reports
```

## Simple Rule to Remember

**Has `/hackers/` in the path? ✅ FREE - Use it!**  
**Missing `/hackers/`? ❌ EXPENSIVE - Don't use!**

## Working Configuration

```python
# ✅ CORRECT - Using HACKER API
USERNAME = "<YOUR_USERNAME>"
API_TOKEN = "<YOUR_HACKERONE_TOKEN>"
API_URL = "https://api.hackerone.com/v1/hackers/programs"

# Fetch programs (WORKS!)
response = requests.get(API_URL, auth=(USERNAME, API_TOKEN))
```

## What We Can Access (FREE)

1. **570+ Programs** - All programs you're invited to
2. **Scope Information** - In-scope assets for each program
3. **Report Submission** - Submit vulnerabilities via API
4. **Earnings Tracking** - Your bounty payments
5. **Report Status** - Track your submissions

## Testing Script

Use this script to test HACKER API access:

```bash
# Test with curl
curl https://api.hackerone.com/v1/hackers/programs \
  -u "<YOUR_USERNAME>:<YOUR_HACKERONE_TOKEN>" \
  -H 'Accept: application/json'

# Or use our Python script
python3 tools/api-testing/test_hacker_api_only.py
```

## Common Mistakes to Avoid

### ❌ DON'T Do This:
```python
# WRONG - This is enterprise API
url = "https://api.hackerone.com/v1/programs"  # Missing /hackers/
```

### ✅ DO This Instead:
```python
# CORRECT - This is hacker API
url = "https://api.hackerone.com/v1/hackers/programs"  # Has /hackers/
```

## Files Updated for HACKER API

All files have been updated to use HACKER API only:
- `/scripts/fetch-hacker-api-programs.py` - Fetches 570 programs
- `/tools/api-testing/test_hacker_api_only.py` - Clean test script
- `/CLAUDE.md` - Configuration with API warning
- `/README.md` - Project documentation with API notice

## Archived Enterprise API Files

All enterprise API references have been archived to:
- `/archive/enterprise-api-cleanup-aug17/`

## 📂 Program Analysis Examples

Real program analyses using HACKER API:
- **[Coinbase Analysis](./bb-sites/hackerone/programs/coinbase/)** - Complete exploration
- **[All Programs Index](./bb-sites/hackerone/PROGRAMS-INDEX.md)** - 570 programs available

## Quick Validation

Run this to ensure no enterprise API references remain:
```bash
grep -r "/v1/programs\|/v1/me\|/v1/organizations" . \
  --exclude-dir=archive --exclude-dir=.git
```

## Summary

**Remember: `/v1/hackers/*` = FREE = Use it!**  
**Everything else = EXPENSIVE = Don't use!**

---

**Last Validated**: August 17, 2025  
**Programs Retrieved**: 570 via HACKER API  
**Cost**: $0 (FREE)