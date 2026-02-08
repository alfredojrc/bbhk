# 🎯 HackerOne HACKER API Complete Guide

**Date**: August 17, 2025  
**Status**: PRODUCTION READY  
**Database**: PostgreSQL with 570 programs

## 📚 What We Learned

### 1. Working Endpoints

| Endpoint | Returns | Example |
|----------|---------|---------|
| `/v1/hackers/programs` | All programs list | 570 programs |
| `/v1/hackers/programs?page[size]=100` | Paginated results | 100 per page |
| `/v1/hackers/programs/{handle}` | Single program | Use handle, not ID |
| `/v1/hackers/programs/{handle}/structured_scopes` | Scope details | 25-50 items typically |
| `/v1/hackers/programs?filter[handle]=coinbase` | Filtered results | Specific program |
| `/v1/hackers/programs?include=structured_scopes` | With includes | Extended data |

### 2. Key Discovery: Use Handle, Not ID
- ✅ `/programs/coinbase` works
- ❌ `/programs/104` returns 404
- Always use the program handle for specific endpoints

### 3. Complete Data Structure

```json
{
  "id": "104",                          // Program ID
  "type": "program",
  "attributes": {
    // Core fields (always present)
    "handle": "coinbase",
    "name": "Coinbase",
    "state": "public_mode",
    "submission_state": "open",
    "currency": "usd",
    
    // Bounty configuration
    "offers_bounties": true,
    "allows_bounty_splitting": true,
    "gold_standard_safe_harbor": true,
    
    // Additional fields (discovered)
    "triage_active": null,
    "open_scope": null,
    "fast_payments": null,
    
    // User-specific
    "number_of_reports_for_user": 0,
    "number_of_valid_reports_for_user": 0,
    "bounty_earned_for_user": 0.0,
    "bookmarked": true,
    
    // Policy (full text)
    "policy": "4KB+ of program details..."
  }
}
```

### 4. Structured Scopes Structure

```json
{
  "type": "structured-scope",
  "id": "120",
  "attributes": {
    "asset_type": "URL",
    "asset_identifier": "*.coinbase.com",
    "eligible_for_bounty": true,
    "eligible_for_submission": true,
    "max_severity": "critical",
    
    // CIA Triad
    "confidentiality_requirement": "high",
    "integrity_requirement": "high", 
    "availability_requirement": "high",
    
    "instruction": "Special notes",
    "created_at": "2017-07-20T23:32:30.242Z",
    "updated_at": "2023-01-24T12:35:40.879Z"
  }
}
```

## 🛠️ Implementation

### PostgreSQL Schema
Created comprehensive schema with:
- `programs` table - All program data
- `structured_scopes` table - Asset details
- `program_stats` table - Calculated metrics
- Views for easy querying

### Fetch Script
`/scripts/fetch_all_programs_to_postgres.py`:
- Fetches all 570 programs
- Gets structured scopes for each
- Stores in PostgreSQL
- Updates statistics

### Query Examples

```sql
-- Find critical assets
SELECT p.name, s.asset_identifier
FROM programs p
JOIN structured_scopes s ON p.program_id = s.program_id
WHERE s.max_severity = 'critical'
  AND s.eligible_for_bounty = true;

-- High-value programs
SELECT name, handle
FROM programs
WHERE offers_bounties = true
  AND gold_standard_safe_harbor = true
ORDER BY name;

-- Programs by scope count
SELECT p.name, COUNT(s.id) as scope_count
FROM programs p
LEFT JOIN structured_scopes s ON p.program_id = s.program_id
GROUP BY p.name
ORDER BY scope_count DESC;
```

## 📊 Key Statistics

From our PostgreSQL database:
- **Total Programs**: 570
- **With Structured Scopes**: ~400
- **Total Scope Items**: Thousands
- **Critical Severity Assets**: Hundreds

## 🚀 Best Practices

### 1. Pagination
Always use pagination for large results:
```python
url = f"{BASE_URL}/programs?page[size]=100"
```

### 2. Rate Limiting
Be respectful:
```python
time.sleep(0.5)  # Between requests
```

### 3. Error Handling
Check status codes:
- 200: Success
- 404: Not found (wrong endpoint format)
- 401: Authentication issue
- 429: Rate limited

### 4. Use Filters
More efficient than fetching all:
```python
# Get only bounty programs
url = "/v1/hackers/programs?filter[offers_bounties]=true"
```

## 🔍 What's NOT Available

Despite having good access, we cannot get:
- ❌ Other hackers' reports
- ❌ Program metrics/statistics
- ❌ Weakness categories
- ❌ Member lists
- ❌ Internal program data

## 📂 File Locations

- **Schema**: `/migration/create_hackerone_schema.sql`
- **Fetch Script**: `/scripts/fetch_all_programs_to_postgres.py`
- **Documentation**: `/docs/bb-sites/hackerone/`
- **Program Analyses**: `/docs/bb-sites/hackerone/programs/`

## ✅ Summary

The HACKER API provides:
1. **Complete program list** (570 programs)
2. **Full policy text** for each program
3. **Structured scope details** via separate endpoint
4. **User-specific statistics**
5. **All bounty configuration**

This is sufficient for bug bounty hunting without needing the $15K+ Enterprise API!