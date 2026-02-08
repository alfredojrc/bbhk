# 📊 Program Analysis Guide - Complete Process

**Date**: August 18, 2025  
**Purpose**: How to fetch and analyze any HackerOne program  
**Example**: Fireblocks MPC

---

## Quick Start (30 seconds)

```bash
# Analyze any HackerOne program
python3 scripts/program-analysis/generate_program_analysis.py <program_handle>

# Example: Fireblocks MPC
python3 scripts/program-analysis/generate_program_analysis.py fireblocks_mpc
```

## Complete Process Flow

### 1. Check if Program Exists

```bash
# Search in database
python3 -c "
import psycopg2
conn = psycopg2.connect(host='localhost', database='bbhk_db', 
                        user='bbhk_user', password='<YOUR_DB_PASSWORD>')
cursor = conn.cursor()
cursor.execute(\"SELECT handle, name FROM programs WHERE handle = 'fireblocks_mpc'\")
print(cursor.fetchone())
"
```

### 2. Fetch Program Data (if not in DB)

```bash
# Use the main fetch script
python3 scripts/fetch_all_programs_to_postgres.py

# Or fetch specific program
python3 scripts/fetch_fireblocks_data.py
```

### 3. Generate Analysis and Documentation

```bash
# Run the analysis generator
python3 scripts/program-analysis/generate_program_analysis.py fireblocks_mpc
```

This creates:
- `/docs/bb-sites/hackerone/programs/fireblocks_mpc/` folder
- `COMPLETE-FIREBLOCKS-MPC-DATA.md` - Full analysis
- JSON data files with program details
- ROI scoring and strategic assessment

### 4. Verify Results

Check created files:
```bash
ls -la docs/bb-sites/hackerone/programs/fireblocks_mpc/
```

## What Gets Created

### PostgreSQL Database
- **programs** table: Program details, policy, bounty info
- **structured_scopes** table: Assets, severity, bounty eligibility

### Documentation Files
```
/docs/bb-sites/hackerone/programs/fireblocks_mpc/
├── COMPLETE-FIREBLOCKS-MPC-DATA.md     # Main analysis
├── fireblocks_mpc_program_*.json       # Program data
├── fireblocks_mpc_structured_scopes_*.json  # Scope items
└── fireblocks_mpc_deep_dive_*.json     # ROI analysis
```

## Data Sources

All data comes from **HackerOne HACKER API** (`/v1/hackers/*`):
- `/programs/{handle}` - Basic program info
- `/programs/{handle}/structured_scopes` - Asset details
- `/programs?filter[handle]={handle}&include=policy` - Policy data

**NO FAKE DATA** - Only real API responses with validation

## Scripts Overview

### Core Scripts
1. **`fetch_all_programs_to_postgres.py`** - Fetches all 570 programs
2. **`generate_program_analysis.py`** - Creates analysis for any program
3. **`api_data_validator.py`** - Validates data integrity (no fake content)

### Validation
All data passes through validation to ensure:
- No fake microblogs
- No future dates
- Only real API content

## Example: Fireblocks MPC Results

```markdown
Program: Fireblocks MPC
Handle: @fireblocks_mpc
Assets: 1 (GitHub repository)
Type: SOURCE_CODE
Severity: Critical
ROI Score: 66/115
Bounty: Yes
Gold Standard: Yes
```

## Troubleshooting

### Program Not Found
```bash
# Check exact handle in database
psql -U bbhk_user -d bbhk_db -c "SELECT handle FROM programs WHERE handle ILIKE '%fireblocks%';"
```

### Database Connection Issues
```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Test connection
psql -U bbhk_user -d bbhk_db -h localhost
```

### Missing Dependencies
```bash
pip install psycopg2-binary requests python-dotenv
```

## Process Validation

✅ **Verified Steps**:
1. Program exists in database (fireblocks_mpc)
2. Analysis script works correctly
3. Documentation generated successfully
4. All data from real API (no fake content)
5. Files created in correct location

## Best Practices

1. **Always validate data** - Use `api_data_validator.py`
2. **Check program exists** - Query database first
3. **Use existing frameworks** - Don't create new scripts
4. **Document everything** - Create markdown files
5. **Save JSON backups** - Keep raw API responses

---

## Quick Commands Reference

```bash
# Analyze any program
python3 scripts/program-analysis/generate_program_analysis.py <handle>

# List all programs
psql -U bbhk_user -d bbhk_db -c "SELECT handle, name FROM programs ORDER BY name;"

# Search programs
psql -U bbhk_user -d bbhk_db -c "SELECT handle, name FROM programs WHERE name ILIKE '%search_term%';"

# Fetch fresh data
python3 scripts/fetch_all_programs_to_postgres.py
```

---

**Status**: ✅ Process Validated and Documented  
**Data Source**: HackerOne HACKER API Only  
**Integrity**: 100% Real Data