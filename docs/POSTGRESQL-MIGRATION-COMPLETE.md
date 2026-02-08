# ✅ PostgreSQL Migration Complete

**Date**: August 17, 2025  
**Status**: OPERATIONAL  
**Database**: PostgreSQL 17.6

## 🎯 What Was Done

### 1. Database Schema Created
- **5 main tables**: programs, structured_scopes, program_attributes, reward_tiers, program_stats
- **2 views**: active_programs, bounty_programs  
- **Indexes** for performance
- **Functions** for statistics

### 2. Data Fetching Script
Created `/scripts/fetch_all_programs_to_postgres.py`:
- Fetches all 570 programs from HACKER API
- For each program, fetches structured scopes
- Stores in PostgreSQL with proper relationships
- Updates statistics automatically

### 3. Old SQLite Cleanup
- Deleted `/core/database/bbhk.db`
- Archived old schema files to `/archive/sqlite-cleanup-aug17/`
- No more SQLite references in active code

## 📊 Database Structure

### Programs Table
```sql
programs
├── program_id (unique HackerOne ID)
├── handle (e.g., "coinbase")
├── name (e.g., "Coinbase")
├── state, submission_state
├── offers_bounties, allows_bounty_splitting
├── gold_standard_safe_harbor
├── policy (full text)
└── user stats (reports, earnings)
```

### Structured Scopes Table
```sql
structured_scopes
├── program_id (foreign key)
├── asset_type (URL, GOOGLE_PLAY_APP_ID, etc.)
├── asset_identifier (*.coinbase.com, etc.)
├── eligible_for_bounty
├── max_severity (critical, high, medium, low)
└── CIA requirements
```

## 🔧 Connection Details

```python
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'bbhk_db',
    'user': 'bbhk_user',
    'password': '<YOUR_DB_PASSWORD>'
}
```

## 📈 Current Status

Running fetch script populates:
- **570 programs** from HackerOne
- **Thousands of scope items**
- **Complete policy text** for each program
- **User-specific statistics**

## 🚀 Usage

### Query Examples

```sql
-- Active bounty programs
SELECT * FROM active_programs 
WHERE offers_bounties = true;

-- High-value programs
SELECT name, handle 
FROM programs p
JOIN structured_scopes s ON p.program_id = s.program_id
WHERE s.max_severity = 'critical'
GROUP BY name, handle;

-- Programs with gold standard
SELECT name, handle 
FROM programs 
WHERE gold_standard_safe_harbor = true;
```

### Python Access

```python
import psycopg2

conn = psycopg2.connect(
    host='localhost',
    database='bbhk_db',
    user='bbhk_user',
    password='<YOUR_DB_PASSWORD>'
)

cursor = conn.cursor()
cursor.execute("SELECT * FROM programs WHERE handle = %s", ('coinbase',))
program = cursor.fetchone()
```

## ✅ Benefits Over SQLite

1. **Concurrent Access** - Multiple processes can read/write
2. **Better Performance** - Optimized for large datasets
3. **Advanced Features** - Views, functions, triggers
4. **Network Access** - Can be accessed remotely
5. **ACID Compliance** - Full transaction support

## 🔗 Related Documentation

- [HackerOne Programs Index](/docs/bb-sites/hackerone/PROGRAMS-INDEX.md)
- [API Reference](/docs/API-REFERENCE.md)
- [Schema SQL](/migration/create_hackerone_schema.sql)