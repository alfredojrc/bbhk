# HackerOne API Exploration Documentation

**Date Started**: 2025-08-17  
**Purpose**: Systematic exploration of HackerOne API capabilities  
**Approach**: Document as we discover, using REAL API data only

---

## 🔧 Available Tools & Resources

### MCP Servers Configured
1. **HackerOne GraphQL MCP** (`hackerone-graphql`)
   - Endpoint: https://hackerone.com/graphql
   - Docker-based server
   - Capabilities: read_programs, read_reports, read_users, read_teams, read_weaknesses, read_scope, query, introspect

2. **Qdrant Vector Database** (`qdrant-bbhk`)
   - Status: Configured but vector model mismatch
   - Purpose: Store and search bug bounty patterns

3. **Other MCPs**: Supabase, Mem0, PerplexityAI

### Existing API Credentials
- **Username**: <YOUR_H1_USERNAME>
- **API Token**: <YOUR_HACKERONE_TOKEN>
- **Base URL**: https://api.hackerone.com/v1
- **Rate Limit**: 600 requests/minute for reads

### Database Resources
- **SQLite DB**: `/home/kali/bbhk/core/database/bbhk.db`
  - Contains 578 programs
  - Tables: programs, targets, campaigns, etc.
- **PostgreSQL**: Available but not primary
- **Qdrant**: Vector database for pattern matching

---

## 📊 Current Data Status

### What We Have
- **578 programs** in database (467 active)
- **459 programs** with detailed HackerOne data
- Program fields captured:
  - Basic: name, handle, state, submission_state
  - Bounty: min_bounty, max_bounty, average_bounty, top_bounty
  - Metrics: response_efficiency_percentage, first_response_time
  - Features: offers_bounties, offers_swag, allows_disclosure
  - Scope: structured_scopes_json, targets

---

## 🔍 API Exploration Sessions

### Session 1: Basic API Discovery
**Date**: 2025-08-17 18:50 UTC

#### Authentication Issues Discovered
- **Initial Token**: <YOUR_HACKERONE_TOKEN> (Returns 401)
- **Environment Token**: <YOUR_HACKERONE_TOKEN> (From .env file)
- **Auth Method**: HTTP Basic Auth (username:token)

#### API Endpoints Structure
Based on code analysis, HackerOne has two different API types:
1. **Organization API** (`/v1/organizations/{org}/*`) - For program owners
2. **Hacker API** (`/v1/hackers/*`) - For bug bounty hunters

Common Hacker endpoints found:
- `/v1/hackers/me` - Get your profile
- `/v1/hackers/programs` - List accessible programs  
- `/v1/hackers/reports` - Your submitted reports
- `/v1/hackers/payments/earnings` - Earnings information
- `/v1/hackers/payments/balance` - Current balance

Let me test with the correct token...

#### Authentication Tests Results
SUCCESS! Found the correct HACKER API endpoint that works:
- ✅ `/v1/hackers/programs` - Returns 200 OK with program data!
- ❌ `/v1/hackers/me` - 401 (needs different auth)
- ❌ `/v1/hackers/reports` - 401 (needs different auth)
- ❌ `/v1/hackers/earnings` - 401 (needs different auth)

**Working Endpoint**: `https://api.hackerone.com/v1/hackers/programs`
**Auth**: Basic Auth with username: <YOUR_H1_USERNAME>, token: <YOUR_HACKERONE_TOKEN>

### Live Programs Retrieved via HACKER API
Successfully fetched **570 programs** from the HACKER API!

#### Sample Programs Retrieved:
1. **HackerOne** (@security) - Allows bounty splitting, gold standard safe harbor
2. **Shopify** (@shopify) - Offers bounties, allows splitting
3. **Netflix** (@netflix) - Major streaming platform
4. **Spotify** (@spotify) - Music streaming giant
5. **Airbnb** (@airbnb) - Travel platform
6. **PayPal** (@paypal) - Payment processor
7. **GitHub** (@github) - Code repository platform
8. **U.S. Dept Of Defense** (@deptofdefense) - Government program
9. **Anthropic (VDP)** (@anthropic-vdp) - AI company VDP
10. **1Password** (@1password) - Password manager

#### Statistics from HACKER API:
- **Total Programs**: 570
- **Data Saved**: `/data/hacker_api_programs_20250817_193331.json`
- **Endpoint Used**: `/v1/hackers/programs` (NOT enterprise API!)
- **Authentication**: Basic Auth (username + API token)

#### Key Program Attributes Available:
- `handle` - Program identifier (e.g., @security)
- `name` - Display name
- `submission_state` - open/closed
- `offers_bounties` - boolean
- `allows_bounty_splitting` - boolean
- `triage_active` - triaging status
- `open_scope` - scope restrictions
- `fast_payments` - payment speed
- `gold_standard_safe_harbor` - legal protection
- `bounty_earned_for_user` - your earnings
- `policy` - full program policy text

---

## 🔧 Qdrant Vector Database Integration

### The Issue
The MCP Qdrant server expects vectors with specific names. Our error:
```
"Wrong input: Vector with name fast-all-minilm-l6-v2 is not configured in this collection"
```

### Solution Applied
Created new collection `bbhk_knowledge` with named vector configuration:
- Vector name: `fast-all-minilm-l6-v2`
- Dimensions: 384 (for all-MiniLM-L6-v2 model)
- Distance metric: Cosine

### How Qdrant MCP Works (from Context7 docs)
1. **Configuration**: Requires environment variables:
   - `QDRANT_URL`: http://localhost:6333
   - `COLLECTION_NAME`: Your collection name
   - `EMBEDDING_MODEL`: sentence-transformers/all-MiniLM-L6-v2

2. **Tools Provided**:
   - `qdrant-store`: Store information with metadata
   - `qdrant-find`: Search using natural language queries

3. **For Claude Code Integration**:
   ```bash
   claude mcp add qdrant \
   -e QDRANT_URL="http://localhost:6333" \
   -e COLLECTION_NAME="bbhk_knowledge" \
   -e EMBEDDING_MODEL="sentence-transformers/all-MiniLM-L6-v2" \
   -- uvx mcp-server-qdrant
   ```

### Current Collections in Our Qdrant
- `hackerone_real_data` - Unnamed vector (384 dims)
- `bbhk-programs` - Unnamed vector
- `bbhk_programs` - Unnamed vector
- `bbhk_vulnerabilities` - Unnamed vector
- `bbhk-project` - Unnamed vector
- `bbhk_knowledge` - **Named vector** (fast-all-minilm-l6-v2)
- `hackerone_api_docs` - Unnamed vector (384 dims)

### Why Named vs Unnamed Vectors Matter
- **Unnamed vectors**: Default, single vector per point
- **Named vectors**: Multiple vectors per point, each with own name
- MCP server expects **named vectors** with specific model name
- Our old collections used **unnamed vectors** causing the error

---

## 📊 Database Exploration

### SQLite Database Analysis

#### Tables Available (20+ tables)
- `programs` - Main program data (578 records)
- `targets` - Program scope targets
- `platforms` - Platform information
- `disclosed_reports` - Public vulnerability reports
- `patterns` - Bug patterns
- `variants` - Pattern variations
- `researcher_queue` - Research tasks
- `program_details`, `program_scope`, `program_bounties` - Extended program info

#### Top Bounty Programs (Max $50,000)
1. Shopify - https://hackerone.com/shopify
2. Spotify - https://hackerone.com/spotify
3. Airbnb - https://hackerone.com/airbnb
4. X / xAI - https://hackerone.com/x
5. Snapchat - https://hackerone.com/snapchat
6. Slack - https://hackerone.com/slack
7. Zendesk - https://hackerone.com/zendesk
8. Stripe - https://hackerone.com/stripe
9. Coinbase - https://hackerone.com/coinbase
10. HackerOne - https://hackerone.com/security

#### Program Table Structure
Key fields captured:
- Basic: `id`, `platform_id`, `program_name`, `program_url`
- Bounty: `min_bounty`, `max_bounty`, `average_bounty`, `top_bounty`
- Metrics: `response_efficiency_percentage`, `first_response_time`, `bug_count`
- Status: `state`, `submission_state`, `active`, `vdp_only`
- Features: `allows_disclosure`, `allows_bounty_splitting`, `offers_swag`
- Extended: `policy`, `website`, `twitter_handle`, `profile_picture`
- JSON fields: `structured_scopes_json`, `weaknesses_json`

---

## 🎯 Key Insights & Next Steps

### What We've Learned
1. **Database is Rich**: We have 578 programs with extensive data already collected
2. **API Authentication Failed**: All tokens return 401 - need new credentials
3. **Qdrant Fixed**: Created proper named vector collection for MCP integration
4. **Top Programs Identified**: Major companies offering up to $50k bounties

### Recommended Actions
1. **Focus on existing data** - We have substantial program data to work with
2. **Fix API authentication** - Need to regenerate HackerOne API tokens
3. **Use Qdrant for pattern matching** - Store vulnerability patterns and search
4. **Explore disclosed reports** - Mine public reports for patterns

### Alternative Approaches
Since API auth is failing, we can:
1. Use the existing 578 programs in database
2. Scrape public HackerOne directory pages
3. Use the GraphQL MCP server (Docker-based)
4. Focus on pattern analysis of existing data

---

## 📝 Summary

We have a robust bug bounty knowledge system with:
- **578 programs** with detailed information
- **SQLite database** with 20+ tables of structured data
- **Qdrant vector database** ready for semantic search
- **Top bounty programs** identified ($50k max)
- **MCP servers** configured (but need auth fixes)

The system is ready for bug bounty research, even without API access!
