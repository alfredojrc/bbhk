# ⚡ BBHK Hacker API Reference

## 📁 Program Data Location
Bug bounty program analyses stored at: **[/docs/bb-sites/hackerone/programs/](./bb-sites/hackerone/programs/)**  
Index of all programs: **[PROGRAMS-INDEX.md](./bb-sites/hackerone/PROGRAMS-INDEX.md)**

## Base URL
```
http://localhost:8000
```

## Authentication
No authentication required - simple local access for individual hackers.

## 🔗 Endpoints

### Health Check
```http
GET /health
```
Returns system health status and database connection.

**Response:**
```json
{
  "status": "healthy",
  "database": "connected",
  "programs_count": 578,
  "timestamp": "2025-08-16T15:00:00.000Z"
}
```

### 🎯 Program Discovery Endpoints

#### Find Programs with Bounties
```http
GET /api/programs?has_bounty=true
```
Returns only programs that pay bounties - your money makers!

**Response:**
```json
{
  "programs": [
    {
      "id": 1,
      "program_name": "HackerOne",
      "handle": "security",
      "maximum_bounty": 25000,
      "offers_bounties": true,
      "platform": "hackerone"
    }
  ],
  "total": 243
}
```

#### High-Value Programs
```bash
# Programs paying $10,000+
curl "http://localhost:8000/api/programs?has_bounty=true" | \
jq '.programs[] | select(.maximum_bounty > 10000)'
```

#### Search by Technology
```http
GET /api/search/programs?q=fintech
```
Find programs by keyword, technology, or company type.

**Response:**
```json
{
  "results": [
    {
      "id": 42,
      "program_name": "Coinbase",
      "score": 0.95,
      "maximum_bounty": 50000
    }
  ],
  "count": 12
}
```

### 🛡️ Safe Target Endpoints (CRITICAL!)

#### Get Safe Targets Only
```http
GET /api/programs/{program_id}/scope?scope_type=in_scope
```
**⚠️ CRITICAL**: Only returns IN-SCOPE targets safe for testing.

**Parameters:**
- `program_id` (path, required): Program ID
- `scope_type=in_scope` (query, required): Only safe targets

**Hacker-Friendly Filters:**
- `scope_type=in_scope` - ONLY safe targets (use this!)
- `scope_type=out_of_scope` - Forbidden targets (avoid!)
- `target_type=url` - Web applications
- `target_type=domain` - Domain wildcards

**Response:**
```json
{
  "programs": [
    {
      "id": 1,
      "program_name": "HackerOne",
      "campaign_name": "Security",
      "campaign_status": "active",
      "handle": "security",
      "maximum_bounty": 25000,
      "offers_bounties": true,
      "scope_count": 150
    }
  ],
  "campaign_filter": null,
  "total": 578
}
```

#### Get Program Details
```http
GET /api/programs/{program_id}
```
Returns detailed information about a specific program.

**Parameters:**
- `program_id` (path, required): Program ID

**Response:**
```json
{
  "program": {
    "id": 1,
    "program_name": "HackerOne",
    "campaign_id": 1,
    "details": {
      "handle": "security",
      "policy": "Security policy text...",
      "submission_state": "open",
      "response_efficiency_percentage": 95.5
    },
    "bounties": {
      "minimum_bounty": 500,
      "maximum_bounty": 25000,
      "offers_bounties": true,
      "offers_swag": false
    },
    "scope": {
      "in_scope": 100,
      "out_of_scope": 50
    }
  }
}
```

#### Export Targets for Tools
```bash
# Save safe targets to file for tools
curl "http://localhost:8000/api/programs/123/scope?scope_type=in_scope" | \
jq -r '.scope[].target' > program_123_targets.txt

# Use with subfinder
subfinder -dL program_123_targets.txt -o subdomains.txt

# Use with httpx
cat program_123_targets.txt | httpx -o live_targets.txt
```

**Response with Safety Warnings:**
```json
{
  "program_id": 123,
  "security_warning": "🚨 ONLY test IN-SCOPE targets! Out-of-scope testing is illegal!",
  "scope": [
    {
      "target": "*.example.com",
      "scope_type": "in_scope",
      "eligible_for_bounty": true,
      "safety_status": "✅ SAFE TO TEST"
    }
  ],
  "statistics": {
    "safe_targets": 45,
    "forbidden_targets": 12,
    "warning": "⚠️ 12 targets are OUT-OF-SCOPE and forbidden!"
  }
}
```

### 🔍 Hacker Discovery Tools

#### Find High-Value Programs
```bash
# Programs with $10,000+ bounties
curl "http://localhost:8000/api/programs" | \
jq '.programs[] | select(.maximum_bounty > 10000) | {name: .program_name, bounty: .maximum_bounty}'
```

#### Quick Recon Pipeline
```bash
# Get targets → subfinder → httpx → nuclei
curl -s "http://localhost:8000/api/programs/123/scope?scope_type=in_scope" | \
jq -r '.scope[].target' | \
subfinder -dL stdin | \
httpx | \
nuclei -t cves/
```

#### Scope Validation Check
```http
GET /api/programs/{program_id}/scope?target={domain}
```
Quickly check if a specific domain is in-scope.

**Example:**
```bash
# Check if subdomain is safe to test
curl "http://localhost:8000/api/programs/123/scope?target=api.example.com"
```

**Response:**
```json
{
  "target": "api.example.com",
  "in_scope": true,
  "eligible_for_bounty": true,
  "safety_status": "✅ SAFE TO TEST",
  "warnings": []
}
```

### 🔍 Search Endpoints

#### Search Programs
```http
GET /api/search/programs
```
Search programs with text query.

**Query Parameters:**
- `q` (string, required): Search query
- `limit` (integer, default: 20): Maximum results

**Response:**
```json
{
  "results": [
    {
      "id": 1,
      "program_name": "HackerOne",
      "score": 0.95,
      "campaign_name": "Security"
    }
  ],
  "count": 5
}
```

### 📊 Statistics Endpoints

#### Get Platform Statistics
```http
GET /api/stats
```
Returns overall platform statistics.

**Response:**
```json
{
  "campaigns": {
    "total": 460,
    "active": 450,
    "ending_soon": 5,
    "ended": 3,
    "archived": 2
  },
  "programs": {
    "total": 578,
    "with_bounties": 243,
    "with_swag": 76
  },
  "scope": {
    "total_targets": 40918,
    "in_scope": 35000,
    "out_of_scope": 5918
  },
  "database": {
    "total_records": 42070,
    "campaign_linked": 42070,
    "orphaned": 0
  }
}
```

### 🚦 Response Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request - Invalid parameters |
| 404 | Not Found - Resource doesn't exist |
| 500 | Internal Server Error |
| 503 | Service Unavailable - Database connection issue |

### 📋 Data Models

#### Campaign Object
```typescript
interface Campaign {
  id: number;
  campaign_name: string;
  campaign_type: 'bug_bounty' | 'vdp' | 'private';
  status: 'planned' | 'active' | 'ending_soon' | 'ended' | 'archived';
  lifecycle_stage: string;
  planned_start_date: string;
  planned_end_date: string;
  actual_start_date?: string;
  actual_end_date?: string;
  auto_archive_enabled: boolean;
  archive_delay_days: number;
  priority: 1 | 2 | 3 | 4 | 5;
  tags?: string[];
  external_references?: object;
  created_at: string;
  updated_at: string;
}
```

#### Program Object
```typescript
interface Program {
  id: number;
  campaign_id: number;
  program_name: string;
  program_url?: string;
  min_bounty?: number;
  max_bounty?: number;
  scope_updated?: string;
  allows_disclosure: boolean;
  vdp_only: boolean;
  active: boolean;
  created_at: string;
  updated_at: string;
}
```

#### Scope Target Object
```typescript
interface ScopeTarget {
  id: number;
  program_id: number;
  campaign_id: number;
  scope_type: 'in_scope' | 'out_of_scope';
  target_type: string;
  target: string;
  instruction?: string;
  max_severity?: string;
  eligible_for_bounty: boolean;
  eligible_for_submission: boolean;
}
```

### 🛠️ Examples

#### Get all active campaigns with programs
```bash
curl "http://<YOUR_HOSTNAME>:8000/api/campaigns/summary" | jq '.campaigns[] | select(.status == "active")'
```

#### Get programs for a specific campaign
```bash
curl "http://<YOUR_HOSTNAME>:8000/api/campaigns/1/programs"
```

#### Filter programs with bounties
```bash
curl "http://<YOUR_HOSTNAME>:8000/api/programs?has_bounty=true&limit=10"
```

#### Search for specific programs
```bash
curl "http://<YOUR_HOSTNAME>:8000/api/search/programs?q=hackerone"
```

## 🚀 Hacker Automation Examples

### Script 1: Find Money-Making Programs
```bash
#!/bin/bash
# find-paying-programs.sh

echo "💰 Finding programs that pay bounties..."
curl -s "http://localhost:8000/api/programs?has_bounty=true&limit=20" | \
jq '.programs[] | {name: .program_name, max_bounty: .maximum_bounty, platform: .platform}' | \
jq -s 'sort_by(.max_bounty) | reverse'
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

echo "🎯 Exporting safe targets for program $PROGRAM_ID..."
curl -s "http://localhost:8000/api/programs/$PROGRAM_ID/scope?scope_type=in_scope" | \
jq -r '.scope[].target' > "program_${PROGRAM_ID}_safe_targets.txt"

echo "✅ $(wc -l < program_${PROGRAM_ID}_safe_targets.txt) safe targets exported"
```

### Script 3: Quick Reconnaissance Pipeline
```bash
#!/bin/bash
# quick-recon.sh

PROGRAM_ID=$1
if [ -z "$PROGRAM_ID" ]; then
    echo "Usage: $0 <program_id>"
    exit 1
fi

echo "🚀 Starting recon for program $PROGRAM_ID..."

# Get safe targets
curl -s "http://localhost:8000/api/programs/$PROGRAM_ID/scope?scope_type=in_scope" | \
jq -r '.scope[].target' > targets.txt

echo "🔍 Found $(wc -l < targets.txt) safe targets"

# Subdomain enumeration
echo "🌐 Finding subdomains..."
subfinder -dL targets.txt -silent > subdomains.txt

# HTTP probing
echo "🔗 Probing for live hosts..."
cat subdomains.txt | httpx -silent > live_hosts.txt

# Quick vulnerability scan
echo "🎯 Quick nuclei scan..."
nuclei -l live_hosts.txt -t http/vulnerabilities/ -silent -o findings.txt

echo "✅ Recon complete!"
echo "📊 $(wc -l < live_hosts.txt) live hosts, $(wc -l < findings.txt) potential findings"
```

### Additional Resources

- **Interactive Docs**: http://localhost:8000/docs
- **Quick Start**: [HACKER-QUICKSTART.md](HACKER-QUICKSTART.md)
- **Legal Safety**: [SCOPE-SECURITY-GUIDE.md](SCOPE-SECURITY-GUIDE.md)

**Remember**: Always verify scope before testing! 🛡️