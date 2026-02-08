# 🎯 Braze Inc Bootstrap Hunt - The PERFECT First Target

## Why Braze? (Not Google/Spotify/GitLab!)
- **105 days old** - Brand new program (May 2025)
- **Only 16 bugs found** - Fresh attack surface
- **3 assets only** - Manageable scope
- **$975 avg medium bugs** - Good payouts
- **0% high/critical found** - Opportunity to be first!
- **Test environment** - Safe to experiment

## Program Intelligence
```
Company: Braze Inc (Marketing Automation Platform)
Handle: braze_inc
Age: 105 days (Started May 7, 2025)
Total Paid: $5,850 (very little!)
Reports: 16 resolved, 206 received
Response: 4 hours (excellent!)
Triage: 2 days (very fast!)
Bounty: 1 month (reasonable)
```

## Scope (Only 3 Assets!)
1. **Dashboard**: https://bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com/
2. **REST API**: https://bug-bounty-rest.k8s.tools-001.d-use-1.braze-dev.com/
3. **GraphQL**: https://bug-bounty-api.k8s.tools-001.d-use-1.braze-dev.com/

## Phase 1: Account Setup (1 Hour)
```bash
# 1. Register primary account
Username: <YOUR_H1_USERNAME>
Email: <YOUR_H1_USERNAME>@wearehackerone.com
URL: https://bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com/

# 2. Create additional test accounts
<YOUR_H1_USERNAME>+1@wearehackerone.com
<YOUR_H1_USERNAME>+2@wearehackerone.com
<YOUR_H1_USERNAME>+3@wearehackerone.com

# 3. Use required headers
X-Bug-Bounty: HackerOne-<YOUR_H1_USERNAME>
```

## Phase 2: Initial Reconnaissance (2 Hours)

### 2.1 Dashboard Exploration
```bash
# Start OWASP ZAP
zaproxy &

# Configure ZAP:
1. Set up proxy (localhost:8080)
2. Create context for bug-bounty-*.braze-dev.com
3. Add authentication (session cookies)
4. Import API definitions if available
```

### 2.2 API Discovery
```bash
# GraphQL Introspection
curl -X POST https://bug-bounty-api.k8s.tools-001.d-use-1.braze-dev.com/graphql \
  -H "Content-Type: application/json" \
  -H "X-Bug-Bounty: HackerOne-<YOUR_H1_USERNAME>" \
  -d '{"query": "{__schema{types{name}}}"}'

# REST API Endpoints
# Check their docs: https://www.braze.com/docs/api/basics/
```

### 2.3 Role Mapping
- Create users with different roles
- Document permissions for each role
- Map feature access per role

## Phase 3: Targeted Testing (Day 2)

### 3.1 IDOR Testing (HIGH PRIORITY)
**Why**: They mentioned "horizontal IDOR patterns under remediation"
```python
# Test campaign/user object access
import requests

headers = {
    "X-Bug-Bounty": "HackerOne-<YOUR_H1_USERNAME>",
    "Authorization": "Bearer USER1_TOKEN"
}

# Test accessing other org's campaigns
campaign_ids = [1, 2, 3, 100, 1000, 10000]
for id in campaign_ids:
    r = requests.get(f"https://bug-bounty-rest.k8s.tools-001.d-use-1.braze-dev.com/campaigns/{id}", 
                     headers=headers)
    if r.status_code == 200:
        print(f"[!] Potential IDOR: Campaign {id} accessible")
```

### 3.2 Cross-Org Access (MENTIONED IN SCOPE!)
**Why**: They explicitly say "show cross-org impact to qualify"
```
Test Cases:
1. Create org A with <YOUR_H1_USERNAME>
2. Create org B with <YOUR_H1_USERNAME>+1
3. Try to access Org B data from Org A session
4. Focus on: users, campaigns, templates, API keys
```

### 3.3 GraphQL Security
```graphql
# Test for:
1. Introspection enabled (info disclosure)
2. Query depth attacks
3. Batching attacks
4. Field suggestions leaking data
5. Mutations without proper auth
```

### 3.4 Business Logic Flaws
**Marketing Automation = Complex Logic**
```
Areas to test:
1. Campaign scheduling bypass
2. Email quota manipulation
3. User segment access control
4. Template sharing between orgs
5. Billing/credit manipulation
6. Workflow automation bugs
```

### 3.5 Authorization Testing
```
Test Matrix:
- Admin → User functions
- User → Admin functions  
- Org A → Org B functions
- Unauthenticated → Authenticated functions
```

## Phase 4: Bug Validation (Day 3)

### 4.1 D.I.E. Framework Check
- **Demonstrable**: Create clear PoC
- **Impactful**: Show business impact
- **Evidentiary**: Document all steps

### 4.2 PoC Template for Braze
```markdown
# Title: [IDOR/Cross-Org/Auth] - Specific Issue

## Summary
Brief description of the vulnerability

## Steps to Reproduce
1. Create account at bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com
2. [Detailed steps with exact URLs and parameters]
3. Observe unauthorized access/action

## Impact
- Access to other organizations' data
- Ability to modify campaigns across orgs
- [Specific business impact]

## Supporting Evidence
[Screenshots, request/response pairs, video if needed]

## Suggested Fix
[Optional but shows professionalism]
```

## Phase 5: Submission Strategy

### 5.1 What NOT to Report (Per Their Rules)
- Tags feature bugs (explicitly out of scope)
- Org-local data exposure only
- Dashboard breakage in your own org
- Editor XSS that doesn't reach dashboard
- Rate limiting on dev cluster

### 5.2 What TO Report
- Cross-org data access ✓
- IDOR affecting multiple orgs ✓
- Business logic with financial impact ✓
- Authorization bypasses ✓
- API security issues ✓

## Expected Outcomes

### Realistic (Based on Stats)
- **2-3 Low Bugs**: $600-900 total
- **1-2 Medium Bugs**: $975-1,950 total
- **Total Expected**: $1,500-2,850

### Best Case
- **1 High Bug** (first one!): $1,500-2,500
- **Multiple Mediums**: $2,000-3,000
- **Total Possible**: $3,500-5,500

## Tools & Resources

### Required
- OWASP ZAP (free, already installed)
- Python for scripting
- curl for API testing

### Documentation
- User Docs: https://www.braze.com/docs/
- API Docs: https://www.braze.com/docs/api/basics/
- Role Management: https://www.braze.com/docs/user_guide/administrative/

## Success Metrics
- **Minimum**: 1 valid bug ($300)
- **Target**: 2-3 bugs ($1,500-2,000)
- **Stretch**: First high/critical ($2,500+)

## Timeline
- **Hour 1**: Account setup
- **Hours 2-3**: Reconnaissance
- **Hours 4-8**: Active testing (Day 2)
- **Hours 9-12**: PoC development & submission (Day 3)
- **Total**: 12 hours maximum investment

## Why This Will Work
1. **Fresh program** - Basic bugs still present
2. **Marketing platform** - Complex business logic
3. **Only 38 hackers** - Low competition
4. **Test environment** - Safe to experiment
5. **Clear scope** - Know exactly what to test
6. **Fast response** - 4 hours to first response

## Next Steps
1. Create Braze account NOW
2. Start with IDOR testing (likely present)
3. Focus on cross-org access (they want this)
4. Document everything
5. Submit via HackerOne

---

**Remember**: This is a BRAND NEW program with only 16 bugs found. The easy stuff is still there!