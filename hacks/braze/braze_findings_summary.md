# Braze Inc Bug Bounty - Current Findings Summary
## August 21, 2025

### Target Intelligence
- **Program**: Braze Inc (105 days old, only 16 bugs found)
- **Scope**: 3 assets only (manageable scope)
- **Policy**: STRICT - immediate removal for violations

### In-Scope Assets ONLY
1. `bug-bounty-dashboard.k8s.tools-001.d-use-1.braze-dev.com` (Web UI)
2. `bug-bounty-rest.k8s.tools-001.d-use-1.braze-dev.com` (REST API) 
3. `bug-bounty-api.k8s.tools-001.d-use-1.braze-dev.com` (GraphQL)

### Critical Policy Rules
- NO automated scanners (Nuclei forbidden)
- Rate limit: <100 req/s
- Required headers: X-Bug-Bounty: HackerOne-<YOUR_H1_USERNAME>
- Account pattern: <TEST_ACCOUNT_EMAIL>
- Focus: Cross-org vulnerabilities (NOT org-local)

### Technical Findings So Far

#### Dashboard Analysis
- K8s API endpoints (/api/v1, /version, /healthz) → ALL redirect to /sign_in
- Proper authentication controls in place
- No information disclosure through K8s endpoints

#### REST API Discovery  
- Root `/` → 400: "Did you mean to visit the Braze dashboard?" 
- `/api` → 404: {"message":"Invalid URL"}
- `/users` → **401: {"message":"Invalid API key: "}** ⭐ EXISTS, requires auth
- `/events` → **401: {"message":"Invalid API key: "}** ⭐ EXISTS, requires auth  
- Most endpoints → 404 (don't exist)

#### GraphQL API
- `/graphql` with introspection query → 404: {"message":"Invalid URL"}
- May need different endpoint or authentication

### Key Questions for Expert Analysis
1. Are the 401 "Invalid API key" responses legitimate findings or normal behavior?
2. Should I focus on registering accounts immediately to test authenticated endpoints?
3. Is the GraphQL "Invalid URL" worth investigating further or move on?
4. What's the strategic priority: account registration vs more endpoint discovery?
5. Are we on track for finding cross-org IDOR vulnerabilities in /users and /events?

### Next Steps Under Consideration
- Register test accounts at bug-bounty.k8s.tools-001.d-use-1.braze.com
- Get API keys for authenticated testing
- Test /users and /events for IDOR vulnerabilities
- Create multiple orgs for cross-org testing
