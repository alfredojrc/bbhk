# 🎯 HubSpot Authenticated Testing - Next Steps

**Account Status**: ✅ ACTIVE  
**Email**: <YOUR_EMAIL>  
**Password**: <YOUR_PASSWORD>  

---

## 🔑 Manual Steps Required to Get API Keys

Since HubSpot blocks automated login, you need to:

### 1. Login Manually to HubSpot
1. Open a real browser (Chrome/Firefox)
2. Go to https://app.hubspot.com/login
3. Enter email: <YOUR_EMAIL>
4. Enter password: <YOUR_PASSWORD>
5. Complete any 2FA or verification

### 2. Generate API Key
1. Once logged in, go to: Settings → Integrations → API Keys
2. Or direct URL: https://app.hubspot.com/settings/[YOUR_PORTAL_ID]/integrations/api-key
3. Click "Create API Key" or "Show" if one exists
4. Copy the API key

### 3. Get Your Portal ID
- Found in the URL after login: app.hubspot.com/contacts/[PORTAL_ID]/
- Or in Settings → Account & Billing

### 4. Save Credentials Here
```bash
HUBSPOT_API_KEY=
HUBSPOT_PORTAL_ID=
HUBSPOT_ACCESS_TOKEN=
```

---

## 🚀 Once You Have API Keys

With valid API credentials, we can test:

### High-Value Vulnerabilities ($2,000-$10,000)

#### 1. IDOR Testing
```bash
# Test cross-object IDOR
curl -X GET "https://api.hubapi.com/crm/v3/objects/contacts/[CONTACT_ID]" \
  -H "Authorization: Bearer [API_KEY]"

# Try accessing other portal's data
curl -X GET "https://api.hubapi.com/crm/v3/objects/companies/[OTHER_PORTAL_COMPANY_ID]" \
  -H "Authorization: Bearer [API_KEY]"
```

#### 2. Privilege Escalation
```bash
# Try to modify user permissions
curl -X PATCH "https://api.hubapi.com/settings/v3/users/[USER_ID]" \
  -H "Authorization: Bearer [API_KEY]" \
  -d '{"role": "super-admin"}'
```

#### 3. Business Logic Flaws
```bash
# Test workflow automation abuse
curl -X POST "https://api.hubapi.com/automation/v3/workflows" \
  -H "Authorization: Bearer [API_KEY]" \
  -d '{"name": "Data Exfiltration", "actions": [...]}'
```

#### 4. OAuth Token Manipulation
```bash
# Test token refresh vulnerabilities
curl -X POST "https://api.hubapi.com/oauth/v1/refresh" \
  -d "refresh_token=[TOKEN]&client_id=[ID]"
```

#### 5. GraphQL Introspection
```bash
# With auth, test deeper GraphQL access
curl -X POST "https://api.hubapi.com/collector/graphql" \
  -H "Authorization: Bearer [API_KEY]" \
  -d '{"query": "{__schema{types{name fields{name}}}}"}'
```

#### 6. CVE-2025-54794 Testing
```python
# Test Claude Connector RCE with auth
python3 /home/kali/bbhk/CVE_2025_54794_POC.py \
  --target https://api.hubspot.com \
  --api-key [YOUR_API_KEY]
```

---

## 📊 Testing Priority

1. **IDOR** - Most common high-value bug
2. **Privilege Escalation** - Critical impact
3. **Business Logic** - Often overlooked
4. **OAuth/Session** - June 2024 incident pattern
5. **GraphQL** - New attack surface
6. **CVE-2025-54794** - If Claude Connector enabled

---

## 🎯 D.I.E. Framework Compliance

For each vulnerability found:

### Demonstrable
- Working PoC script
- Clear reproduction steps
- API request/response pairs

### Impactful
- Data breach potential
- Account takeover risk
- Financial impact

### Evidentiary
- Full HTTP traces
- Screenshots if applicable
- Correlation IDs

---

## 💰 Expected Bounties (Authenticated)

- **Critical RCE**: $5,000-$10,000
- **High IDOR**: $2,000-$5,000
- **Medium Privilege Escalation**: $1,000-$3,000
- **Low Business Logic**: $500-$1,500

---

**Next Action**: Get API keys manually, then we can begin high-value authenticated testing!