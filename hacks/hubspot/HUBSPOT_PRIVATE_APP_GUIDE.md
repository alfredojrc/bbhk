# 🔑 HubSpot Private App Setup Guide (2025)

## ⚠️ CRITICAL UPDATE: API Keys Are DEPRECATED!

**As of November 30, 2022, HubSpot API Keys no longer exist!**  
You must use **Private Apps** for API access instead.

---

## 📋 Step-by-Step: Create Private App for <YOUR_EMAIL>

### 1. Login to HubSpot
- URL: https://app.hubspot.com/login
- Email: <YOUR_EMAIL>
- Password: <YOUR_PASSWORD>

### 2. Navigate to Private Apps
```
Settings (⚙️ icon) → Integrations → Private Apps
```

### 3. Create Private App
1. Click **"Create a private app"**
2. **Basic Info Tab**:
   - Name: `Security Testing App`
   - Description: `Bug bounty testing per HackerOne policy`

### 4. Set Scopes (Permissions)
Go to **"Scopes"** tab and enable these for comprehensive testing:

#### CRM Scopes (Essential for IDOR testing)
- ✅ crm.objects.contacts.read
- ✅ crm.objects.contacts.write
- ✅ crm.objects.companies.read
- ✅ crm.objects.companies.write
- ✅ crm.objects.deals.read
- ✅ crm.objects.deals.write
- ✅ crm.objects.owners.read

#### Settings Scopes (For privilege escalation testing)
- ✅ settings.users.read
- ✅ settings.users.write (if available)
- ✅ settings.users.teams.read
- ✅ settings.users.teams.write

#### Forms & Marketing (For business logic testing)
- ✅ forms
- ✅ forms-uploaded-files
- ✅ marketing-events

#### Files & Content
- ✅ files
- ✅ files.ui_hidden.read

#### Automation & Workflows
- ✅ automation
- ✅ business-intelligence
- ✅ integration-sync

### 5. Create and Get Token
1. Click **"Create app"** button (top right)
2. Review and confirm
3. Click **"Show token"** to reveal your access token
4. **COPY THE TOKEN IMMEDIATELY** - You can only view it once!

---

## 🔐 Your Access Token

Once created, save here:
```bash
HUBSPOT_ACCESS_TOKEN=[YOUR_TOKEN_HERE]
HUBSPOT_PORTAL_ID=[Found in URL: app.hubspot.com/contacts/XXXXX/]
```

---

## 🧪 Test Your Token

```bash
# Test basic access
curl -X GET "https://api.hubapi.com/crm/v3/objects/contacts" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json"

# Should return contacts list or empty array
```

---

## 🎯 High-Value Testing with Private App Token

### 1. IDOR Testing ($2,000-$5,000)
```bash
# Test cross-object reference
curl -X GET "https://api.hubapi.com/crm/v3/objects/contacts/12345" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Try accessing another portal's data
curl -X GET "https://api.hubapi.com/crm/v3/objects/companies/99999" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 2. Privilege Escalation ($1,000-$3,000)
```bash
# Try to modify user permissions
curl -X PATCH "https://api.hubapi.com/settings/v3/users/USER_ID" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"roleId": "super-admin"}'
```

### 3. Business Logic Flaws ($500-$2,000)
```bash
# Test workflow manipulation
curl -X POST "https://api.hubapi.com/automation/v4/actions/callbacks/complete" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"callbackId": "OTHER_PORTAL_CALLBACK"}'
```

### 4. GraphQL with Authentication
```bash
# Now with auth, test deeper introspection
curl -X POST "https://api.hubapi.com/collector/graphql" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{__schema{types{name fields{name description}}}}"}'
```

### 5. OAuth Token Security
```bash
# Test token scope escalation
curl -X POST "https://api.hubapi.com/oauth/v1/refresh" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "YOUR_TOKEN", "grant_type": "refresh_token", "scope": "oauth contacts forms-uploaded-files"}'
```

---

## ⚠️ Security Notes

### What Changed from API Keys
- **Old**: `?hapikey=YOUR_KEY` in URL
- **New**: `Authorization: Bearer YOUR_TOKEN` in headers
- **Better**: Scoped permissions, more secure

### Token Security
- Tokens don't expire (unlike OAuth)
- Can be revoked anytime
- Each integration gets its own token
- Granular permission control

### Rate Limits
- 100 requests per 10 seconds
- 250,000 requests per day
- Use batch endpoints when possible

---

## 🚨 If Token Creation Fails

### Common Issues:
1. **No Private Apps option**: Need Super Admin permissions
2. **Scopes missing**: Some scopes require paid plans
3. **Trial limitations**: Some features restricted in trials

### Alternative: OAuth App (More Complex)
If Private Apps don't work, create an OAuth app:
1. Go to https://developers.hubspot.com
2. Create developer account
3. Create public app
4. Use OAuth flow for token

---

## 📊 Expected Results

With proper token and scopes, you should be able to:
- ✅ Access all CRM objects
- ✅ Test cross-portal access (IDOR)
- ✅ Attempt privilege escalation
- ✅ Manipulate workflows
- ✅ Access GraphQL endpoints
- ✅ Test business logic flaws

---

## 💰 Bounty Potential

With authenticated access via Private App:
- **Critical**: $5,000-$10,000 (RCE, data breach)
- **High**: $2,000-$5,000 (IDOR, privilege escalation)
- **Medium**: $500-$2,000 (business logic, info disclosure)
- **Low**: $100-$500 (minor issues)

---

**NEXT ACTION**: Login to HubSpot and create Private App to get access token!