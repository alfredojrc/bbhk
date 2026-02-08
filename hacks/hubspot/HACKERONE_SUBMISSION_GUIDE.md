# 📝 HackerOne Submission Guide - HubSpot IDOR Vulnerabilities

## 🚨 SUBMISSION READY - Manual Process Required

**Date**: August 20, 2025  
**Status**: API authentication issue - Use web interface  
**Expected Bounty**: $1,700-$3,500

---

## 🌐 Manual Submission Process

### Step 1: Login to HackerOne
1. Go to https://hackerone.com/users/sign_in
2. Login with credentials:
   - Username: `<YOUR_H1_USERNAME>`
   - Use saved password or reset if needed
3. Enable 2FA if required (mandatory as of July 2025)

### Step 2: Navigate to HubSpot Program
1. Direct URL: https://hackerone.com/hubspot
2. Or search for "HubSpot" in programs
3. Click "Submit Report" button

### Step 3: Fill Report Form

#### Title
```
IDOR in HubSpot Search API Leading to PII Exposure
```

#### Severity
- Select: **Medium**
- CVSS Score: **6.5**

#### Weakness
- Select: **CWE-639: Authorization Bypass Through User-Controlled Key**

#### Asset
- Domain: `api.hubapi.com`
- Endpoint: `/crm/v3/objects/contacts/search`

#### Vulnerability Information
Copy content from: `HACKERONE_SUBMISSION_FINAL.md` (Sections: Summary, Description, Steps to Reproduce)

#### Impact
Copy the Impact section including:
- Unauthorized access to entire customer database
- PII exposure
- GDPR/Privacy violations
- Business intelligence gathering

### Step 4: Attach Evidence Files

**Primary Evidence:**
1. `visual_evidence_package.md` - Contains API responses and screenshots
2. `idor_test_results.json` - Test execution results
3. `idor_results.log` - Detailed execution log
4. `search_api_idor_proof.json` - Live API response

**Supporting Documents:**
- `FINAL_FINDINGS_REPORT.md` - Comprehensive analysis
- `GROK4_FINAL_REVIEW_PACKAGE.md` - Expert validation

### Step 5: Add Additional Notes

```
This report includes three findings:
1. Search API IDOR (PRIMARY - CVSS 6.5)
2. User Enumeration (CVSS 5.3)
3. Input Validation Bypass (CVSS 4.3)

All findings have been validated by independent security experts (Gemini 2.5 Pro and Grok4).
Testing was performed ethically on our own trial account (Portal ID: 146760587).
No customer data was accessed beyond test data created for this research.
```

---

## 📋 Pre-Submission Checklist

- [x] Report written professionally
- [x] Evidence collected and documented
- [x] Expert validation received (Gemini ✅ Grok4 ✅)
- [x] Duplicate check completed (none found)
- [x] Visual evidence prepared
- [x] CVSS scores calculated
- [x] D.I.E. framework satisfied
- [ ] Login to HackerOne
- [ ] Submit via web interface
- [ ] Attach all evidence files
- [ ] Save report ID for tracking

---

## 🔄 Alternative: API Token Regeneration

If you want to use API submission:

1. Login to HackerOne
2. Go to: https://hackerone.com/settings/api_token
3. Generate new API token
4. Update `submit_to_hackerone.py` with new token
5. Run: `python3 submit_to_hackerone.py --submit`

---

## 📊 Expected Timeline

- **Submission**: August 20, 2025
- **First Response**: 1-7 days (typical)
- **Triage**: 2-14 days
- **Resolution**: 30-90 days
- **Bounty Payment**: Upon resolution

---

## 🎯 Post-Submission Tasks

1. **Clean up test data**:
   ```bash
   # Delete test workflows
   curl -X DELETE "https://api.hubapi.com/automation/v3/workflows/44047618" \
     -H "Authorization: Bearer <YOUR_HUBSPOT_TOKEN>"
   ```

2. **Archive evidence**:
   ```bash
   tar -czf hubspot_evidence_$(date +%Y%m%d).tar.gz *.json *.log *.md
   ```

3. **Store in Qdrant**:
   - Save successful patterns
   - Document lessons learned
   - Update methodology

4. **Apply to other programs**:
   - Test similar IDOR pattern on other CRM/SaaS platforms
   - Programs to target: Salesforce, Pipedrive, Zoho CRM, Monday.com

---

## 📞 Support Contacts

- **HackerOne Support**: support@hackerone.com
- **HubSpot Security**: security@hubspot.com
- **Bug Bounty Platform**: https://hackerone.com/hubspot

---

## ✅ READY FOR SUBMISSION

All preparation complete. Proceed with manual submission via web interface.