# 📎 DELIVERABLES - Files to Upload to HackerOne

## Report Information
- **Report ID**: 3306949
- **URL**: https://hackerone.com/reports/3306949
- **Status**: Submitted via API, awaiting file attachments

---

## 📁 Files to Upload (4 files)

### 1. `visual_evidence_package.md` (3.3 KB)
**Description**: Contains API responses and visual proof of vulnerabilities
- Shows actual API responses with PII
- Includes execution timeline
- Documents duplicate check results

### 2. `idor_test_results.json` (330 bytes)
**Description**: Test execution summary in JSON format
- Timestamp of testing
- Tests executed
- Vulnerabilities found
- Token used (redacted)

### 3. `idor_results.log` (2.3 KB)
**Description**: Detailed execution log
- Shows all 6 IDOR tests performed
- Contains actual contact data found
- Proves Search API IDOR vulnerability
- Shows 10+ contacts exposed

### 4. `search_api_idor_proof.json` (2.3 KB)
**Description**: Live API response demonstrating the vulnerability
- Full JSON response from Search API
- Shows contact IDs and emails
- Includes Maria Johnson and Brian Halligan contacts
- Proves unauthorized access to PII

---

## 📤 How to Upload

1. **Go to Report**: https://hackerone.com/reports/3306949

2. **Login** with your HackerOne credentials

3. **Find Attachment Option**:
   - Look for "Add attachments" button
   - Or find paperclip icon 📎
   - Or "Upload files" option

4. **Select All 4 Files**:
   - Browse to this folder: `/home/kali/bbhk/hacks/hubspot/deliverables/`
   - Select all 4 files
   - Upload them together

5. **Add Comment** (optional but recommended):
   ```
   Evidence files attached demonstrating the vulnerabilities:
   - API responses showing PII exposure
   - Test execution logs with timestamps
   - JSON proof of unauthorized data access
   
   All testing performed ethically on our trial account (Portal ID: 146760587)
   ```

---

## ⏰ Upload Timeline

**URGENT**: Upload these files as soon as possible!
- Files provide critical evidence for triage
- Speeds up validation process
- Supports bounty amount justification
- Shows professionalism

---

## ✅ Checklist

- [ ] Navigate to https://hackerone.com/reports/3306949
- [ ] Login to HackerOne
- [ ] Upload `visual_evidence_package.md`
- [ ] Upload `idor_test_results.json`
- [ ] Upload `idor_results.log`
- [ ] Upload `search_api_idor_proof.json`
- [ ] Add explanatory comment
- [ ] Confirm uploads successful

---

## 📊 Expected Impact

Uploading these files will:
- **Validate** the IDOR vulnerability claim
- **Prove** access to 10+ contacts with PII
- **Support** $1,700-$3,500 bounty expectation
- **Accelerate** triage process

---

**Created**: August 20, 2025
**Purpose**: Manual upload to HackerOne Report #3306949
**Location**: `/home/kali/bbhk/hacks/hubspot/deliverables/`