#!/usr/bin/env python3
"""
Check HackerOne Report 3304094 status and submit if in draft
"""

import os
import requests
import json
import base64
from requests.auth import HTTPBasicAuth

# HackerOne Hacker API credentials
USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
REPORT_ID = "3304094"

# API Base URL
BASE_URL = "https://api.hackerone.com"

def get_auth():
    """Get authentication for API requests"""
    return HTTPBasicAuth(USERNAME, API_TOKEN)

def check_report_status():
    """Check the status of report 3304094"""
    print(f"[*] Checking report {REPORT_ID} status...")
    
    # Try different endpoint variations
    endpoints = [
        f"/v1/hackers/me/reports/{REPORT_ID}",
        f"/v1/hackers/reports/{REPORT_ID}",
        f"/v1/reports/{REPORT_ID}"
    ]
    
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    for endpoint in endpoints:
        url = BASE_URL + endpoint
        print(f"[*] Trying endpoint: {endpoint}")
        
        try:
            # Try with basic auth
            response = requests.get(url, auth=get_auth(), headers=headers)
            print(f"    Status Code: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"[+] Report found!")
                print(json.dumps(data, indent=2))
                return data
            elif response.status_code == 404:
                print(f"    Report not found at this endpoint")
            elif response.status_code == 401:
                print(f"    Authentication failed")
                # Try with API token in header
                headers_with_token = headers.copy()
                headers_with_token["Authorization"] = f"Bearer {API_TOKEN}"
                response = requests.get(url, headers=headers_with_token)
                print(f"    Retry with Bearer token - Status: {response.status_code}")
                if response.status_code == 200:
                    data = response.json()
                    print(f"[+] Report found with Bearer auth!")
                    print(json.dumps(data, indent=2))
                    return data
            else:
                print(f"    Error: {response.text}")
                
        except Exception as e:
            print(f"    Exception: {e}")
    
    # Try to list all reports and find ours
    print("\n[*] Trying to list all reports to find ours...")
    url = f"{BASE_URL}/v1/hackers/me/reports"
    params = {
        "page[size]": 100,
        "filter[state][]": ["new", "pending-program-review", "triaged", "needs-more-info", "resolved", "not-applicable", "informative", "duplicate", "spam"]
    }
    
    try:
        response = requests.get(url, auth=get_auth(), headers=headers, params=params)
        print(f"    Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if "data" in data:
                print(f"[*] Found {len(data['data'])} reports")
                for report in data['data']:
                    if report.get('id') == REPORT_ID:
                        print(f"[+] Found report {REPORT_ID}!")
                        print(json.dumps(report, indent=2))
                        return report
                print(f"[-] Report {REPORT_ID} not found in list")
            else:
                print("[!] No data in response")
        else:
            print(f"    Error: {response.text}")
    except Exception as e:
        print(f"    Exception: {e}")
    
    return None

def submit_draft_report(report_data):
    """Submit a draft report"""
    print(f"\n[*] Attempting to submit draft report {REPORT_ID}...")
    
    # Draft reports typically need to be submitted through a different endpoint
    # This varies based on the program and report state
    
    if report_data:
        state = report_data.get('attributes', {}).get('state', 'unknown')
        print(f"[*] Current report state: {state}")
        
        if state == 'new' or state == 'draft':
            print("[!] Report is in draft/new state and needs to be submitted")
            print("[!] Draft reports typically need to be submitted through the web interface")
            print("[!] The API may not support submitting drafts directly")
            return False
        else:
            print(f"[*] Report is already submitted with state: {state}")
            return True
    
    print("[-] Could not determine report state")
    return False

def main():
    print("=" * 60)
    print("HackerOne Report 3304094 Status Checker")
    print("=" * 60)
    
    # Check report status
    report_data = check_report_status()
    
    if report_data:
        # Try to submit if it's a draft
        submit_draft_report(report_data)
    else:
        print(f"\n[-] Could not find report {REPORT_ID}")
        print("\nPossible reasons:")
        print("1. The report ID might be incorrect")
        print("2. The report might be a draft that hasn't been submitted yet")
        print("3. The API credentials might not have access to this report")
        print("4. Draft reports may not be accessible via the API")
        print("\nNote: Draft reports typically need to be submitted through the HackerOne web interface")
        print("Visit: https://hackerone.com/reports/3304094 to submit your draft")

if __name__ == "__main__":
    main()