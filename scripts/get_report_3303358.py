#!/usr/bin/env python3
import os
import os
"""
Retrieve HackerOne Report 3303358 for unbiased review
"""

import requests
import json
from requests.auth import HTTPBasicAuth

# HackerOne Hacker API credentials
USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
REPORT_ID = "3303358"

# API Base URL
BASE_URL = "https://api.hackerone.com"

def get_auth():
    """Get authentication for API requests"""
    return HTTPBasicAuth(USERNAME, API_TOKEN)

def get_report():
    """Retrieve report 3303358"""
    print(f"[*] Retrieving report {REPORT_ID}...")
    
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
            response = requests.get(url, auth=get_auth(), headers=headers)
            print(f"    Status Code: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"[+] Report found!")
                return data
            elif response.status_code == 404:
                print(f"    Report not found at this endpoint")
            elif response.status_code == 401:
                print(f"    Authentication failed")
            else:
                print(f"    Error: {response.text[:200]}")
                
        except Exception as e:
            print(f"    Exception: {e}")
    
    # Try to list all reports and find ours
    print("\n[*] Trying to list all reports to find #3303358...")
    url = f"{BASE_URL}/v1/hackers/me/reports"
    params = {
        "page[size]": 100,
        "filter[state][]": ["new", "pending-program-review", "triaged", "needs-more-info", 
                          "resolved", "not-applicable", "informative", "duplicate", "spam"]
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
                        return report
                print(f"[-] Report {REPORT_ID} not found in list")
            else:
                print("[!] No data in response")
        else:
            print(f"    Error: {response.text[:200]}")
    except Exception as e:
        print(f"    Exception: {e}")
    
    return None

def save_report(report_data):
    """Save report to file for analysis"""
    if report_data:
        # Save full JSON
        with open(f'report_{REPORT_ID}.json', 'w') as f:
            json.dump(report_data, f, indent=2)
        print(f"[+] Saved full report to report_{REPORT_ID}.json")
        
        # Extract key details for markdown
        attrs = report_data.get('attributes', {})
        
        markdown_content = f"""# HackerOne Report #{REPORT_ID} - For Unbiased Review

## Report Details
- **Title**: {attrs.get('title', 'N/A')}
- **State**: {attrs.get('state', 'N/A')}
- **Created**: {attrs.get('created_at', 'N/A')}
- **Severity**: {attrs.get('severity_rating', 'N/A')}
- **Program**: {report_data.get('relationships', {}).get('program', {}).get('data', {}).get('attributes', {}).get('handle', 'N/A')}

## Vulnerability Description
{attrs.get('vulnerability_information', 'No description available')}

## Impact
{attrs.get('impact', 'No impact statement available')}

## Steps to Reproduce
{attrs.get('steps_to_reproduce', 'No steps available')}

## Supporting Material
{attrs.get('supporting_material', 'No supporting material')}
"""
        
        with open(f'report_{REPORT_ID}_for_review.md', 'w') as f:
            f.write(markdown_content)
        print(f"[+] Saved report summary to report_{REPORT_ID}_for_review.md")
        
        return markdown_content
    return None

def main():
    print("=" * 60)
    print(f"HackerOne Report {REPORT_ID} Retrieval")
    print("=" * 60)
    
    # Get report
    report_data = get_report()
    
    if report_data:
        markdown = save_report(report_data)
        if markdown:
            print("\n" + "="*60)
            print("REPORT CONTENT FOR REVIEW:")
            print("="*60)
            print(markdown)
    else:
        print(f"\n[-] Could not retrieve report {REPORT_ID}")
        print("\nPossible reasons:")
        print("1. The report might be in draft state (not accessible via API)")
        print("2. The API credentials might need to be refreshed")
        print("3. The report ID might be incorrect")
        print("\nTrying alternative: Check if we need a new API token...")

if __name__ == "__main__":
    main()