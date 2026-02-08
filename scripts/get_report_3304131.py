#!/usr/bin/env python3
import os
import os
"""
Retrieve HackerOne Report 3304131 via API
"""

import requests
import json
from requests.auth import HTTPBasicAuth

# HackerOne Hacker API credentials
USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
REPORT_ID = "3304131"

# API Base URL
BASE_URL = "https://api.hackerone.com"

def get_auth():
    """Get authentication for API requests"""
    return HTTPBasicAuth(USERNAME, API_TOKEN)

def get_report():
    """Retrieve report 3304131"""
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
            response = requests.get(url, auth=get_auth(), headers=headers, timeout=30)
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
    print("\n[*] Trying to list all reports to find #3304131...")
    url = f"{BASE_URL}/v1/hackers/me/reports"
    params = {
        "page[size]": 100,
        "filter[state][]": ["new", "pending-program-review", "triaged", "needs-more-info", 
                          "resolved", "not-applicable", "informative", "duplicate", "spam"]
    }
    
    try:
        response = requests.get(url, auth=get_auth(), headers=headers, params=params, timeout=30)
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
        relationships = report_data.get('relationships', {})
        
        # Get program info
        program_data = relationships.get('program', {}).get('data', {})
        program_handle = program_data.get('attributes', {}).get('handle', 'N/A')
        
        # Get severity info
        severity_data = relationships.get('severity', {}).get('data', {})
        severity_rating = severity_data.get('attributes', {}).get('rating', 'N/A')
        
        # Get activities/comments
        activities = relationships.get('activities', {}).get('data', [])
        comments = []
        for activity in activities:
            if activity.get('type') == 'activity-comment':
                message = activity.get('attributes', {}).get('message', '')
                actor = activity.get('relationships', {}).get('actor', {}).get('data', {})
                actor_name = actor.get('attributes', {}).get('username', 'Unknown')
                created = activity.get('attributes', {}).get('created_at', '')
                comments.append(f"**{actor_name}** ({created}):\n{message}\n")
        
        markdown_content = f"""# HackerOne Report #{REPORT_ID}

## Report Details
- **Title**: {attrs.get('title', 'N/A')}
- **State**: {attrs.get('state', 'N/A')}
- **Created**: {attrs.get('created_at', 'N/A')}
- **Last Activity**: {attrs.get('last_reporter_activity_at', 'N/A')}
- **Severity**: {severity_rating}
- **Program**: {program_handle}
- **Triaged**: {attrs.get('triaged_at', 'Not yet')}
- **Closed**: {attrs.get('closed_at', 'Not closed')}

## Vulnerability Description
{attrs.get('vulnerability_information', 'No description available')}

## Impact
{attrs.get('impact', 'No impact statement available')}

## Steps to Reproduce
{attrs.get('steps_to_reproduce', 'No steps available')}

## Supporting Material
{attrs.get('supporting_material', 'No supporting material')}

## Activity Timeline
{"".join(comments) if comments else "No comments yet"}

## CVE IDs
{', '.join(attrs.get('cve_ids', [])) if attrs.get('cve_ids') else 'None'}
"""
        
        with open(f'report_{REPORT_ID}_analysis.md', 'w') as f:
            f.write(markdown_content)
        print(f"[+] Saved report analysis to report_{REPORT_ID}_analysis.md")
        
        # Print summary
        print("\n" + "="*60)
        print("REPORT SUMMARY:")
        print("="*60)
        print(f"Title: {attrs.get('title', 'N/A')}")
        print(f"State: {attrs.get('state', 'N/A')}")
        print(f"Program: {program_handle}")
        print(f"Severity: {severity_rating}")
        print(f"Created: {attrs.get('created_at', 'N/A')}")
        print(f"Triaged: {attrs.get('triaged_at', 'Not yet')}")
        
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
    else:
        print(f"\n[-] Could not retrieve report {REPORT_ID}")
        print("\nPossible reasons:")
        print("1. The report might be in draft state (not accessible via API)")
        print("2. The report ID might be incorrect")
        print("3. The report might not exist yet")
        print("4. API credentials might need refresh")

if __name__ == "__main__":
    main()