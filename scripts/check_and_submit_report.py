#!/usr/bin/env python3
"""
Check and Submit HackerOne Draft Report 3304094
Based on our working submission script
"""

import os
import requests
import json

# API Credentials (from our working script)
API_USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"
REPORT_ID = "3304094"

class HackerOneChecker:
    def __init__(self):
        self.auth = (API_USERNAME, API_TOKEN)
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    
    def test_authentication(self):
        """Test if our API credentials work"""
        try:
            response = requests.get(
                f"{BASE_URL}/me",
                auth=self.auth,
                headers={'Accept': 'application/json'}
            )
            if response.status_code == 200:
                print("✅ Authentication successful!")
                data = response.json()
                if 'data' in data:
                    print(f"   Username: {data['data'].get('attributes', {}).get('username', 'Unknown')}")
                return True
            else:
                print(f"❌ Authentication failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
        except Exception as e:
            print(f"❌ Error testing authentication: {e}")
            return False
    
    def check_all_reports(self):
        """List all reports to find our specific one"""
        print(f"\n[*] Checking all reports for ID {REPORT_ID}...")
        
        try:
            # Try to get all reports
            response = requests.get(
                f"{BASE_URL}/me/reports",
                auth=self.auth,
                headers={'Accept': 'application/json'},
                params={'page[size]': 100}
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    print(f"   Found {len(data['data'])} total reports")
                    
                    for report in data['data']:
                        if report.get('id') == REPORT_ID:
                            print(f"\n✅ Found report {REPORT_ID}!")
                            attrs = report.get('attributes', {})
                            print(f"   Title: {attrs.get('title', 'N/A')}")
                            print(f"   State: {attrs.get('state', 'N/A')}")
                            print(f"   Created: {attrs.get('created_at', 'N/A')}")
                            print(f"   Program: {attrs.get('team', {}).get('handle', 'N/A')}")
                            return report
                    
                    print(f"[-] Report {REPORT_ID} not found in your reports list")
                else:
                    print("[-] No reports data in response")
            else:
                print(f"[-] Failed to get reports: {response.status_code}")
                print(f"    Response: {response.text}")
                
        except Exception as e:
            print(f"❌ Error checking reports: {e}")
        
        return None
    
    def check_draft_reports(self):
        """Check specifically for draft/new reports"""
        print(f"\n[*] Checking for draft reports...")
        
        try:
            # Try different state filters
            states = ['new', 'draft', 'pending-program-review']
            
            for state in states:
                response = requests.get(
                    f"{BASE_URL}/me/reports",
                    auth=self.auth,
                    headers={'Accept': 'application/json'},
                    params={
                        'page[size]': 100,
                        'filter[state][]': state
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if 'data' in data and len(data['data']) > 0:
                        print(f"   Found {len(data['data'])} reports in '{state}' state")
                        
                        for report in data['data']:
                            report_id = report.get('id')
                            attrs = report.get('attributes', {})
                            print(f"      ID: {report_id} - {attrs.get('title', 'No title')[:50]}...")
                            
                            if report_id == REPORT_ID:
                                print(f"\n✅ Found report {REPORT_ID} in {state} state!")
                                return report
                
        except Exception as e:
            print(f"❌ Error checking draft reports: {e}")
        
        return None

    def submit_draft_via_web(self):
        """Provide instructions for web submission"""
        print("\n" + "="*60)
        print("DRAFT REPORT SUBMISSION INSTRUCTIONS")
        print("="*60)
        print(f"""
Since report {REPORT_ID} is in draft state, it needs to be submitted via web:

1. Go to: https://hackerone.com/reports/{REPORT_ID}
2. Log in with your HackerOne account (username: {API_USERNAME})
3. Review the draft report
4. Click "Submit Report" button at the bottom
5. Confirm submission

Note: The HackerOne API typically doesn't support submitting drafts that were
created via the web interface. Draft reports must be submitted through the
same interface where they were created.
        """)

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║        HackerOne Report 3304094 Status Checker               ║
║        Check and Submit Draft Report                         ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    checker = HackerOneChecker()
    
    # Step 1: Test authentication
    print("\n[1] Testing API authentication...")
    if not checker.test_authentication():
        print("\n⚠️  Authentication issue - but continuing to check...")
    
    # Step 2: Check all reports
    print("\n[2] Searching for report in all reports...")
    report = checker.check_all_reports()
    
    # Step 3: If not found, check draft reports specifically
    if not report:
        print("\n[3] Checking draft reports specifically...")
        report = checker.check_draft_reports()
    
    # Step 4: Provide submission instructions
    if not report:
        print(f"\n⚠️  Report {REPORT_ID} not found via API")
        print("\nThis could mean:")
        print("1. The report is a web-created draft (not accessible via API)")
        print("2. The report ID is incorrect")
        print("3. The report was already submitted/deleted")
        
    checker.submit_draft_via_web()

if __name__ == "__main__":
    main()