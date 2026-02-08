#!/usr/bin/env python3
"""
Attach Evidence Files to HackerOne Report via API
Report ID: 3306949
Date: August 20, 2025
"""

import requests
import json
import base64
import os
from typing import Dict, List

# API Credentials (confirmed working)
API_USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"
REPORT_ID = "3306949"

class HackerOneFileAttacher:
    def __init__(self):
        self.auth = (API_USERNAME, API_TOKEN)
        self.headers = {
            'Accept': 'application/json'
        }
        self.files_to_attach = [
            "visual_evidence_package.md",
            "idor_test_results.json",
            "idor_results.log",
            "search_api_idor_proof.json"
        ]
    
    def add_comment_with_attachments(self):
        """
        Add a comment with attachments to the report
        Based on 2021 API update for attachment uploads
        """
        print(f"\n📎 Attempting to attach files to report {REPORT_ID}...")
        
        # Prepare comment
        comment_text = """Evidence files attached demonstrating the vulnerabilities:

1. **visual_evidence_package.md** - Contains API responses showing PII exposure
2. **idor_test_results.json** - Test execution summary with timestamps
3. **idor_results.log** - Detailed execution log showing all test attempts
4. **search_api_idor_proof.json** - Live API response with 10+ contacts exposed

All testing was performed ethically on our own trial account (Portal ID: 146760587)."""
        
        # Try different endpoint patterns based on common API conventions
        endpoints_to_try = [
            f"{BASE_URL}/reports/{REPORT_ID}/comments",
            f"{BASE_URL}/reports/{REPORT_ID}/activities",
            f"{BASE_URL}/reports/{REPORT_ID}/attachments",
            f"https://api.hackerone.com/v1/reports/{REPORT_ID}/comments"
        ]
        
        for endpoint in endpoints_to_try:
            print(f"\n🔍 Trying endpoint: {endpoint}")
            
            # Prepare multipart form data
            files = []
            for filename in self.files_to_attach:
                if os.path.exists(filename):
                    with open(filename, 'rb') as f:
                        file_content = f.read()
                        files.append(('attachments[]', (filename, file_content, 'application/octet-stream')))
            
            # Prepare the data
            data = {
                'data': json.dumps({
                    'type': 'activity-comment',
                    'attributes': {
                        'message': comment_text,
                        'internal': False
                    }
                })
            }
            
            try:
                # Try multipart upload
                response = requests.post(
                    endpoint,
                    auth=self.auth,
                    data=data,
                    files=files
                )
                
                print(f"   Response Code: {response.status_code}")
                
                if response.status_code in [200, 201]:
                    print(f"✅ Successfully attached files via {endpoint}!")
                    return True
                elif response.status_code == 404:
                    print(f"   Endpoint not found")
                elif response.status_code == 403:
                    print(f"   Forbidden - may need different permissions")
                else:
                    print(f"   Response: {response.text[:200]}")
                    
            except Exception as e:
                print(f"   Error: {e}")
        
        return False
    
    def try_alternative_attachment_method(self):
        """
        Try alternative methods based on API patterns
        """
        print("\n🔄 Trying alternative attachment methods...")
        
        # Method 1: Try to update report with attachments
        report_update_url = f"{BASE_URL}/reports/{REPORT_ID}"
        
        # Prepare file data as base64
        attachments_data = []
        for filename in self.files_to_attach:
            if os.path.exists(filename):
                with open(filename, 'rb') as f:
                    file_content = f.read()
                    base64_content = base64.b64encode(file_content).decode('utf-8')
                    attachments_data.append({
                        'filename': filename,
                        'content': base64_content,
                        'content_type': 'text/plain' if filename.endswith('.md') or filename.endswith('.log') else 'application/json'
                    })
        
        # Try PATCH to update report
        update_data = {
            'data': {
                'type': 'report',
                'attributes': {
                    'attachments': attachments_data
                }
            }
        }
        
        try:
            response = requests.patch(
                report_update_url,
                auth=self.auth,
                headers={'Content-Type': 'application/json'},
                json=update_data
            )
            
            print(f"PATCH Response: {response.status_code}")
            if response.status_code in [200, 201]:
                print("✅ Files attached via report update!")
                return True
                
        except Exception as e:
            print(f"Error with PATCH: {e}")
        
        return False
    
    def verify_files_exist(self):
        """Verify all evidence files exist"""
        print("\n📂 Verifying evidence files...")
        all_exist = True
        
        for filename in self.files_to_attach:
            if os.path.exists(filename):
                size = os.path.getsize(filename)
                print(f"   ✅ {filename} ({size} bytes)")
            else:
                print(f"   ❌ {filename} NOT FOUND")
                all_exist = False
        
        return all_exist
    
    def provide_manual_instructions(self):
        """Provide manual upload instructions"""
        print("\n" + "="*60)
        print("📋 MANUAL ATTACHMENT INSTRUCTIONS")
        print("="*60)
        print(f"""
Since API attachment might not be supported for the Hacker API,
please attach files manually:

1. Go to: https://hackerone.com/reports/{REPORT_ID}
2. Login with your credentials
3. Look for "Add attachments" or paperclip icon
4. Upload these files:
   - visual_evidence_package.md
   - idor_test_results.json
   - idor_results.log
   - search_api_idor_proof.json
5. Add comment: "Evidence files demonstrating the vulnerabilities"

The report is submitted and triagers can see it, but attaching
evidence will speed up the validation process.
        """)

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║        HackerOne File Attachment Tool                        ║
║        Report: 3306949 (HubSpot IDOR)                       ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    attacher = HackerOneFileAttacher()
    
    # Step 1: Verify files exist
    if not attacher.verify_files_exist():
        print("\n❌ Some files are missing. Cannot proceed.")
        return
    
    # Step 2: Try to attach via API
    success = attacher.add_comment_with_attachments()
    
    if not success:
        # Try alternative method
        success = attacher.try_alternative_attachment_method()
    
    if not success:
        # Provide manual instructions
        attacher.provide_manual_instructions()
        print("\n⚠️  API attachment appears to not be fully supported for Hacker API")
        print("    This is a known limitation - files must be attached manually")
        print("    Your report #3306949 is submitted and will be triaged!")
    else:
        print(f"\n✅ Files successfully attached to report {REPORT_ID}!")
        print(f"    View at: https://hackerone.com/reports/{REPORT_ID}")

if __name__ == "__main__":
    main()