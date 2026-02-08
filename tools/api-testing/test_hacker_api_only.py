#!/usr/bin/env python3
"""
HACKER API Test Script - Using FREE Endpoints Only!
Date: August 17, 2025

✅ This script ONLY uses HACKER API endpoints (/v1/hackers/*)
❌ NO Enterprise API endpoints (which cost $15,000+/year)
"""

import os
import requests
import json
from datetime import datetime

# HACKER API Configuration (FREE for bug hunters!)
USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"

def test_hacker_endpoints():
    """Test all available HACKER API endpoints"""
    
    print("=" * 60)
    print("🚀 HackerOne HACKER API Test (FREE Endpoints Only)")
    print("=" * 60)
    print(f"Username: {USERNAME}")
    print(f"Base URL: {BASE_URL}")
    print("-" * 60)
    
    auth = (USERNAME, API_TOKEN)
    headers = {'Accept': 'application/json'}
    
    # Define HACKER API endpoints to test
    endpoints = [
        {
            'name': 'Programs Available to You',
            'url': f'{BASE_URL}/programs',
            'description': '✅ Lists all programs you have access to'
        },
        {
            'name': 'Your Profile',
            'url': f'{BASE_URL}/me',
            'description': '✅ Your hacker profile information'
        },
        {
            'name': 'Your Reports',
            'url': f'{BASE_URL}/reports',
            'description': '✅ Vulnerability reports you submitted'
        },
        {
            'name': 'Your Earnings',
            'url': f'{BASE_URL}/earnings',
            'description': '✅ Your bounty payments and earnings'
        }
    ]
    
    results = []
    
    for endpoint in endpoints:
        print(f"\n📍 Testing: {endpoint['name']}")
        print(f"   URL: {endpoint['url']}")
        print(f"   {endpoint['description']}")
        
        try:
            response = requests.get(
                endpoint['url'],
                auth=auth,
                headers=headers,
                timeout=10
            )
            
            status = response.status_code
            
            if status == 200:
                data = response.json()
                if 'data' in data:
                    count = len(data['data'])
                    print(f"   ✅ SUCCESS - Status: {status}, Items: {count}")
                else:
                    print(f"   ✅ SUCCESS - Status: {status}")
                
                results.append({
                    'endpoint': endpoint['name'],
                    'status': 'SUCCESS',
                    'code': status,
                    'data_count': count if 'data' in data else 'N/A'
                })
            else:
                print(f"   ⚠️  Status: {status}")
                if status == 401:
                    print(f"      Note: May require additional permissions")
                
                results.append({
                    'endpoint': endpoint['name'],
                    'status': 'AUTH_REQUIRED',
                    'code': status
                })
                
        except Exception as e:
            print(f"   ❌ Error: {e}")
            results.append({
                'endpoint': endpoint['name'],
                'status': 'ERROR',
                'error': str(e)
            })
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Summary")
    print("=" * 60)
    
    successful = [r for r in results if r.get('status') == 'SUCCESS']
    auth_required = [r for r in results if r.get('status') == 'AUTH_REQUIRED']
    errors = [r for r in results if r.get('status') == 'ERROR']
    
    print(f"✅ Successful: {len(successful)} endpoints")
    print(f"🔐 Auth Required: {len(auth_required)} endpoints")
    print(f"❌ Errors: {len(errors)} endpoints")
    
    if successful:
        print("\n✅ Working Endpoints:")
        for r in successful:
            print(f"   • {r['endpoint']} - {r.get('data_count', 'N/A')} items")
    
    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'hacker_api_test_{timestamp}.json'
    
    with open(filename, 'w') as f:
        json.dump({
            'timestamp': timestamp,
            'username': USERNAME,
            'results': results,
            'summary': {
                'successful': len(successful),
                'auth_required': len(auth_required),
                'errors': len(errors)
            }
        }, f, indent=2)
    
    print(f"\n💾 Results saved to: {filename}")
    
    # Important reminder
    print("\n" + "⚠️ " * 10)
    print("REMEMBER: Always use HACKER API endpoints (/v1/hackers/*)")
    print("NEVER use Enterprise API endpoints - they cost $15,000+/year!")
    print("⚠️ " * 10)

def verify_no_enterprise_endpoints():
    """Verify we're NOT using any enterprise endpoints"""
    
    print("\n" + "=" * 60)
    print("🔍 Verifying NO Enterprise Endpoints Used")
    print("=" * 60)
    
    # These are WRONG - Enterprise endpoints we should NEVER use
    forbidden_patterns = [
        '/v1/programs',
        '/v1/me',
        '/v1/organizations',
        '/v1/reports',
        '/v1/users'
    ]
    
    # Check our code doesn't contain these
    clean = True
    for pattern in forbidden_patterns:
        if pattern in open(__file__).read():
            # Exception: if it's in this verification function or comments
            if pattern != '/v1/hackers' + pattern.replace('/v1', ''):
                print(f"❌ Found forbidden endpoint: {pattern}")
                clean = False
    
    if clean:
        print("✅ Clean! No enterprise endpoints found in this script")
    
    return clean

if __name__ == "__main__":
    # First verify we're not using enterprise endpoints
    if verify_no_enterprise_endpoints():
        # Then test the HACKER API
        test_hacker_endpoints()
    else:
        print("\n❌ Script contains enterprise endpoints! Aborting.")
        print("Fix the script to use only /v1/hackers/* endpoints")