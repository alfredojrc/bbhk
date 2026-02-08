#!/usr/bin/env python3
"""
Test HackerOne HACKER API Endpoints
For individual bug bounty hunters, NOT organizations!
"""

import os
import sys
import requests
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime
import json

# Load environment variables
env_path = Path(__file__).parent.parent.parent / '.env'
load_dotenv(env_path)

# Get credentials
USERNAME = os.getenv('HACKERONE_API_USERNAME')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN')

print("="*60)
print("HackerOne HACKER API Test (Not Organization API!)")
print("="*60)
print(f"Timestamp: {datetime.now()}")
print(f"Username: {USERNAME}")
print(f"Token: {API_TOKEN[:10]}..." if API_TOKEN else "Token: NOT SET")
print("")

if not USERNAME or not API_TOKEN:
    print("❌ ERROR: Credentials not found in .env file!")
    sys.exit(1)

# HACKER API endpoints - different from organization endpoints!
hacker_endpoints = [
    {
        'name': 'Hacker Profile (Me)',
        'url': 'https://api.hackerone.com/v1/hackers/me',
        'description': 'Get your hacker profile information'
    },
    {
        'name': 'Hacker Programs',
        'url': 'https://api.hackerone.com/v1/hackers/programs',
        'description': 'List programs you have access to',
        'params': {'page[size]': 5}
    },
    {
        'name': 'Hacker Reports',
        'url': 'https://api.hackerone.com/v1/hackers/reports',
        'description': 'Your submitted vulnerability reports',
        'params': {'page[size]': 5}
    },
    {
        'name': 'Hacker Earnings',
        'url': 'https://api.hackerone.com/v1/hackers/earnings',
        'description': 'Your earnings and payouts'
    },
    {
        'name': 'Public Programs',
        'url': 'https://api.hackerone.com/v1/programs',
        'description': 'Public bug bounty programs',
        'params': {'page[size]': 3}
    },
    {
        'name': 'Hacktivity',
        'url': 'https://api.hackerone.com/v1/hacktivity',
        'description': 'Recent public vulnerability disclosures',
        'params': {'page[size]': 3}
    }
]

# Also try alternative authentication methods
auth_methods = [
    ('Basic Auth (username:token)', (USERNAME, API_TOKEN)),
    ('Basic Auth (token:token)', (API_TOKEN, API_TOKEN)),
    ('Basic Auth (email:token)', (os.getenv('HACKERONE_EMAIL', ''), API_TOKEN))
]

print("Testing HACKER API Endpoints...")
print("-"*60)

success_count = 0

for endpoint in hacker_endpoints:
    print(f"\n📍 Testing: {endpoint['name']}")
    print(f"   URL: {endpoint['url']}")
    print(f"   Purpose: {endpoint['description']}")
    
    # Try different auth methods for first endpoint
    if endpoint['name'] == 'Hacker Profile (Me)':
        for auth_name, auth_creds in auth_methods:
            print(f"\n   Trying {auth_name}...")
            try:
                response = requests.get(
                    endpoint['url'],
                    auth=auth_creds,
                    params=endpoint.get('params', {}),
                    headers={
                        'Accept': 'application/json',
                        'User-Agent': 'BBHK/1.0'
                    },
                    timeout=10
                )
                
                print(f"   Status: {response.status_code}")
                
                if response.status_code == 200:
                    print(f"   ✅ SUCCESS with {auth_name}!")
                    success_count += 1
                    
                    try:
                        data = response.json()
                        # Try to extract useful info
                        if 'data' in data:
                            if isinstance(data['data'], dict):
                                attrs = data['data'].get('attributes', {})
                                print(f"   Username: {attrs.get('username', 'N/A')}")
                                print(f"   Reputation: {attrs.get('reputation', 'N/A')}")
                            elif isinstance(data['data'], list):
                                print(f"   Found {len(data['data'])} items")
                    except:
                        print(f"   Response preview: {response.text[:200]}")
                    break  # Found working auth, skip other methods
                    
                elif response.status_code == 401:
                    print(f"   ❌ Unauthorized with {auth_name}")
                    
            except Exception as e:
                print(f"   ❌ Error with {auth_name}: {str(e)}")
    else:
        # Use the working auth method for other endpoints
        try:
            response = requests.get(
                endpoint['url'],
                auth=(USERNAME, API_TOKEN),  # Use default first
                params=endpoint.get('params', {}),
                headers={
                    'Accept': 'application/json',
                    'User-Agent': 'BBHK/1.0'
                },
                timeout=10
            )
            
            print(f"   Status: {response.status_code}")
            
            if response.status_code == 200:
                print(f"   ✅ SUCCESS!")
                success_count += 1
                
                try:
                    data = response.json()
                    if 'data' in data:
                        if isinstance(data['data'], list):
                            print(f"   Found {len(data['data'])} items")
                            # Show first item if exists
                            if data['data']:
                                first = data['data'][0]
                                if 'attributes' in first:
                                    attrs = first['attributes']
                                    # Show relevant info based on endpoint
                                    if 'title' in attrs:
                                        print(f"   First item: {attrs['title'][:50]}...")
                                    elif 'name' in attrs:
                                        print(f"   First item: {attrs['name']}")
                except:
                    print(f"   Data received but couldn't parse details")
                    
            elif response.status_code == 401:
                print(f"   ❌ UNAUTHORIZED - Token not valid for hacker API")
                print(f"   Response: {response.text[:200]}")
                
            elif response.status_code == 403:
                print(f"   ⚠️  FORBIDDEN - Valid token but no access to this data")
                
            elif response.status_code == 404:
                print(f"   ❓ NOT FOUND - Endpoint might not exist")
                
            elif response.status_code == 429:
                print(f"   ⚠️  RATE LIMITED")
                
        except Exception as e:
            print(f"   ❌ ERROR: {str(e)}")

print("\n" + "="*60)
print("SUMMARY:")
print("="*60)

if success_count > 0:
    print(f"✅ {success_count} endpoints worked!")
    print("\nYour HACKER API access is working!")
    print("You can now use the HackerOne API for:")
    print("  - Fetching program information")
    print("  - Submitting reports")
    print("  - Tracking earnings")
    print("  - Automation workflows")
else:
    print("❌ No endpoints worked with current credentials")
    print("\nPossible issues:")
    print("1. Token might be for organization API, not hacker API")
    print("2. Need to generate token from hacker settings, not org settings")
    print("3. Token might be expired or revoked")
    print("\nTo fix:")
    print("1. Go to: https://hackerone.com/settings/api_token")
    print("2. Generate a NEW token (this will revoke the old one)")
    print("3. Update .env file with new token")
    print("4. Run this test again")

print("\n" + "="*60)
print("Additional debugging info:")
print("="*60)

# Try to access the API root to see if we get any response
print("\nTesting API root endpoint...")
try:
    response = requests.get(
        "https://api.hackerone.com/",
        auth=(USERNAME, API_TOKEN),
        headers={'Accept': 'application/json'},
        timeout=10
    )
    print(f"Root endpoint status: {response.status_code}")
    if response.status_code == 200:
        print("✅ API is reachable and responding")
    print(f"Response: {response.text[:300]}")
except Exception as e:
    print(f"❌ Cannot reach API: {e}")