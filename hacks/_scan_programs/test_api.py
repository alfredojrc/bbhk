#!/usr/bin/env python3
"""
Quick API test to debug program fetching
"""

import json
import os
import requests

API_USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"

auth = (API_USERNAME, API_TOKEN)
headers = {'Accept': 'application/json'}

print("Testing HackerOne API...")

# Fetch first 10 programs
response = requests.get(
    f"{BASE_URL}/programs",
    auth=auth,
    headers=headers,
    params={'page[number]': 1, 'page[size]': 10},
    timeout=30
)

print(f"Status Code: {response.status_code}")

if response.status_code == 200:
    data = response.json()
    programs = data.get('data', [])
    
    print(f"Programs fetched: {len(programs)}")
    
    if programs:
        # Check first program structure
        first = programs[0]
        attrs = first.get('attributes', {})
        
        print("\nFirst program details:")
        print(f"  Handle: {attrs.get('handle')}")
        print(f"  Name: {attrs.get('name')}")
        print(f"  State: {attrs.get('state')}")
        print(f"  Submission State: {attrs.get('submission_state')}")
        print(f"  Offers Bounties: {attrs.get('offers_bounties')}")
        
        # Check how many are open and offer bounties
        open_with_bounties = 0
        for prog in programs:
            attrs = prog.get('attributes', {})
            if (attrs.get('state') == 'open' and 
                attrs.get('submission_state') == 'open' and
                attrs.get('offers_bounties')):
                open_with_bounties += 1
        
        print(f"\nPrograms open with bounties: {open_with_bounties}/{len(programs)}")
        
        # Save sample for inspection
        with open('sample_programs.json', 'w') as f:
            json.dump(programs[:3], f, indent=2)
        print("\nSaved first 3 programs to sample_programs.json for inspection")
else:
    print(f"Error: {response.text}")