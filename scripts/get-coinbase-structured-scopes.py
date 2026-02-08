#!/usr/bin/env python3
"""
Get Coinbase structured scopes - this endpoint WORKS!
"""

import os
import requests
import json
from datetime import datetime

USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')

def get_structured_scopes():
    """Fetch Coinbase structured scopes"""
    print("🎯 Fetching Coinbase Structured Scopes")
    print("="*60)
    
    auth = (USERNAME, API_TOKEN)
    headers = {'Accept': 'application/json'}
    
    # This endpoint works!
    url = "https://api.hackerone.com/v1/hackers/programs/coinbase/structured_scopes"
    
    print(f"URL: {url}")
    
    try:
        response = requests.get(url, auth=auth, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Check what we got
            if 'data' in data:
                scopes = data.get('data', [])
                print(f"\n✅ SUCCESS - Got {len(scopes)} scope items!")
                
                # Analyze scope structure
                if scopes:
                    print("\n📊 Scope Item Structure:")
                    first_scope = scopes[0]
                    print(f"  Type: {first_scope.get('type')}")
                    print(f"  ID: {first_scope.get('id')}")
                    
                    attrs = first_scope.get('attributes', {})
                    print(f"\n  Attributes available:")
                    for key in attrs.keys():
                        print(f"    • {key}: {attrs[key]}")
                
                # Group by asset type
                asset_types = {}
                for scope in scopes:
                    attrs = scope.get('attributes', {})
                    asset_type = attrs.get('asset_type', 'unknown')
                    if asset_type not in asset_types:
                        asset_types[asset_type] = []
                    asset_types[asset_type].append(attrs)
                
                print("\n📁 Scope by Asset Type:")
                for asset_type, items in asset_types.items():
                    print(f"\n  {asset_type}: {len(items)} items")
                    for item in items[:3]:  # Show first 3
                        asset = item.get('asset_identifier', 'N/A')
                        eligible = item.get('eligible_for_bounty', False)
                        severity = item.get('max_severity', 'N/A')
                        print(f"    • {asset}")
                        print(f"      Bounty: {eligible}, Max Severity: {severity}")
                
                # Save full data
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f'/home/kali/bbhk/docs/bb-sites/hackerone/programs/coinbase/coinbase_structured_scopes_{timestamp}.json'
                
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                
                print(f"\n💾 Full data saved to: {filename}")
                
                return data
            else:
                print(f"Unexpected response structure: {data}")
        else:
            print(f"❌ Error: HTTP {response.status_code}")
            print(f"Response: {response.text[:500]}")
            
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    return None

def get_with_handle_endpoint():
    """Also test the /programs/coinbase endpoint"""
    print("\n🔍 Testing /programs/coinbase endpoint")
    print("="*60)
    
    auth = (USERNAME, API_TOKEN)
    headers = {'Accept': 'application/json'}
    
    url = "https://api.hackerone.com/v1/hackers/programs/coinbase"
    
    try:
        response = requests.get(url, auth=auth, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # This should return the full program data
            if 'data' in data:
                program = data.get('data')
                if isinstance(program, dict):
                    attrs = program.get('attributes', {})
                    print(f"✅ Got program data with {len(attrs)} attributes")
                    
                    # Check for any new fields
                    for key in attrs.keys():
                        if key not in ['handle', 'name', 'state', 'policy']:
                            value = attrs[key]
                            if isinstance(value, str) and len(value) > 50:
                                value = value[:50] + "..."
                            print(f"  • {key}: {value}")
                elif isinstance(program, list):
                    print(f"✅ Got {len(program)} programs (unexpected list)")
            else:
                print("✅ Got response (no 'data' field)")
        else:
            print(f"❌ Status: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    print("="*60)
    print("🚀 COINBASE STRUCTURED SCOPES EXPLORATION")
    print("="*60)
    
    # Get structured scopes
    scopes_data = get_structured_scopes()
    
    # Test handle endpoint
    get_with_handle_endpoint()
    
    if scopes_data:
        print("\n" + "="*60)
        print("✅ EXPLORATION COMPLETE")
        print("="*60)
        print("\nKey Finding: The HACKER API provides access to:")
        print("1. Full program data via /programs/coinbase")
        print("2. Structured scopes via /programs/coinbase/structured_scopes")
        print("3. Filters and includes work on /programs endpoint")

if __name__ == "__main__":
    main()