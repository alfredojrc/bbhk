#!/usr/bin/env python3
"""
Deep dive into Coinbase - explore ALL available data from HACKER API
"""

import os
import requests
import json
import re
from datetime import datetime

USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"

def test_program_specific_endpoints():
    """Test if we can access program-specific endpoints"""
    print("🔍 Testing Program-Specific Endpoints")
    print("="*60)
    
    auth = (USERNAME, API_TOKEN)
    headers = {'Accept': 'application/json'}
    
    # Coinbase program ID is 104, handle is "coinbase"
    endpoints_to_test = [
        # Try different endpoint patterns
        f"{BASE_URL}/programs/104",
        f"{BASE_URL}/programs/coinbase",
        f"{BASE_URL}/programs?filter[handle]=coinbase",
        f"{BASE_URL}/programs?filter[id]=104",
        f"{BASE_URL}/programs?page[size]=100&filter[bookmarked]=true",
        
        # Try to get more details
        f"{BASE_URL}/programs/104/structured_scopes",
        f"{BASE_URL}/programs/coinbase/structured_scopes",
        f"{BASE_URL}/programs/104/weaknesses",
        f"{BASE_URL}/programs/104/metrics",
        
        # Try relationships
        f"{BASE_URL}/programs/104/relationships",
        f"{BASE_URL}/programs/104/members",
        
        # Try includes
        f"{BASE_URL}/programs?filter[handle]=coinbase&include=structured_scopes",
        f"{BASE_URL}/programs?filter[handle]=coinbase&include=weaknesses",
    ]
    
    results = []
    for endpoint in endpoints_to_test:
        print(f"\nTesting: {endpoint}")
        try:
            response = requests.get(endpoint, auth=auth, headers=headers, timeout=10)
            status = response.status_code
            
            if status == 200:
                data = response.json()
                # Check what we got
                if 'data' in data:
                    if isinstance(data['data'], list):
                        print(f"  ✅ SUCCESS - Got {len(data['data'])} items")
                    else:
                        print(f"  ✅ SUCCESS - Got single item")
                    results.append((endpoint, "SUCCESS", data))
                else:
                    print(f"  ✅ SUCCESS - Got response")
                    results.append((endpoint, "SUCCESS", data))
            else:
                print(f"  ❌ Status: {status}")
                results.append((endpoint, f"HTTP {status}", None))
                
        except Exception as e:
            print(f"  ❌ Error: {e}")
            results.append((endpoint, "ERROR", None))
    
    return results

def extract_all_scope_from_policy(policy_text):
    """Extract ALL scope information from policy text"""
    print("\n📋 Extracting Complete Scope from Policy")
    print("="*60)
    
    scope_data = {
        'in_scope_domains': [],
        'in_scope_apps': [],
        'in_scope_ips': [],
        'in_scope_smart_contracts': [],
        'in_scope_other': [],
        'out_of_scope': [],
        'reward_tiers': [],
        'special_programs': []
    }
    
    # Extract domains
    domain_pattern = r'\*?\.?[\w-]+\.(?:com|net|org|io)'
    domains = re.findall(domain_pattern, policy_text)
    scope_data['in_scope_domains'] = list(set(domains))
    
    # Extract mobile apps
    app_pattern = r'com\.\w+\.\w+|org\.\w+'
    apps = re.findall(app_pattern, policy_text)
    scope_data['in_scope_apps'] = list(set(apps))
    
    # Extract IP ranges
    ip_pattern = r'\d+\.\d+\.\d+\.\d+(?:/\d+)?'
    ips = re.findall(ip_pattern, policy_text)
    scope_data['in_scope_ips'] = list(set(ips))
    
    # Extract reward amounts
    reward_pattern = r'\$[\d,]+(?:\.\d+)?(?:\s*(?:million|M))?'
    rewards = re.findall(reward_pattern, policy_text)
    scope_data['reward_tiers'] = list(set(rewards))
    
    # Look for specific sections
    if "Smart Contract" in policy_text:
        scope_data['in_scope_smart_contracts'].append("Web3 Smart Contracts")
    if "Base Network" in policy_text or "base.org" in policy_text:
        scope_data['in_scope_smart_contracts'].append("Base L2 Network")
    if "CB-MPC" in policy_text:
        scope_data['in_scope_other'].append("CB-MPC Cryptography Library")
    
    # Extract out of scope items
    out_scope_section = re.search(r'Out of scope:(.*?)(?:Eligibility|$)', policy_text, re.DOTALL)
    if out_scope_section:
        out_items = re.findall(r'\* ([^\n]+)', out_scope_section.group(1))
        scope_data['out_of_scope'] = out_items
    
    return scope_data

def check_additional_parameters():
    """Check if we can get more data with additional parameters"""
    print("\n🔬 Testing Additional Parameters")
    print("="*60)
    
    auth = (USERNAME, API_TOKEN)
    headers = {'Accept': 'application/json'}
    
    params_to_test = [
        {'page[size]': 100, 'fields[program]': 'handle,name,policy,structured_scopes'},
        {'page[size]': 100, 'include': 'structured_scopes,weaknesses'},
        {'filter[state]': 'public_mode', 'filter[offers_bounties]': 'true'},
        {'sort': '-bounty_earned_for_user'},
    ]
    
    for params in params_to_test:
        print(f"\nTesting params: {params}")
        url = f"{BASE_URL}/programs"
        
        try:
            response = requests.get(url, auth=auth, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                programs = data.get('data', [])
                
                # Find Coinbase
                for program in programs:
                    if program.get('attributes', {}).get('handle') == 'coinbase':
                        attrs = program.get('attributes', {})
                        print(f"  ✅ Found Coinbase with {len(attrs)} attributes")
                        
                        # Check for new fields
                        standard_fields = {'handle', 'name', 'state', 'submission_state', 
                                         'offers_bounties', 'currency', 'policy', 'bookmarked',
                                         'allows_bounty_splitting', 'gold_standard_safe_harbor',
                                         'started_accepting_at', 'profile_picture',
                                         'number_of_reports_for_user', 'bounty_earned_for_user'}
                        
                        new_fields = set(attrs.keys()) - standard_fields
                        if new_fields:
                            print(f"  🆕 NEW FIELDS FOUND: {new_fields}")
                        
                        # Check relationships
                        rels = program.get('relationships', {})
                        if rels:
                            print(f"  🔗 Relationships: {list(rels.keys())}")
                        
                        # Check included data
                        included = data.get('included', [])
                        if included:
                            print(f"  📦 Included data: {len(included)} items")
                        
                        break
            else:
                print(f"  ❌ Status: {response.status_code}")
                
        except Exception as e:
            print(f"  ❌ Error: {e}")

def analyze_full_policy_structure():
    """Analyze the complete structure of the policy text"""
    print("\n📜 Analyzing Full Policy Structure")
    print("="*60)
    
    # Load the saved Coinbase data
    with open('/home/kali/bbhk/docs/bb-sites/hackerone/programs/coinbase/coinbase_program_20250817_200908.json', 'r') as f:
        coinbase_data = json.load(f)
    
    policy = coinbase_data['attributes']['policy']
    
    # Find all sections
    sections = re.findall(r'^#+\s+(.+)$', policy, re.MULTILINE)
    print("Policy Sections Found:")
    for section in sections:
        print(f"  • {section}")
    
    # Count specific mentions
    keywords = {
        'Critical': len(re.findall(r'critical', policy, re.IGNORECASE)),
        'High': len(re.findall(r'high', policy, re.IGNORECASE)),
        'Medium': len(re.findall(r'medium', policy, re.IGNORECASE)),
        'Low': len(re.findall(r'low', policy, re.IGNORECASE)),
        'Extreme': len(re.findall(r'extreme', policy, re.IGNORECASE)),
        'Smart Contract': len(re.findall(r'smart contract', policy, re.IGNORECASE)),
        'Base': len(re.findall(r'base', policy, re.IGNORECASE)),
        'Million': len(re.findall(r'million|\$\d+M', policy, re.IGNORECASE)),
    }
    
    print("\nKeyword Frequency:")
    for keyword, count in keywords.items():
        print(f"  • {keyword}: {count} mentions")
    
    # Extract complete scope
    scope_data = extract_all_scope_from_policy(policy)
    
    print("\n🎯 Complete Scope Extracted:")
    print(f"  • In-Scope Domains: {len(scope_data['in_scope_domains'])}")
    for domain in sorted(scope_data['in_scope_domains'])[:10]:
        print(f"    - {domain}")
    
    print(f"  • Mobile Apps: {len(scope_data['in_scope_apps'])}")
    for app in scope_data['in_scope_apps']:
        print(f"    - {app}")
    
    print(f"  • IP Ranges: {scope_data['in_scope_ips']}")
    
    print(f"  • Reward Amounts Found: {sorted(scope_data['reward_tiers'])}")
    
    return scope_data

def main():
    print("="*60)
    print("🔬 COINBASE DEEP DIVE - HACKER API")
    print("="*60)
    
    # Test program-specific endpoints
    endpoint_results = test_program_specific_endpoints()
    
    # Check additional parameters
    check_additional_parameters()
    
    # Analyze full policy
    scope_data = analyze_full_policy_structure()
    
    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    results = {
        'timestamp': timestamp,
        'endpoint_tests': [(e[0], e[1]) for e in endpoint_results if e[1] == "SUCCESS"],
        'complete_scope': scope_data
    }
    
    filename = f'/home/kali/bbhk/docs/bb-sites/hackerone/programs/coinbase/coinbase_deep_dive_{timestamp}.json'
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Results saved to: {filename}")
    
    print("\n" + "="*60)
    print("✅ DEEP DIVE COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()