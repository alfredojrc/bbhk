#!/usr/bin/env python3
"""
Explore Coinbase Bug Bounty Program via HACKER API
Date: August 17, 2025
Purpose: Deep dive into Coinbase program structure using ONLY the HACKER API
"""

import os
import requests
import json
from datetime import datetime
import time

# HACKER API Configuration (FREE!)
USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"

def fetch_all_programs():
    """First, fetch all programs to find Coinbase"""
    print("🔍 Fetching all programs to find Coinbase...")
    
    auth = (USERNAME, API_TOKEN)
    headers = {'Accept': 'application/json'}
    
    all_programs = []
    page_number = 1
    next_url = f"{BASE_URL}/programs?page[size]=100"
    
    while next_url:
        try:
            response = requests.get(next_url, auth=auth, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                programs = data.get('data', [])
                
                for program in programs:
                    attrs = program.get('attributes', {})
                    if 'coinbase' in attrs.get('handle', '').lower() or 'coinbase' in attrs.get('name', '').lower():
                        print(f"\n✅ Found Coinbase Program!")
                        print(f"   ID: {program.get('id')}")
                        print(f"   Handle: {attrs.get('handle')}")
                        print(f"   Name: {attrs.get('name')}")
                        return program
                
                all_programs.extend(programs)
                
                # Check for next page
                links = data.get('links', {})
                next_url = links.get('next')
                page_number += 1
                
                # Be respectful with rate limiting
                time.sleep(0.5)
                
            else:
                print(f"❌ Error: HTTP {response.status_code}")
                break
                
        except Exception as e:
            print(f"❌ Exception: {e}")
            break
    
    return None

def explore_program_structure(program):
    """Explore the structure of the Coinbase program data"""
    print("\n" + "="*60)
    print("📊 COINBASE PROGRAM STRUCTURE")
    print("="*60)
    
    # Extract all attributes
    attrs = program.get('attributes', {})
    
    # Basic Information
    print("\n📌 Basic Information:")
    print(f"   • ID: {program.get('id')}")
    print(f"   • Type: {program.get('type')}")
    print(f"   • Handle: {attrs.get('handle')}")
    print(f"   • Name: {attrs.get('name')}")
    
    # Status Information
    print("\n🔄 Status Information:")
    print(f"   • State: {attrs.get('state')}")
    print(f"   • Submission State: {attrs.get('submission_state')}")
    print(f"   • Triage Active: {attrs.get('triage_active')}")
    print(f"   • Open Scope: {attrs.get('open_scope')}")
    print(f"   • Started Accepting At: {attrs.get('started_accepting_at')}")
    
    # Bounty Information
    print("\n💰 Bounty Information:")
    print(f"   • Offers Bounties: {attrs.get('offers_bounties')}")
    print(f"   • Offers Swag: {attrs.get('offers_swag')}")
    print(f"   • Currency: {attrs.get('currency')}")
    print(f"   • Allows Bounty Splitting: {attrs.get('allows_bounty_splitting')}")
    print(f"   • Fast Payments: {attrs.get('fast_payments')}")
    
    # User-Specific Information
    print("\n👤 Your Stats with Coinbase:")
    print(f"   • Number of Reports: {attrs.get('number_of_reports_for_user')}")
    print(f"   • Bounty Earned: ${attrs.get('bounty_earned_for_user')}")
    print(f"   • Last Invitation Accepted: {attrs.get('last_invitation_accepted_at_for_user')}")
    print(f"   • Bookmarked: {attrs.get('bookmarked')}")
    
    # Legal & Compliance
    print("\n⚖️ Legal & Compliance:")
    print(f"   • Gold Standard Safe Harbor: {attrs.get('gold_standard_safe_harbor')}")
    
    # Available Data Fields
    print("\n📁 All Available Fields:")
    for key in sorted(attrs.keys()):
        value = attrs[key]
        if isinstance(value, str) and len(value) > 100:
            value = value[:100] + "..."
        print(f"   • {key}: {value}")
    
    # Relationships (if any)
    relationships = program.get('relationships', {})
    if relationships:
        print("\n🔗 Relationships Available:")
        for rel_name, rel_data in relationships.items():
            print(f"   • {rel_name}: {rel_data}")
    
    # Links
    links = program.get('links', {})
    if links:
        print("\n🔗 Links:")
        for link_name, link_url in links.items():
            print(f"   • {link_name}: {link_url}")
    
    return attrs

def save_coinbase_data(program_data):
    """Save Coinbase program data for analysis"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"data/coinbase_program_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(program_data, f, indent=2)
    
    print(f"\n💾 Saved to: {filename}")
    return filename

def analyze_policy(attrs):
    """Analyze the policy text if available"""
    policy = attrs.get('policy', '')
    if policy:
        print("\n" + "="*60)
        print("📜 POLICY ANALYSIS")
        print("="*60)
        
        # First 500 characters of policy
        print("\n📝 Policy Preview:")
        print(policy[:500])
        
        # Look for key sections
        print("\n🔍 Key Policy Sections Found:")
        sections = [
            "scope", "reward", "out of scope", "eligibility", 
            "disclosure", "safe harbor", "prohibit", "legal",
            "payment", "severity", "critical", "high", "medium", "low"
        ]
        
        for section in sections:
            if section.lower() in policy.lower():
                count = policy.lower().count(section.lower())
                print(f"   • '{section}': mentioned {count} times")

def main():
    print("="*60)
    print("🎯 COINBASE BUG BOUNTY EXPLORATION")
    print("Using HACKER API Only - Real Data")
    print("="*60)
    
    # Find Coinbase program
    coinbase = fetch_all_programs()
    
    if coinbase:
        # Explore structure
        attrs = explore_program_structure(coinbase)
        
        # Analyze policy
        analyze_policy(attrs)
        
        # Save data
        save_coinbase_data(coinbase)
        
        print("\n" + "="*60)
        print("✅ EXPLORATION COMPLETE")
        print("="*60)
        
        # Summary
        print("\n📊 Key Findings:")
        print(f"   • Program is {attrs.get('submission_state', 'unknown').upper()} for submissions")
        print(f"   • Offers bounties: {attrs.get('offers_bounties', False)}")
        print(f"   • Fast payments: {attrs.get('fast_payments', False)}")
        print(f"   • Gold standard safe harbor: {attrs.get('gold_standard_safe_harbor', False)}")
        
    else:
        print("\n❌ Could not find Coinbase program")
        print("This might mean:")
        print("1. You don't have access to Coinbase's program")
        print("2. The program name/handle is different")
        print("3. API pagination needs adjustment")

if __name__ == "__main__":
    main()