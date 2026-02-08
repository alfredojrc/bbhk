#!/usr/bin/env python3
"""
Fetch programs using the HACKER API (not enterprise API!)
This is the correct endpoint that works for individual hackers
"""

import os
import requests
import json
import sqlite3
from datetime import datetime

# HACKER API Configuration
USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
API_URL = "https://api.hackerone.com/v1/hackers/programs"

def fetch_all_programs():
    """Fetch all programs from the HACKER API"""
    print("🔍 Fetching programs from HackerOne HACKER API...")
    print(f"   Endpoint: {API_URL}")
    print(f"   Username: {USERNAME}")
    print("-" * 60)
    
    auth = (USERNAME, API_TOKEN)
    headers = {'Accept': 'application/json'}
    
    all_programs = []
    page_number = 1
    next_url = API_URL + "?page[size]=100"
    
    while next_url:
        print(f"\n📄 Fetching page {page_number}...")
        
        try:
            response = requests.get(next_url, auth=auth, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                programs = data.get('data', [])
                
                print(f"   ✅ Retrieved {len(programs)} programs")
                
                for program in programs:
                    attrs = program.get('attributes', {})
                    program_info = {
                        'id': program.get('id'),
                        'handle': attrs.get('handle'),
                        'name': attrs.get('name'),
                        'currency': attrs.get('currency'),
                        'submission_state': attrs.get('submission_state'),
                        'state': attrs.get('state'),
                        'offers_bounties': attrs.get('offers_bounties'),
                        'allows_bounty_splitting': attrs.get('allows_bounty_splitting'),
                        'bookmarked': attrs.get('bookmarked'),
                        'triage_active': attrs.get('triage_active'),
                        'open_scope': attrs.get('open_scope'),
                        'fast_payments': attrs.get('fast_payments'),
                        'gold_standard_safe_harbor': attrs.get('gold_standard_safe_harbor'),
                        'started_accepting_at': attrs.get('started_accepting_at'),
                        'number_of_reports_for_user': attrs.get('number_of_reports_for_user'),
                        'bounty_earned_for_user': attrs.get('bounty_earned_for_user'),
                        'profile_picture': attrs.get('profile_picture'),
                        'policy_snippet': attrs.get('policy', '')[:500]  # First 500 chars of policy
                    }
                    all_programs.append(program_info)
                    print(f"      • {program_info['name']} (@{program_info['handle']})")
                
                # Check for next page
                links = data.get('links', {})
                next_url = links.get('next')
                page_number += 1
                
            else:
                print(f"   ❌ Error: HTTP {response.status_code}")
                print(f"   Response: {response.text[:200]}")
                break
                
        except Exception as e:
            print(f"   ❌ Exception: {e}")
            break
    
    return all_programs

def save_to_json(programs):
    """Save programs to JSON file"""
    filename = f"data/hacker_api_programs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(filename, 'w') as f:
        json.dump(programs, f, indent=2)
    
    print(f"\n💾 Saved {len(programs)} programs to {filename}")
    return filename

def update_database(programs):
    """Update SQLite database with new program data"""
    conn = sqlite3.connect('core/database/bbhk.db')
    cursor = conn.cursor()
    
    updated = 0
    new = 0
    
    for program in programs:
        # Check if program exists
        cursor.execute("SELECT id FROM programs WHERE program_url LIKE ?", 
                      (f"%/{program['handle']}%",))
        existing = cursor.fetchone()
        
        if existing:
            # Update existing program
            cursor.execute("""
                UPDATE programs 
                SET allows_bounty_splitting = ?,
                    state = ?,
                    submission_state = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE program_url LIKE ?
            """, (
                program['allows_bounty_splitting'],
                program['state'],
                program['submission_state'],
                f"%/{program['handle']}%"
            ))
            updated += 1
        else:
            # Could insert new program here if needed
            new += 1
    
    conn.commit()
    conn.close()
    
    print(f"\n📊 Database update:")
    print(f"   • Updated: {updated} programs")
    print(f"   • New (not inserted): {new} programs")

def main():
    print("=" * 60)
    print("🚀 HackerOne HACKER API Program Fetcher")
    print("=" * 60)
    
    # Fetch all programs
    programs = fetch_all_programs()
    
    if programs:
        print(f"\n✅ Successfully fetched {len(programs)} total programs!")
        
        # Save to JSON
        json_file = save_to_json(programs)
        
        # Update database
        update_database(programs)
        
        # Show some statistics
        print("\n📈 Statistics:")
        bounty_programs = [p for p in programs if p['offers_bounties']]
        open_programs = [p for p in programs if p['submission_state'] == 'open']
        splitting_programs = [p for p in programs if p['allows_bounty_splitting']]
        
        print(f"   • Bounty programs: {len(bounty_programs)}")
        print(f"   • Open for submissions: {len(open_programs)}")
        print(f"   • Allow bounty splitting: {len(splitting_programs)}")
        
    else:
        print("\n❌ No programs fetched")

if __name__ == "__main__":
    main()