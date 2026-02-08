#!/usr/bin/env python3
"""
Fetch Fireblocks MPC data from HackerOne API
Uses HACKER API only - no fake data!

Author: BBHK Team
Date: August 18, 2025
"""

import requests
import psycopg2
from psycopg2.extras import RealDictCursor
import json
from datetime import datetime
import os
import sys

# Add validator
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from api_data_validator import validate_before_insert

# HackerOne API Configuration
USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'bbhk_db',
    'user': 'bbhk_user',
    'password': os.getenv('POSTGRES_PASSWORD', '')
}

class FireblocksFetcher:
    def __init__(self):
        self.auth = (USERNAME, API_TOKEN)
        self.headers = {'Accept': 'application/json'}
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update(self.headers)
        self.program_data = None
        self.scopes_data = []
        
    def find_fireblocks(self):
        """Search for Fireblocks in HackerOne"""
        print("🔍 Searching for Fireblocks MPC...")
        
        # Try different possible handles
        possible_handles = ['fireblocks_mpc', 'fireblocks', 'fireblocksofficial', 'fireblocks-mpc']
        
        for handle in possible_handles:
            print(f"   Trying handle: {handle}")
            url = f"{BASE_URL}/programs?filter[handle]={handle}"
            
            response = self.session.get(url)
            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    program = data['data'][0]
                    attrs = program['attributes']
                    print(f"✅ Found program: {attrs['name']} (@{attrs['handle']})")
                    self.program_data = program
                    return True
        
        # If not found by exact handle, search all programs
        print("   Searching all programs...")
        url = f"{BASE_URL}/programs"
        params = {'page[size]': 100}
        
        while url:
            response = self.session.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                
                for program in data['data']:
                    attrs = program['attributes']
                    if 'fireblocks' in attrs.get('handle', '').lower() or \
                       'fireblocks' in attrs.get('name', '').lower():
                        print(f"✅ Found program: {attrs['name']} (@{attrs['handle']})")
                        self.program_data = program
                        return True
                
                # Check next page
                url = data.get('links', {}).get('next')
                params = {}  # Clear params for next URL
            else:
                break
        
        print("❌ Fireblocks not found in HackerOne")
        return False
    
    def fetch_structured_scopes(self):
        """Fetch structured scopes for the program"""
        if not self.program_data:
            return False
            
        handle = self.program_data['attributes']['handle']
        print(f"📡 Fetching structured scopes for {handle}...")
        
        url = f"{BASE_URL}/programs/{handle}/structured_scopes"
        response = self.session.get(url)
        
        if response.status_code == 200:
            data = response.json()
            self.scopes_data = data.get('data', [])
            print(f"   ✅ Found {len(self.scopes_data)} scope items")
            return True
        else:
            print(f"   ❌ Could not fetch scopes: {response.status_code}")
            return False
    
    def fetch_with_includes(self):
        """Fetch program with policy and other includes"""
        if not self.program_data:
            return False
            
        handle = self.program_data['attributes']['handle']
        print(f"📥 Fetching enhanced data for {handle}...")
        
        # Fetch with policy include
        url = f"{BASE_URL}/programs?filter[handle]={handle}&include=policy"
        response = self.session.get(url)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('data'):
                self.program_data = data['data'][0]
                policy = self.program_data['attributes'].get('policy', '')
                print(f"   ✅ Policy data: {len(policy)} characters")
                return True
        
        return False
    
    def store_in_database(self):
        """Store program data in PostgreSQL"""
        if not self.program_data:
            print("❌ No program data to store")
            return False
        
        print("💾 Storing in PostgreSQL...")
        
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            cursor = conn.cursor()
            
            attrs = self.program_data['attributes']
            
            # Prepare program data
            program_data = {
                'program_id': self.program_data['id'],
                'handle': attrs.get('handle'),
                'name': attrs.get('name'),
                'currency': attrs.get('currency', 'usd'),
                'submission_state': attrs.get('submission_state'),
                'state': attrs.get('state'),
                'offers_bounties': attrs.get('offers_bounties', False),
                'offers_swag': attrs.get('offers_swag', False),
                'policy': attrs.get('policy'),
                'last_fetched_at': datetime.now()
            }
            
            # Validate data before insertion
            is_valid, cleaned_data = validate_before_insert(program_data)
            if not is_valid:
                print("❌ Data validation failed - contains fake patterns")
                return False
            
            # Use cleaned data
            program_data = cleaned_data
            
            # Insert or update program
            cursor.execute("""
                INSERT INTO programs (
                    program_id, handle, name, currency, submission_state, state,
                    offers_bounties, offers_swag, policy, last_fetched_at
                ) VALUES (
                    %(program_id)s, %(handle)s, %(name)s, %(currency)s, 
                    %(submission_state)s, %(state)s, %(offers_bounties)s,
                    %(offers_swag)s, %(policy)s, %(last_fetched_at)s
                )
                ON CONFLICT (program_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    submission_state = EXCLUDED.submission_state,
                    state = EXCLUDED.state,
                    offers_bounties = EXCLUDED.offers_bounties,
                    offers_swag = EXCLUDED.offers_swag,
                    policy = EXCLUDED.policy,
                    last_fetched_at = EXCLUDED.last_fetched_at,
                    updated_at = CURRENT_TIMESTAMP
            """, program_data)
            
            print(f"   ✅ Stored program: {attrs['name']}")
            
            # Store structured scopes
            if self.scopes_data:
                for scope in self.scopes_data:
                    scope_attrs = scope['attributes']
                    
                    cursor.execute("""
                        INSERT INTO structured_scopes (
                            scope_id, program_id, asset_type, asset_identifier,
                            eligible_for_bounty, max_severity
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (scope_id) DO UPDATE SET
                            asset_type = EXCLUDED.asset_type,
                            asset_identifier = EXCLUDED.asset_identifier,
                            eligible_for_bounty = EXCLUDED.eligible_for_bounty,
                            max_severity = EXCLUDED.max_severity
                    """, (
                        scope['id'],
                        self.program_data['id'],
                        scope_attrs.get('asset_type'),
                        scope_attrs.get('asset_identifier'),
                        scope_attrs.get('eligible_for_bounty', False),
                        scope_attrs.get('max_severity')
                    ))
                
                print(f"   ✅ Stored {len(self.scopes_data)} scope items")
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"❌ Database error: {e}")
            return False
    
    def save_json_files(self, output_dir):
        """Save JSON data files"""
        if not self.program_data:
            return []
        
        print(f"💾 Saving JSON files to {output_dir}...")
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        files = []
        
        # Save program data
        program_file = f"{output_dir}/fireblocks_program_{timestamp}.json"
        with open(program_file, 'w') as f:
            json.dump(self.program_data, f, indent=2, default=str)
        files.append(program_file)
        print(f"   ✅ Saved: {program_file}")
        
        # Save scopes data
        if self.scopes_data:
            scopes_file = f"{output_dir}/fireblocks_scopes_{timestamp}.json"
            with open(scopes_file, 'w') as f:
                json.dump({'scopes': self.scopes_data}, f, indent=2, default=str)
            files.append(scopes_file)
            print(f"   ✅ Saved: {scopes_file}")
        
        return files
    
    def run(self):
        """Run complete fetch process"""
        print("🚀 Fireblocks MPC Data Fetcher")
        print("=" * 60)
        
        # Step 1: Find Fireblocks
        if not self.find_fireblocks():
            print("\n❌ Cannot proceed without finding Fireblocks")
            return False
        
        # Step 2: Fetch enhanced data
        self.fetch_with_includes()
        
        # Step 3: Fetch structured scopes
        self.fetch_structured_scopes()
        
        # Step 4: Store in database
        if not self.store_in_database():
            print("\n⚠️  Database storage failed")
        
        # Step 5: Save JSON files
        docs_dir = "/home/kali/bbhk/docs/bb-sites/hackerone/programs/fireblocks"
        self.save_json_files(docs_dir)
        
        print("\n✅ Fireblocks data fetch complete!")
        return True

if __name__ == "__main__":
    fetcher = FireblocksFetcher()
    success = fetcher.run()