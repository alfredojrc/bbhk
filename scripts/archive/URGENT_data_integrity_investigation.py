#!/usr/bin/env python3
"""
URGENT: Data Integrity Investigation
Critical investigation of database vs API data discrepancy

Author: Truth Enforcement Team
Date: August 17, 2025
"""

import os
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
import json
from datetime import datetime
import hashlib

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

class DataIntegrityInvestigator:
    def __init__(self):
        self.auth = (USERNAME, API_TOKEN)
        self.headers = {'Accept': 'application/json'}
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update(self.headers)
        self.evidence = {}
        
    def get_database_policy(self):
        """Get Watson Group policy from database"""
        print("\n🔍 EXTRACTING DATABASE POLICY...")
        print("=" * 60)
        
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get the policy and metadata
        cursor.execute("""
            SELECT 
                program_id,
                handle,
                name,
                policy,
                created_at,
                updated_at,
                last_fetched_at
            FROM programs 
            WHERE handle = 'watson_group'
        """)
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            policy = result['policy']
            print(f"✅ Database Policy Found:")
            print(f"   Length: {len(policy) if policy else 0} characters")
            print(f"   Created: {result['created_at']}")
            print(f"   Updated: {result['updated_at']}")
            print(f"   Last Fetched: {result['last_fetched_at']}")
            print(f"   MD5 Hash: {hashlib.md5(policy.encode() if policy else b'').hexdigest()}")
            print(f"\n   First 200 chars:")
            print(f"   {policy[:200] if policy else 'No policy'}")
            
            self.evidence['database'] = {
                'policy_length': len(policy) if policy else 0,
                'policy_content': policy,
                'created_at': str(result['created_at']),
                'updated_at': str(result['updated_at']),
                'last_fetched_at': str(result['last_fetched_at']),
                'md5_hash': hashlib.md5(policy.encode() if policy else b'').hexdigest()
            }
            
            return policy
        else:
            print("❌ No Watson Group data in database!")
            return None
    
    def get_api_policy_direct(self):
        """Get Watson Group policy directly from API"""
        print("\n🔍 FETCHING FRESH API DATA...")
        print("=" * 60)
        
        # Method 1: Direct program endpoint
        url1 = f"{BASE_URL}/programs/watson_group"
        print(f"Testing: {url1}")
        
        try:
            response = self.session.get(url1, timeout=30)
            if response.status_code == 200:
                data = response.json()
                policy1 = data.get('data', {}).get('attributes', {}).get('policy', '')
                print(f"✅ Direct endpoint policy: {len(policy1)} characters")
                print(f"   MD5 Hash: {hashlib.md5(policy1.encode() if policy1 else b'').hexdigest()}")
                print(f"   First 200 chars: {policy1[:200] if policy1 else 'No policy'}")
                
                self.evidence['api_direct'] = {
                    'policy_length': len(policy1),
                    'policy_content': policy1,
                    'md5_hash': hashlib.md5(policy1.encode() if policy1 else b'').hexdigest()
                }
            else:
                print(f"❌ Direct endpoint failed: {response.status_code}")
                policy1 = None
        except Exception as e:
            print(f"❌ Error: {e}")
            policy1 = None
        
        # Method 2: Filter with include
        url2 = f"{BASE_URL}/programs?filter[handle]=watson_group&include=policy"
        print(f"\nTesting: {url2}")
        
        try:
            response = self.session.get(url2, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    policy2 = data['data'][0].get('attributes', {}).get('policy', '')
                    print(f"✅ Include endpoint policy: {len(policy2)} characters")
                    print(f"   MD5 Hash: {hashlib.md5(policy2.encode() if policy2 else b'').hexdigest()}")
                    print(f"   First 200 chars: {policy2[:200] if policy2 else 'No policy'}")
                    
                    self.evidence['api_include'] = {
                        'policy_length': len(policy2),
                        'policy_content': policy2,
                        'md5_hash': hashlib.md5(policy2.encode() if policy2 else b'').hexdigest()
                    }
                else:
                    policy2 = None
            else:
                print(f"❌ Include endpoint failed: {response.status_code}")
                policy2 = None
        except Exception as e:
            print(f"❌ Error: {e}")
            policy2 = None
        
        return policy1, policy2
    
    def compare_policies(self, db_policy, api_policy1, api_policy2):
        """Compare all policies"""
        print("\n🔬 COMPARING POLICIES...")
        print("=" * 60)
        
        comparisons = []
        
        # Compare lengths
        db_len = len(db_policy) if db_policy else 0
        api1_len = len(api_policy1) if api_policy1 else 0
        api2_len = len(api_policy2) if api_policy2 else 0
        
        print(f"📏 LENGTH COMPARISON:")
        print(f"   Database:    {db_len:,} characters")
        print(f"   API Direct:  {api1_len:,} characters")
        print(f"   API Include: {api2_len:,} characters")
        
        if db_len > max(api1_len, api2_len):
            print(f"\n⚠️  DATABASE HAS {db_len - max(api1_len, api2_len):,} MORE CHARACTERS!")
            print("   This is IMPOSSIBLE if data comes only from API!")
        
        # Compare content
        print(f"\n🔤 CONTENT COMPARISON:")
        
        if db_policy and api_policy1:
            if db_policy == api_policy1:
                print("   DB vs API Direct: ✅ IDENTICAL")
            else:
                print("   DB vs API Direct: ❌ DIFFERENT")
                # Find where they differ
                for i, (c1, c2) in enumerate(zip(db_policy[:500], api_policy1[:500])):
                    if c1 != c2:
                        print(f"      First difference at position {i}")
                        print(f"      DB:  ...{db_policy[max(0,i-20):i+20]}...")
                        print(f"      API: ...{api_policy1[max(0,i-20):i+20]}...")
                        break
        
        # Check for suspicious content
        print(f"\n🚨 SUSPICIOUS CONTENT CHECK:")
        
        suspicious_terms = ['microblog', 'December 2024', 'Latest updates', 'Drogas Lithuania']
        
        for term in suspicious_terms:
            db_has = term.lower() in db_policy.lower() if db_policy else False
            api1_has = term.lower() in api_policy1.lower() if api_policy1 else False
            api2_has = term.lower() in api_policy2.lower() if api_policy2 else False
            
            if db_has and not (api1_has or api2_has):
                print(f"   ⚠️  '{term}' found in DB but NOT in API!")
                comparisons.append(f"SUSPICIOUS: '{term}' in DB only")
        
        self.evidence['comparison'] = {
            'db_length': db_len,
            'api_direct_length': api1_len,
            'api_include_length': api2_len,
            'db_has_more': db_len > max(api1_len, api2_len),
            'extra_characters': db_len - max(api1_len, api2_len) if db_len > max(api1_len, api2_len) else 0,
            'suspicious_findings': comparisons
        }
    
    def check_fetch_script_source(self):
        """Check what the original fetch script actually does"""
        print("\n🔍 CHECKING FETCH SCRIPT SOURCE...")
        print("=" * 60)
        
        # Check if the fetch script modifies data
        script_path = "/home/kali/bbhk/scripts/fetch_all_programs_to_postgres.py"
        
        try:
            with open(script_path, 'r') as f:
                script_content = f.read()
                
            # Look for policy manipulation
            if 'microblog' in script_content.lower():
                print("⚠️  Script mentions 'microblog'!")
            if 'Latest updates' in script_content:
                print("⚠️  Script contains 'Latest updates' text!")
            if 'December 2024' in script_content:
                print("⚠️  Script contains 'December 2024' text!")
            
            # Check if it adds extra content
            if 'policy = ' in script_content or 'policy +=' in script_content:
                print("⚠️  Script modifies policy variable!")
                
            print(f"Script size: {len(script_content)} bytes")
            
        except Exception as e:
            print(f"❌ Could not check script: {e}")
    
    def generate_verdict(self):
        """Generate investigation verdict"""
        print("\n" + "=" * 60)
        print("⚖️  INVESTIGATION VERDICT")
        print("=" * 60)
        
        db_len = self.evidence.get('database', {}).get('policy_length', 0)
        api_len = max(
            self.evidence.get('api_direct', {}).get('policy_length', 0),
            self.evidence.get('api_include', {}).get('policy_length', 0)
        )
        
        if db_len > api_len:
            print("\n🚨 CRITICAL FINDING: DATA INTEGRITY VIOLATION!")
            print(f"   Database contains {db_len - api_len:,} characters NOT from API")
            print("   This violates the principle that DB only contains API data")
            print("\n   POSSIBLE EXPLANATIONS:")
            print("   1. ❌ Fake/synthetic data was added")
            print("   2. ❌ Manual data manipulation occurred")
            print("   3. ❓ API response changed over time (unlikely)")
            print("   4. ❓ Different API endpoint was used initially")
            
            print("\n   RECOMMENDATION: IMMEDIATE DATA CLEANUP REQUIRED!")
            
            verdict = "DATA_INTEGRITY_VIOLATION"
        else:
            print("\n✅ Data integrity appears intact")
            verdict = "DATA_INTEGRITY_OK"
        
        # Save evidence
        evidence_file = f"/home/kali/bbhk/analysis/URGENT_integrity_evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(evidence_file, 'w') as f:
            json.dump(self.evidence, f, indent=2, default=str)
        
        print(f"\n💾 Evidence saved: {evidence_file}")
        
        return verdict
    
    def run_investigation(self):
        """Run complete investigation"""
        print("🚨 URGENT DATA INTEGRITY INVESTIGATION")
        print("=" * 60)
        print("Investigating: Watson Group policy discrepancy")
        print("Issue: Database has 12,060 chars, API returns 2,558 chars")
        
        # Get database policy
        db_policy = self.get_database_policy()
        
        # Get fresh API data
        api_policy1, api_policy2 = self.get_api_policy_direct()
        
        # Compare them
        self.compare_policies(db_policy, api_policy1, api_policy2)
        
        # Check source script
        self.check_fetch_script_source()
        
        # Generate verdict
        verdict = self.generate_verdict()
        
        return verdict, self.evidence

if __name__ == "__main__":
    investigator = DataIntegrityInvestigator()
    verdict, evidence = investigator.run_investigation()