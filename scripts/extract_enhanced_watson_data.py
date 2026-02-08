#!/usr/bin/env python3
"""
Enhanced Watson Group Data Extraction
Extracts additional program data using discovered API endpoints with includes

Author: BBHK Team + Claude-Flow Hive Mind  
Date: August 17, 2025
"""

import requests
import json
from datetime import datetime
import os

# HackerOne API Configuration
USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"

class EnhancedWatsonDataExtractor:
    def __init__(self):
        self.auth = (USERNAME, API_TOKEN)
        self.headers = {'Accept': 'application/json'}
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update(self.headers)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = "/home/kali/bbhk/docs/bb-sites/hackerone/programs/watson_group"
        
    def extract_with_includes(self, include_type):
        """Extract Watson Group data with specific includes"""
        url = f"{BASE_URL}/programs?filter[handle]=watson_group&include={include_type}"
        
        try:
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Successfully extracted data with include={include_type}")
                print(f"   📏 Data size: {len(json.dumps(data))} characters")
                
                return data
            else:
                print(f"❌ Failed to extract with include={include_type}: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"💥 Error extracting with include={include_type}: {e}")
            return None
    
    def compare_policy_data(self, api_policy, db_policy):
        """Compare API policy data with PostgreSQL policy data"""
        print("\n📊 POLICY DATA COMPARISON:")
        print("=" * 50)
        
        api_length = len(api_policy) if api_policy else 0
        db_length = len(db_policy) if db_policy else 0
        
        print(f"API Policy Length: {api_length} characters")
        print(f"DB Policy Length: {db_length} characters")
        
        if api_policy and db_policy:
            if api_policy == db_policy:
                print("✅ Policies are IDENTICAL")
            else:
                print("⚠️  Policies are DIFFERENT")
                
                # Find differences
                if api_length != db_length:
                    print(f"   Length difference: {abs(api_length - db_length)} characters")
                
                # Sample comparison
                api_start = api_policy[:200] if api_policy else ""
                db_start = db_policy[:200] if db_policy else ""
                
                if api_start != db_start:
                    print("   First 200 characters differ:")
                    print(f"   API: {api_start[:100]}...")
                    print(f"   DB:  {db_start[:100]}...")
        
        return {
            'api_length': api_length,
            'db_length': db_length,
            'identical': api_policy == db_policy if api_policy and db_policy else False
        }
    
    def analyze_enhanced_data(self, policy_data, scopes_data, rewards_data):
        """Analyze the enhanced API data"""
        print("\n🔍 ENHANCED DATA ANALYSIS:")
        print("=" * 50)
        
        analysis = {
            'extraction_timestamp': datetime.now().isoformat(),
            'data_sources': ['API with includes'],
            'findings': {}
        }
        
        # Analyze policy data
        if policy_data and 'data' in policy_data:
            program_data = policy_data['data'][0] if policy_data['data'] else {}
            policy_text = program_data.get('attributes', {}).get('policy', '')
            
            analysis['findings']['policy'] = {
                'available': bool(policy_text),
                'length': len(policy_text),
                'contains_microblog': 'microblog' in policy_text.lower(),
                'contains_rewards': 'reward' in policy_text.lower() or 'bounty' in policy_text.lower(),
                'contains_scope': 'scope' in policy_text.lower(),
                'last_update_mentioned': 'December 2024' in policy_text
            }
            
            print(f"📋 Policy Analysis:")
            print(f"   Length: {analysis['findings']['policy']['length']} characters")
            print(f"   Contains microblog: {analysis['findings']['policy']['contains_microblog']}")
            print(f"   Contains rewards: {analysis['findings']['policy']['contains_rewards']}")
            print(f"   Contains scope: {analysis['findings']['policy']['contains_scope']}")
        
        # Analyze scopes data
        if scopes_data and 'included' in scopes_data:
            scopes = [item for item in scopes_data['included'] if item['type'] == 'structured-scope']
            
            analysis['findings']['structured_scopes'] = {
                'count': len(scopes),
                'asset_types': list(set(scope['attributes'].get('asset_type') for scope in scopes)),
                'severities': list(set(scope['attributes'].get('max_severity') for scope in scopes))
            }
            
            print(f"🎯 Scopes Analysis:")
            print(f"   Total scopes: {analysis['findings']['structured_scopes']['count']}")
            print(f"   Asset types: {analysis['findings']['structured_scopes']['asset_types']}")
            print(f"   Severities: {analysis['findings']['structured_scopes']['severities']}")
        
        # Analyze rewards data
        if rewards_data and 'included' in rewards_data:
            rewards = [item for item in rewards_data['included'] if item['type'] == 'bounty']
            
            analysis['findings']['rewards'] = {
                'bounty_count': len(rewards),
                'bounty_available': len(rewards) > 0
            }
            
            print(f"💰 Rewards Analysis:")
            print(f"   Bounty records: {analysis['findings']['rewards']['bounty_count']}")
            print(f"   Has reward data: {analysis['findings']['rewards']['bounty_available']}")
        
        return analysis
    
    def extract_policy_from_db(self):
        """Extract policy from PostgreSQL for comparison"""
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            
            DB_CONFIG = {
                'host': 'localhost',
                'port': 5432,
                'database': 'bbhk_db',
                'user': 'bbhk_user',
                'password': os.getenv('POSTGRES_PASSWORD', '')
            }
            
            conn = psycopg2.connect(**DB_CONFIG)
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            cursor.execute('SELECT policy FROM programs WHERE handle = %s', ('watson_group',))
            result = cursor.fetchone()
            
            conn.close()
            
            return result['policy'] if result else None
            
        except Exception as e:
            print(f"❌ Could not extract policy from DB: {e}")
            return None
    
    def save_enhanced_data(self, policy_data, scopes_data, rewards_data, analysis):
        """Save enhanced data files"""
        
        # Save enhanced policy data
        if policy_data:
            policy_file = f"{self.output_dir}/watson_enhanced_policy_{self.timestamp}.json"
            with open(policy_file, 'w') as f:
                json.dump(policy_data, f, indent=2, default=str)
            print(f"💾 Saved enhanced policy: {policy_file}")
        
        # Save enhanced scopes data  
        if scopes_data:
            scopes_file = f"{self.output_dir}/watson_enhanced_scopes_{self.timestamp}.json"
            with open(scopes_file, 'w') as f:
                json.dump(scopes_data, f, indent=2, default=str)
            print(f"💾 Saved enhanced scopes: {scopes_file}")
        
        # Save enhanced rewards data
        if rewards_data:
            rewards_file = f"{self.output_dir}/watson_enhanced_rewards_{self.timestamp}.json"
            with open(rewards_file, 'w') as f:
                json.dump(rewards_data, f, indent=2, default=str)
            print(f"💾 Saved enhanced rewards: {rewards_file}")
        
        # Save analysis
        analysis_file = f"{self.output_dir}/watson_enhanced_analysis_{self.timestamp}.json"
        with open(analysis_file, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        print(f"💾 Saved enhanced analysis: {analysis_file}")
    
    def run_enhanced_extraction(self):
        """Run complete enhanced data extraction"""
        print("🚀 Enhanced Watson Group Data Extraction")
        print("=" * 60)
        
        # Extract data with different includes
        print("\n📥 Extracting data with includes...")
        policy_data = self.extract_with_includes('policy')
        scopes_data = self.extract_with_includes('structured_scopes')
        rewards_data = self.extract_with_includes('rewards')
        
        # Get DB policy for comparison
        db_policy = self.extract_policy_from_db()
        
        # Compare API policy with DB policy
        if policy_data and 'data' in policy_data and policy_data['data']:
            api_policy = policy_data['data'][0].get('attributes', {}).get('policy', '')
            comparison = self.compare_policy_data(api_policy, db_policy)
        else:
            comparison = {'api_length': 0, 'db_length': len(db_policy) if db_policy else 0, 'identical': False}
        
        # Analyze enhanced data
        analysis = self.analyze_enhanced_data(policy_data, scopes_data, rewards_data)
        analysis['policy_comparison'] = comparison
        
        # Save all data
        self.save_enhanced_data(policy_data, scopes_data, rewards_data, analysis)
        
        print("\n✅ Enhanced Data Extraction Complete!")
        
        return {
            'policy_data': policy_data,
            'scopes_data': scopes_data, 
            'rewards_data': rewards_data,
            'analysis': analysis
        }

if __name__ == "__main__":
    extractor = EnhancedWatsonDataExtractor()
    results = extractor.run_enhanced_extraction()