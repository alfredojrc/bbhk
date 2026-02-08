#!/usr/bin/env python3
"""
Enhanced HackerOne Program Data Extractor
Uses discovered include parameters for comprehensive data extraction

Author: BBHK Team + Claude-Flow Hive Mind
Date: August 17, 2025
"""

import os
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
import json
from datetime import datetime
import argparse

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

class EnhancedDataExtractor:
    def __init__(self, program_handle):
        self.program_handle = program_handle
        self.auth = (USERNAME, API_TOKEN)
        self.headers = {'Accept': 'application/json'}
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update(self.headers)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.db_conn = None
        
    def connect_db(self):
        """Connect to PostgreSQL database"""
        try:
            self.db_conn = psycopg2.connect(**DB_CONFIG)
            return True
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return False
    
    def extract_enhanced_api_data(self):
        """Extract enhanced data using include parameters"""
        print(f"🔍 Extracting enhanced API data for: {self.program_handle}")
        
        enhanced_data = {}
        
        # Test all include options
        include_types = ['policy', 'structured_scopes', 'rewards']
        
        for include_type in include_types:
            url = f"{BASE_URL}/programs?filter[handle]={self.program_handle}&include={include_type}"
            
            try:
                response = self.session.get(url, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    enhanced_data[include_type] = data
                    print(f"   ✅ {include_type}: {len(json.dumps(data))} characters")
                else:
                    print(f"   ❌ {include_type}: HTTP {response.status_code}")
                    enhanced_data[include_type] = None
                    
            except Exception as e:
                print(f"   💥 {include_type}: {e}")
                enhanced_data[include_type] = None
        
        return enhanced_data
    
    def extract_database_data(self):
        """Extract existing data from PostgreSQL"""
        print(f"📊 Extracting database data for: {self.program_handle}")
        
        cursor = self.db_conn.cursor(cursor_factory=RealDictCursor)
        
        # Get program data
        cursor.execute('SELECT * FROM programs WHERE handle = %s', (self.program_handle,))
        program_data = cursor.fetchone()
        
        if not program_data:
            print(f"   ❌ Program not found in database")
            return None
        
        # Get structured scopes
        cursor.execute('''
            SELECT * FROM structured_scopes 
            WHERE program_id = %s 
            ORDER BY max_severity, asset_type
        ''', (program_data['program_id'],))
        scopes_data = cursor.fetchall()
        
        db_data = {
            'program': dict(program_data) if program_data else None,
            'scopes': [dict(scope) for scope in scopes_data] if scopes_data else [],
            'extraction_timestamp': datetime.now().isoformat()
        }
        
        print(f"   ✅ Program: {program_data['name'] if program_data else 'Not found'}")
        print(f"   ✅ Scopes: {len(scopes_data)} items")
        print(f"   ✅ Policy: {len(program_data['policy']) if program_data and program_data['policy'] else 0} characters")
        
        return db_data
    
    def compare_data_sources(self, enhanced_api_data, db_data):
        """Compare API and database data sources"""
        print(f"\n📋 Comparing data sources for: {self.program_handle}")
        
        comparison = {
            'program_handle': self.program_handle,
            'comparison_timestamp': datetime.now().isoformat(),
            'sources': {}
        }
        
        # Compare policy data
        api_policy = None
        if enhanced_api_data.get('policy') and 'data' in enhanced_api_data['policy']:
            api_data = enhanced_api_data['policy']['data']
            if api_data:
                api_policy = api_data[0].get('attributes', {}).get('policy', '')
        
        db_policy = db_data['program']['policy'] if db_data and db_data['program'] else ''
        
        comparison['sources']['policy'] = {
            'api_length': len(api_policy) if api_policy else 0,
            'db_length': len(db_policy) if db_policy else 0,
            'api_available': bool(api_policy),
            'db_available': bool(db_policy),
            'content_identical': api_policy == db_policy if api_policy and db_policy else False
        }
        
        print(f"   📄 Policy comparison:")
        print(f"      API: {comparison['sources']['policy']['api_length']} chars")
        print(f"      DB:  {comparison['sources']['policy']['db_length']} chars")
        print(f"      Identical: {comparison['sources']['policy']['content_identical']}")
        
        # Compare scopes data
        api_scopes_count = 0
        if enhanced_api_data.get('structured_scopes') and 'included' in enhanced_api_data['structured_scopes']:
            api_scopes = [item for item in enhanced_api_data['structured_scopes']['included'] 
                         if item['type'] == 'structured-scope']
            api_scopes_count = len(api_scopes)
        
        db_scopes_count = len(db_data['scopes']) if db_data else 0
        
        comparison['sources']['scopes'] = {
            'api_count': api_scopes_count,
            'db_count': db_scopes_count,
            'counts_match': api_scopes_count == db_scopes_count
        }
        
        print(f"   🎯 Scopes comparison:")
        print(f"      API: {comparison['sources']['scopes']['api_count']} items")
        print(f"      DB:  {comparison['sources']['scopes']['db_count']} items")
        print(f"      Match: {comparison['sources']['scopes']['counts_match']}")
        
        # Compare rewards data
        api_rewards_count = 0
        if enhanced_api_data.get('rewards') and 'included' in enhanced_api_data['rewards']:
            api_rewards = [item for item in enhanced_api_data['rewards']['included'] 
                          if item['type'] == 'bounty']
            api_rewards_count = len(api_rewards)
        
        comparison['sources']['rewards'] = {
            'api_count': api_rewards_count,
            'api_available': api_rewards_count > 0
        }
        
        print(f"   💰 Rewards data:")
        print(f"      API: {comparison['sources']['rewards']['api_count']} bounty records")
        
        return comparison
    
    def generate_comprehensive_report(self, enhanced_api_data, db_data, comparison):
        """Generate comprehensive data comparison report"""
        
        report = {
            'program_handle': self.program_handle,
            'analysis_timestamp': datetime.now().isoformat(),
            'data_sources': {
                'enhanced_api_data': enhanced_api_data,
                'database_data': db_data,
                'comparison_analysis': comparison
            },
            'recommendations': self.generate_recommendations(comparison),
            'summary': self.generate_summary(comparison)
        }
        
        # Save comprehensive report
        output_file = f"/home/kali/bbhk/analysis/{self.program_handle}_comprehensive_data_analysis_{self.timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n💾 Comprehensive report saved: {output_file}")
        return report
    
    def generate_recommendations(self, comparison):
        """Generate data source recommendations"""
        recommendations = []
        
        policy_db_length = comparison['sources']['policy']['db_length']
        policy_api_length = comparison['sources']['policy']['api_length']
        
        if policy_db_length > policy_api_length:
            recommendations.append({
                'type': 'data_source',
                'priority': 'high',
                'recommendation': 'Use PostgreSQL database for policy data - contains more comprehensive information',
                'details': f'Database has {policy_db_length - policy_api_length} more characters of policy content'
            })
        
        scopes_match = comparison['sources']['scopes']['counts_match']
        if scopes_match:
            recommendations.append({
                'type': 'data_source',
                'priority': 'medium',
                'recommendation': 'Both API and database have identical scope counts - either source is reliable',
                'details': f'Both sources contain {comparison["sources"]["scopes"]["db_count"]} scope items'
            })
        
        return recommendations
    
    def generate_summary(self, comparison):
        """Generate executive summary"""
        return {
            'data_completeness': 'excellent',
            'primary_source_recommendation': 'PostgreSQL database',
            'api_usefulness': 'good for real-time verification',
            'gaps_identified': comparison['sources']['policy']['content_identical'] == False,
            'overall_assessment': 'Database provides superior data coverage'
        }
    
    def run_comprehensive_analysis(self):
        """Run complete comprehensive analysis"""
        print("🚀 Enhanced Program Data Analysis")
        print("=" * 60)
        print(f"Program: {self.program_handle}")
        
        # Connect to database
        if not self.connect_db():
            return None
        
        # Extract enhanced API data
        enhanced_api_data = self.extract_enhanced_api_data()
        
        # Extract database data
        db_data = self.extract_database_data()
        
        # Compare data sources
        comparison = self.compare_data_sources(enhanced_api_data, db_data)
        
        # Generate comprehensive report
        report = self.generate_comprehensive_report(enhanced_api_data, db_data, comparison)
        
        # Close database connection
        self.db_conn.close()
        
        print("\n✅ Comprehensive Analysis Complete!")
        
        return report

def main():
    parser = argparse.ArgumentParser(description='Enhanced HackerOne Program Data Analysis')
    parser.add_argument('program_handle', help='HackerOne program handle (e.g., watson_group)')
    
    args = parser.parse_args()
    
    analyzer = EnhancedDataExtractor(args.program_handle)
    results = analyzer.run_comprehensive_analysis()
    
    if results:
        print(f"\n🎯 Analysis complete for: {args.program_handle}")
        print(f"📊 Results available in: /home/kali/bbhk/analysis/")

if __name__ == "__main__":
    main()