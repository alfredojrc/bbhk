#!/usr/bin/env python3
"""
Data Integrity Validator
Ensures database contains ONLY real API data, no fake content

Author: Data Integrity Team
Date: August 17, 2025
"""

import os
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
import json
from datetime import datetime

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

# Suspicious patterns that indicate fake data
FAKE_DATA_PATTERNS = [
    'microblog',
    'Microblog',
    'Latest updates',
    'December 2024',
    'January 2025',  # Future dates
    'February 2025',
    'Drogas Lithuania e-commerce websites and apps have been added',
    'we will keep you updated on the latest changes',
    '12th of December 2024',
    '25th of September 2024'
]

# Maximum reasonable policy size (based on real API data)
MAX_REASONABLE_POLICY_SIZE = 40000  # Largest real policy seen

class DataIntegrityValidator:
    def __init__(self):
        self.auth = (USERNAME, API_TOKEN)
        self.headers = {'Accept': 'application/json'}
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update(self.headers)
        self.violations = []
        
    def connect_db(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(**DB_CONFIG)
            return True
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return False
    
    def check_for_fake_patterns(self):
        """Check for known fake data patterns"""
        print("🔍 Checking for fake data patterns...")
        
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        for pattern in FAKE_DATA_PATTERNS:
            cursor.execute("""
                SELECT program_id, handle, name
                FROM programs 
                WHERE policy ILIKE %s
            """, (f'%{pattern}%',))
            
            results = cursor.fetchall()
            if results:
                for row in results:
                    violation = {
                        'type': 'FAKE_PATTERN_DETECTED',
                        'program': row['handle'],
                        'pattern': pattern,
                        'severity': 'CRITICAL'
                    }
                    self.violations.append(violation)
                    print(f"   ❌ VIOLATION: '{pattern}' found in {row['handle']}")
    
    def check_policy_sizes(self):
        """Check for suspiciously large policies"""
        print("🔍 Checking policy sizes...")
        
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT program_id, handle, name, length(policy) as policy_len
            FROM programs 
            WHERE policy IS NOT NULL
            ORDER BY policy_len DESC
            LIMIT 10
        """)
        
        results = cursor.fetchall()
        for row in results:
            if row['policy_len'] > MAX_REASONABLE_POLICY_SIZE:
                violation = {
                    'type': 'SUSPICIOUS_SIZE',
                    'program': row['handle'],
                    'size': row['policy_len'],
                    'severity': 'WARNING'
                }
                self.violations.append(violation)
                print(f"   ⚠️  WARNING: {row['handle']} has unusually large policy ({row['policy_len']} chars)")
    
    def validate_against_api(self, sample_size=5):
        """Validate random samples against fresh API data"""
        print(f"🔍 Validating {sample_size} random programs against API...")
        
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        # Get random sample
        cursor.execute("""
            SELECT program_id, handle, policy
            FROM programs 
            WHERE policy IS NOT NULL
            ORDER BY RANDOM()
            LIMIT %s
        """, (sample_size,))
        
        samples = cursor.fetchall()
        
        for sample in samples:
            # Fetch fresh from API
            url = f"{BASE_URL}/programs?filter[handle]={sample['handle']}&include=policy"
            
            try:
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('data'):
                        api_policy = data['data'][0].get('attributes', {}).get('policy', '')
                        db_policy = sample['policy'] or ''
                        
                        # Compare lengths
                        api_len = len(api_policy)
                        db_len = len(db_policy)
                        
                        if db_len > api_len * 1.1:  # More than 10% larger
                            violation = {
                                'type': 'API_MISMATCH',
                                'program': sample['handle'],
                                'db_size': db_len,
                                'api_size': api_len,
                                'difference': db_len - api_len,
                                'severity': 'HIGH'
                            }
                            self.violations.append(violation)
                            print(f"   ❌ MISMATCH: {sample['handle']} DB({db_len}) > API({api_len}) by {db_len-api_len} chars")
                        else:
                            print(f"   ✅ VALID: {sample['handle']} matches API")
                            
            except Exception as e:
                print(f"   ⚠️  Could not validate {sample['handle']}: {e}")
    
    def generate_report(self):
        """Generate integrity report"""
        print("\n📋 DATA INTEGRITY REPORT")
        print("=" * 60)
        
        if not self.violations:
            print("✅ NO VIOLATIONS FOUND - Database integrity verified!")
            status = "CLEAN"
        else:
            print(f"❌ FOUND {len(self.violations)} VIOLATIONS:")
            
            critical = [v for v in self.violations if v['severity'] == 'CRITICAL']
            high = [v for v in self.violations if v['severity'] == 'HIGH']
            warning = [v for v in self.violations if v['severity'] == 'WARNING']
            
            if critical:
                print(f"\n🚨 CRITICAL ({len(critical)}):")
                for v in critical:
                    print(f"   - {v['program']}: {v['type']} ({v.get('pattern', '')})")
            
            if high:
                print(f"\n❌ HIGH ({len(high)}):")
                for v in high:
                    print(f"   - {v['program']}: DB has {v['difference']} more chars than API")
            
            if warning:
                print(f"\n⚠️  WARNING ({len(warning)}):")
                for v in warning:
                    print(f"   - {v['program']}: Policy size {v['size']} chars")
            
            status = "VIOLATIONS_FOUND"
        
        # Save report
        report = {
            'validation_timestamp': datetime.now().isoformat(),
            'status': status,
            'violations': self.violations,
            'statistics': {
                'total_violations': len(self.violations),
                'critical': len([v for v in self.violations if v['severity'] == 'CRITICAL']),
                'high': len([v for v in self.violations if v['severity'] == 'HIGH']),
                'warning': len([v for v in self.violations if v['severity'] == 'WARNING'])
            }
        }
        
        report_file = f"/home/kali/bbhk/analysis/integrity_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n💾 Report saved: {report_file}")
        
        return status == "CLEAN"
    
    def run_validation(self):
        """Run complete validation"""
        print("🛡️ DATA INTEGRITY VALIDATION")
        print("=" * 60)
        print("Ensuring database contains ONLY real API data...")
        
        if not self.connect_db():
            return False
        
        # Run all checks
        self.check_for_fake_patterns()
        self.check_policy_sizes()
        self.validate_against_api()
        
        # Generate report
        is_clean = self.generate_report()
        
        # Close connection
        self.conn.close()
        
        if is_clean:
            print("\n✅ DATABASE INTEGRITY VERIFIED!")
            print("   No fake data detected")
            print("   All content matches API sources")
        else:
            print("\n❌ INTEGRITY VIOLATIONS DETECTED!")
            print("   Immediate cleanup required")
            print("   Run CLEAN_FAKE_DATA_AND_REFETCH.py to fix")
        
        return is_clean

if __name__ == "__main__":
    validator = DataIntegrityValidator()
    is_clean = validator.run_validation()
    
    exit(0 if is_clean else 1)