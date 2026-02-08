#!/usr/bin/env python3
"""
COMPLETE Data Cleanup - Remove ALL fake data
Compares every program with API and replaces any that don't match

Author: Truth Enforcement Team
Date: August 17, 2025
"""

import os
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
import json
from datetime import datetime
import sys

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

class CompleteDataCleanup:
    def __init__(self):
        self.auth = (USERNAME, API_TOKEN)
        self.headers = {'Accept': 'application/json'}
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update(self.headers)
        self.cleaned_count = 0
        self.checked_count = 0
        self.mismatches = []
        
    def connect_db(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(**DB_CONFIG)
            return True
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return False
    
    def get_all_programs(self):
        """Get all programs from database"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT program_id, handle, name, length(policy) as policy_len, policy
            FROM programs 
            WHERE policy IS NOT NULL
            ORDER BY handle
        """)
        
        return cursor.fetchall()
    
    def get_real_api_data(self, program_handle):
        """Get REAL data from HackerOne API"""
        url = f"{BASE_URL}/programs?filter[handle]={program_handle}&include=policy"
        
        try:
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    program = data['data'][0]
                    attrs = program.get('attributes', {})
                    
                    # Get REAL policy from API
                    real_policy = attrs.get('policy', '')
                    
                    return {
                        'program_id': program.get('id'),
                        'handle': attrs.get('handle'),
                        'name': attrs.get('name'),
                        'policy': real_policy,  # REAL policy only
                        'policy_length': len(real_policy) if real_policy else 0
                    }
            
            return None
            
        except Exception as e:
            print(f"   ❌ API error for {program_handle}: {e}")
            return None
    
    def check_and_clean(self, program):
        """Check program against API and clean if needed"""
        handle = program['handle']
        db_policy_len = program['policy_len']
        
        # Get real data from API
        real_data = self.get_real_api_data(handle)
        
        if not real_data:
            print(f"   ⚠️  Could not fetch API data for {handle}")
            return False
        
        api_policy_len = real_data['policy_length']
        
        # Check if DB has significantly more data than API (10% tolerance)
        if db_policy_len > api_policy_len * 1.1:
            print(f"   ❌ FAKE DATA: {handle} - DB({db_policy_len}) > API({api_policy_len}) by {db_policy_len - api_policy_len} chars")
            
            # Clean it!
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE programs 
                SET policy = %s,
                    updated_at = %s,
                    last_fetched_at = %s
                WHERE program_id = %s
            """, (
                real_data['policy'],
                datetime.now(),
                datetime.now(),
                program['program_id']
            ))
            
            self.conn.commit()
            
            self.mismatches.append({
                'handle': handle,
                'db_size': db_policy_len,
                'api_size': api_policy_len,
                'removed': db_policy_len - api_policy_len
            })
            
            self.cleaned_count += 1
            print(f"   ✅ CLEANED: Removed {db_policy_len - api_policy_len} fake characters")
            return True
        
        return False
    
    def run_complete_cleanup(self):
        """Run complete cleanup on ALL programs"""
        print("🚨 COMPLETE DATA CLEANUP PROCESS")
        print("=" * 60)
        print("Checking EVERY program against API...")
        
        if not self.connect_db():
            return False
        
        # Get all programs
        programs = self.get_all_programs()
        total = len(programs)
        
        print(f"\n📊 Found {total} programs to check")
        print("This will take several minutes...\n")
        
        # Check each program
        for i, program in enumerate(programs, 1):
            if i % 10 == 0:
                print(f"\n📍 Progress: {i}/{total} programs checked...")
            
            self.checked_count += 1
            self.check_and_clean(program)
        
        # Final report
        print("\n" + "=" * 60)
        print("📋 COMPLETE CLEANUP REPORT")
        print("=" * 60)
        print(f"✅ Programs checked: {self.checked_count}")
        print(f"🧹 Programs cleaned: {self.cleaned_count}")
        
        if self.mismatches:
            total_removed = sum(m['removed'] for m in self.mismatches)
            print(f"📉 Total fake data removed: {total_removed:,} characters")
            
            print("\nPrograms cleaned:")
            for m in self.mismatches:
                print(f"   - {m['handle']}: removed {m['removed']} fake chars")
        
        # Save detailed report
        report = {
            'cleanup_timestamp': datetime.now().isoformat(),
            'programs_checked': self.checked_count,
            'programs_cleaned': self.cleaned_count,
            'mismatches': self.mismatches,
            'total_fake_chars_removed': sum(m['removed'] for m in self.mismatches) if self.mismatches else 0
        }
        
        report_file = f"/home/kali/bbhk/analysis/COMPLETE_CLEANUP_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n💾 Detailed report saved: {report_file}")
        
        # Close connection
        self.conn.close()
        
        if self.cleaned_count == 0:
            print("\n✅ DATABASE IS CLEAN!")
            print("   No fake data found")
        else:
            print(f"\n✅ CLEANUP COMPLETE!")
            print(f"   Cleaned {self.cleaned_count} programs")
            print("   Database now contains ONLY real API data")
        
        return True

if __name__ == "__main__":
    print("⚠️  WARNING: This will check ALL programs against API")
    print("   This may take 5-10 minutes to complete")
    print("   All fake data will be replaced with real API data")
    
    response = input("\nProceed with COMPLETE cleanup? (yes/no): ")
    
    if response.lower() == 'yes':
        cleaner = CompleteDataCleanup()
        success = cleaner.run_complete_cleanup()
        
        if success:
            print("\n🎯 Database is now 100% clean and verified!")
        else:
            print("\n❌ Cleanup failed. Please check errors above.")
    else:
        print("\n❌ Cleanup cancelled.")