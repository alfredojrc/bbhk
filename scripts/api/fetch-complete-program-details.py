#!/usr/bin/env python3
"""
Fetch COMPLETE program details from HackerOne API
Extracts ALL available fields for each program
NO FAKE DATA - Only real API responses
"""

import requests
import json
import time
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional
import os

# Configuration
DB_PATH = "/home/kali/bbhk/core/database/bbhk.db"
API_BASE = "https://api.hackerone.com/v1"
CACHE_DIR = "/home/kali/bbhk/data/api_cache/programs"
DETAILS_FILE = "/home/kali/bbhk/data/program_details.json"

# HackerOne credentials (from existing script)
USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')

class ProgramDetailsFetcher:
    def __init__(self):
        self.session = requests.Session()
        self.session.auth = (USERNAME, API_TOKEN)
        self.session.headers.update({
            'Accept': 'application/json',
            'User-Agent': 'BBHK-DetailsFetcher/1.0'
        })
        os.makedirs(CACHE_DIR, exist_ok=True)
        self.all_program_details = []
        
    def fetch_program_list(self) -> List[Dict]:
        """Get list of all programs from API"""
        print("\n📋 Fetching program list from HackerOne API...")
        
        try:
            response = self.session.get(f"{API_BASE}/hackers/programs")
            if response.status_code == 200:
                data = response.json()
                programs = data.get('data', [])
                print(f"   ✅ Found {len(programs)} programs")
                return programs
        except Exception as e:
            print(f"   ❌ Error fetching programs: {e}")
        
        return []
    
    def fetch_complete_program_details(self, program: Dict) -> Dict:
        """Extract ALL available fields for a program"""
        attributes = program.get('attributes', {})
        relationships = program.get('relationships', {})
        
        # Build comprehensive program object with ALL fields
        complete_details = {
            # Core identifiers
            'id': program.get('id'),
            'type': program.get('type'),
            'handle': attributes.get('handle'),
            'name': attributes.get('name'),
            
            # URLs and media
            'profile_picture': attributes.get('profile_picture'),
            'profile_picture_urls': attributes.get('profile_picture_urls', {}),
            'cover_photo_url': attributes.get('cover_photo_url'),
            'website': attributes.get('website'),
            'twitter_handle': attributes.get('twitter_handle'),
            
            # Program status and configuration
            'state': attributes.get('state'),
            'submission_state': attributes.get('submission_state'),
            'triage_active': attributes.get('triage_active'),
            'publicly_visible_retesting': attributes.get('publicly_visible_retesting'),
            'open_bounty_table': attributes.get('open_bounty_table'),
            'bug_count': attributes.get('bug_count'),
            
            # Bounty information
            'offers_bounties': attributes.get('offers_bounties'),
            'offers_swag': attributes.get('offers_swag'),
            'currency': attributes.get('currency'),
            'total_bounties_paid': attributes.get('total_bounties_paid'),
            'average_bounty': attributes.get('average_bounty'),
            'top_bounty': attributes.get('top_bounty'),
            'bounty_table': attributes.get('bounty_table', {}),
            
            # Response metrics
            'response_efficiency_percentage': attributes.get('response_efficiency_percentage'),
            'first_response_time': attributes.get('first_response_time'),
            'acknowledgement_time': attributes.get('acknowledgement_time'),
            'resolution_time': attributes.get('resolution_time'),
            
            # User-specific data
            'number_of_reports_for_user': attributes.get('number_of_reports_for_user'),
            'number_of_valid_reports_for_user': attributes.get('number_of_valid_reports_for_user'),
            'bounty_earned_for_user': attributes.get('bounty_earned_for_user'),
            'last_invitation_accepted_at_for_user': attributes.get('last_invitation_accepted_at_for_user'),
            'bookmarked': attributes.get('bookmarked'),
            'allows_private_disclosure': attributes.get('allows_private_disclosure'),
            
            # Dates
            'started_accepting_at': attributes.get('started_accepting_at'),
            'created_at': attributes.get('created_at'),
            'updated_at': attributes.get('updated_at'),
            
            # Policy and rules
            'policy': attributes.get('policy'),
            'policy_html': attributes.get('policy_html'),
            'disclosure_policy': attributes.get('disclosure_policy'),
            'response_efficiency_in_words': attributes.get('response_efficiency_in_words'),
            
            # Scope information (will be fetched separately)
            'structured_scopes': [],
            'weaknesses': [],
            
            # Additional metadata
            'managed': attributes.get('managed'),
            'disable_bounty_splitting': attributes.get('disable_bounty_splitting'),
            'allows_bounty_splitting': attributes.get('allows_bounty_splitting'),
            'gold_standard_safe_harbor': attributes.get('gold_standard_safe_harbor'),
            
            # Relationships (store IDs for later expansion)
            'relationships': {
                'weaknesses': relationships.get('weaknesses', {}).get('data', []),
                'structured_scopes': relationships.get('structured_scopes', {}).get('data', []),
                'members': relationships.get('members', {}).get('data', []),
                'groups': relationships.get('groups', {}).get('data', [])
            }
        }
        
        # Try to fetch additional details if handle exists
        if complete_details['handle']:
            time.sleep(0.1)  # Rate limiting
            
            # Fetch structured scopes
            try:
                scope_response = self.session.get(
                    f"{API_BASE}/programs/{complete_details['handle']}/structured_scopes"
                )
                if scope_response.status_code == 200:
                    scope_data = scope_response.json()
                    complete_details['structured_scopes'] = scope_data.get('data', [])
            except:
                pass
            
            # Fetch weaknesses
            try:
                weakness_response = self.session.get(
                    f"{API_BASE}/programs/{complete_details['handle']}/weaknesses"
                )
                if weakness_response.status_code == 200:
                    weakness_data = weakness_response.json()
                    complete_details['weaknesses'] = weakness_data.get('data', [])
            except:
                pass
        
        return complete_details
    
    def process_all_programs(self):
        """Process all programs and extract complete details"""
        print("\n🔍 Extracting complete details for all programs...")
        
        programs = self.fetch_program_list()
        
        for i, program in enumerate(programs, 1):
            print(f"\n   [{i}/{len(programs)}] Processing {program.get('attributes', {}).get('name', 'Unknown')}...")
            
            complete_details = self.fetch_complete_program_details(program)
            self.all_program_details.append(complete_details)
            
            # Save individual program cache
            if complete_details['handle']:
                cache_file = os.path.join(CACHE_DIR, f"{complete_details['handle']}.json")
                with open(cache_file, 'w') as f:
                    json.dump(complete_details, f, indent=2)
            
            # Rate limiting
            if i % 10 == 0:
                print(f"      ⏳ Processed {i} programs, pausing for rate limit...")
                time.sleep(2)
        
        # Save all details to single file
        with open(DETAILS_FILE, 'w') as f:
            json.dump(self.all_program_details, f, indent=2)
        
        print(f"\n✅ Complete details saved for {len(self.all_program_details)} programs")
        print(f"   📁 Individual caches: {CACHE_DIR}")
        print(f"   📄 Complete dataset: {DETAILS_FILE}")
    
    def update_database_with_details(self):
        """Update database with complete program details"""
        print("\n💾 Updating database with complete details...")
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Add new columns if they don't exist
        new_columns = [
            ("response_efficiency_percentage", "REAL"),
            ("first_response_time", "INTEGER"),
            ("total_bounties_paid", "REAL"),
            ("average_bounty", "REAL"),
            ("top_bounty", "REAL"),
            ("bug_count", "INTEGER"),
            ("state", "TEXT"),
            ("submission_state", "TEXT"),
            ("offers_swag", "BOOLEAN"),
            ("policy", "TEXT"),
            ("website", "TEXT"),
            ("twitter_handle", "TEXT"),
            ("profile_picture", "TEXT"),
            ("structured_scopes_json", "TEXT"),
            ("weaknesses_json", "TEXT")
        ]
        
        for col_name, col_type in new_columns:
            try:
                cursor.execute(f"ALTER TABLE programs ADD COLUMN {col_name} {col_type}")
                print(f"   ✅ Added column: {col_name}")
            except sqlite3.OperationalError:
                pass  # Column already exists
        
        # Update each program with complete details
        for details in self.all_program_details:
            if details['name']:
                cursor.execute("""
                    UPDATE programs 
                    SET response_efficiency_percentage = ?,
                        first_response_time = ?,
                        total_bounties_paid = ?,
                        average_bounty = ?,
                        top_bounty = ?,
                        bug_count = ?,
                        state = ?,
                        submission_state = ?,
                        offers_swag = ?,
                        policy = ?,
                        website = ?,
                        twitter_handle = ?,
                        profile_picture = ?,
                        structured_scopes_json = ?,
                        weaknesses_json = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE program_name = ?
                """, (
                    details.get('response_efficiency_percentage'),
                    details.get('first_response_time'),
                    details.get('total_bounties_paid'),
                    details.get('average_bounty'),
                    details.get('top_bounty'),
                    details.get('bug_count'),
                    details.get('state'),
                    details.get('submission_state'),
                    1 if details.get('offers_swag') else 0,
                    details.get('policy', '')[:5000],  # Truncate long policies
                    details.get('website'),
                    details.get('twitter_handle'),
                    details.get('profile_picture'),
                    json.dumps(details.get('structured_scopes', [])),
                    json.dumps(details.get('weaknesses', [])),
                    details['name']
                ))
        
        conn.commit()
        conn.close()
        
        print(f"   ✅ Database updated with complete details")
    
    def generate_field_report(self):
        """Generate report of all available fields"""
        print("\n📊 Generating field availability report...")
        
        # Count non-null values for each field
        field_counts = {}
        
        for details in self.all_program_details:
            for key, value in details.items():
                if key not in field_counts:
                    field_counts[key] = 0
                if value is not None and value != "" and value != [] and value != {}:
                    field_counts[key] += 1
        
        # Sort by availability
        sorted_fields = sorted(field_counts.items(), key=lambda x: x[1], reverse=True)
        
        report_path = "/home/kali/bbhk/docs/PROGRAM-FIELDS-AVAILABLE.md"
        with open(report_path, 'w') as f:
            f.write("# HackerOne Program Fields Available\n\n")
            f.write(f"**Total Programs Analyzed**: {len(self.all_program_details)}\n")
            f.write(f"**Generated**: {datetime.now().isoformat()}\n\n")
            f.write("## Field Availability\n\n")
            f.write("| Field Name | Programs with Data | Coverage % |\n")
            f.write("|------------|-------------------|------------|\n")
            
            total_programs = len(self.all_program_details)
            for field, count in sorted_fields:
                percentage = (count / total_programs * 100) if total_programs > 0 else 0
                f.write(f"| {field} | {count} | {percentage:.1f}% |\n")
            
            f.write("\n## Key Insights\n\n")
            f.write("### Always Available Fields\n")
            for field, count in sorted_fields:
                if count == total_programs:
                    f.write(f"- {field}\n")
            
            f.write("\n### Commonly Available Fields (>80%)\n")
            for field, count in sorted_fields:
                percentage = (count / total_programs * 100) if total_programs > 0 else 0
                if percentage > 80 and count < total_programs:
                    f.write(f"- {field} ({percentage:.1f}%)\n")
            
            f.write("\n### Rarely Available Fields (<20%)\n")
            for field, count in sorted_fields:
                percentage = (count / total_programs * 100) if total_programs > 0 else 0
                if percentage < 20:
                    f.write(f"- {field} ({percentage:.1f}%)\n")
        
        print(f"   ✅ Field report saved to {report_path}")

def main():
    print("=" * 60)
    print("FETCHING COMPLETE PROGRAM DETAILS FROM HACKERONE")
    print("NO FAKE DATA - ONLY REAL API RESPONSES")
    print("=" * 60)
    
    fetcher = ProgramDetailsFetcher()
    
    # Process all programs
    fetcher.process_all_programs()
    
    # Update database
    fetcher.update_database_with_details()
    
    # Generate field report
    fetcher.generate_field_report()
    
    print("\n" + "=" * 60)
    print("✅ COMPLETE PROGRAM DETAILS EXTRACTION FINISHED")
    print("=" * 60)
    print(f"📁 Program caches: {CACHE_DIR}")
    print(f"📄 Complete dataset: {DETAILS_FILE}")
    print(f"📊 Field report: /home/kali/bbhk/docs/PROGRAM-FIELDS-AVAILABLE.md")
    print(f"💾 Database: Updated with all available fields")
    print("\n🚨 ALL DATA IS REAL FROM HACKERONE API - NO FAKE DATA")

if __name__ == "__main__":
    main()