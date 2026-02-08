#!/usr/bin/env python3
"""
HackerOne Real Data Fetcher - FIXED VERSION
Fetches 100% authentic data from HackerOne API
ALLOWS legitimate test subdomains but blocks fake programs
"""

import os
import sys
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import time
import logging
from dotenv import load_dotenv

# Load environment
load_dotenv('/home/kali/bbhk/.env')

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealDataFetcher:
    def __init__(self):
        self.api_username = os.getenv('HACKERONE_API_USERNAME')
        self.api_token = os.getenv('HACKERONE_API_TOKEN')
        self.pg_config = {
            'host': 'localhost',
            'port': 5432,
            'database': 'bbhk_db',
            'user': 'bbhk_user',
            'password': os.getenv('POSTGRES_PASSWORD', '')
        }
        self.session = requests.Session()
        self.stats = {
            'programs_fetched': 0,
            'scopes_fetched': 0,
            'programs_stored': 0,
            'fake_programs_blocked': 0
        }
        
    def connect_db(self):
        """Connect to PostgreSQL"""
        try:
            conn = psycopg2.connect(**self.pg_config)
            logger.info("✅ Connected to PostgreSQL")
            return conn
        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            return None
    
    def is_fake_program(self, program_data):
        """Check if program is fake/test (but allow legitimate programs)"""
        attrs = program_data.get('attributes', {})
        handle = attrs.get('handle', '').lower()
        name = attrs.get('name', '').lower()
        
        # Block obvious test/fake programs
        fake_indicators = [
            'security-test-', 'test-program', 'fake-', 'sample-', 'demo-program',
            'example-', 'dummy-'
        ]
        
        for indicator in fake_indicators:
            if indicator in handle or indicator in name:
                self.stats['fake_programs_blocked'] += 1
                logger.warning(f"⚠️ Blocked fake program: {handle}")
                return True
        
        # Allow HackerOne's legitimate test programs (they use these for documentation)
        if handle in ['security', 'hackerone']:
            return False
            
        return False
    
    def fetch_programs(self, limit=100):
        """Fetch real HackerOne programs"""
        logger.info(f"🚀 Fetching up to {limit} real HackerOne programs...")
        
        programs = []
        page = 1
        
        while len(programs) < limit:
            try:
                response = self.session.get(
                    'https://api.hackerone.com/v1/hackers/programs',
                    auth=(self.api_username, self.api_token),
                    params={
                        'page[size]': min(100, limit - len(programs)),
                        'page[number]': page
                    },
                    timeout=30
                )
                
                if response.status_code != 200:
                    logger.error(f"❌ API error: {response.status_code}")
                    break
                
                data = response.json()
                if not data.get('data'):
                    break
                
                for program in data['data']:
                    if not self.is_fake_program(program):
                        programs.append(program)
                        self.stats['programs_fetched'] += 1
                
                if not data.get('links', {}).get('next'):
                    break
                    
                page += 1
                time.sleep(1)  # Rate limiting
                
            except Exception as e:
                logger.error(f"❌ Error fetching programs: {e}")
                break
        
        logger.info(f"📦 Fetched {len(programs)} real programs (blocked {self.stats['fake_programs_blocked']} fake)")
        return programs
    
    def store_program(self, conn, program_data):
        """Store real program in database"""
        attrs = program_data.get('attributes', {})
        program_id = program_data.get('id')
        
        try:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO programs (
                    id, handle, name, currency, policy, profile_picture,
                    submission_state, triage_active, state, started_accepting_at,
                    number_of_reports_for_user, number_of_valid_reports_for_user,
                    bounty_earned_for_user, last_invitation_accepted_at_for_user,
                    bookmarked, allows_bounty_splitting, offers_bounties,
                    open_scope, fast_payments, gold_standard_safe_harbor
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                ) ON CONFLICT (id) DO UPDATE SET
                    name = EXCLUDED.name,
                    submission_state = EXCLUDED.submission_state,
                    updated_at = CURRENT_TIMESTAMP
            """, (
                program_id,
                attrs.get('handle'),
                attrs.get('name'),
                attrs.get('currency', 'usd'),
                attrs.get('policy'),
                attrs.get('profile_picture'),
                attrs.get('submission_state'),
                attrs.get('triage_active', False),
                attrs.get('state'),
                attrs.get('started_accepting_at'),
                attrs.get('number_of_reports_for_user', 0),
                attrs.get('number_of_valid_reports_for_user', 0),
                attrs.get('bounty_earned_for_user', 0.0),
                attrs.get('last_invitation_accepted_at_for_user'),
                attrs.get('bookmarked', False),
                attrs.get('allows_bounty_splitting', False),
                attrs.get('offers_bounties', False),
                attrs.get('open_scope', False),
                attrs.get('fast_payments', False),
                attrs.get('gold_standard_safe_harbor', False)
            ))
            
            conn.commit()
            self.stats['programs_stored'] += 1
            logger.info(f"✅ Stored program: {attrs.get('name')} ({attrs.get('handle')})")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error storing program: {e}")
            conn.rollback()
            return False
    
    def fetch_and_store_scopes(self, conn, program_handle, program_id):
        """Fetch and store program scopes"""
        try:
            response = self.session.get(
                f'https://api.hackerone.com/v1/hackers/programs/{program_handle}/structured_scopes',
                auth=(self.api_username, self.api_token),
                timeout=30
            )
            
            if response.status_code != 200:
                return
            
            data = response.json()
            scopes = data.get('data', [])
            
            cursor = conn.cursor()
            
            for scope in scopes:
                attrs = scope.get('attributes', {})
                scope_id = scope.get('id')
                
                cursor.execute("""
                    INSERT INTO structured_scopes (
                        id, program_id, asset_type, asset_identifier,
                        instruction, eligible_for_bounty, eligible_for_submission,
                        max_severity, confidentiality_requirement,
                        integrity_requirement, availability_requirement
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                """, (
                    scope_id,
                    program_id,
                    attrs.get('asset_type'),
                    attrs.get('asset_identifier'),
                    attrs.get('instruction'),
                    attrs.get('eligible_for_bounty', False),
                    attrs.get('eligible_for_submission', False),
                    attrs.get('max_severity'),
                    attrs.get('confidentiality_requirement'),
                    attrs.get('integrity_requirement'),
                    attrs.get('availability_requirement')
                ))
                
                self.stats['scopes_fetched'] += 1
            
            conn.commit()
            logger.info(f"  📍 Stored {len(scopes)} scopes for {program_handle}")
            
        except Exception as e:
            logger.error(f"❌ Error fetching scopes for {program_handle}: {e}")
    
    def run(self, limit=50):
        """Execute the real data fetching pipeline"""
        logger.info("🚀 STARTING REAL HACKERONE DATA COLLECTION")
        logger.info("=" * 50)
        logger.info("⚠️ ZERO TOLERANCE FOR FAKE DATA!")
        logger.info("=" * 50)
        
        # Connect to database
        conn = self.connect_db()
        if not conn:
            sys.exit(1)
        
        # Fetch programs
        programs = self.fetch_programs(limit)
        if not programs:
            logger.error("❌ No programs fetched")
            sys.exit(1)
        
        # Process each program
        for i, program in enumerate(programs, 1):
            attrs = program.get('attributes', {})
            handle = attrs.get('handle', '')
            program_id = program.get('id')
            
            logger.info(f"[{i}/{len(programs)}] Processing: {handle}")
            
            # Store program
            if self.store_program(conn, program):
                # Fetch scopes
                self.fetch_and_store_scopes(conn, handle, program_id)
            
            # Rate limiting
            time.sleep(0.5)
        
        # Final verification
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM programs")
        program_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM structured_scopes") 
        scope_count = cursor.fetchone()[0]
        
        logger.info("=" * 50)
        logger.info("📊 REAL DATA COLLECTION COMPLETE:")
        logger.info(f"  Programs stored: {program_count}")
        logger.info(f"  Scopes stored: {scope_count}")
        logger.info(f"  Fake programs blocked: {self.stats['fake_programs_blocked']}")
        logger.info("=" * 50)
        logger.info("✅ 100% REAL HACKERONE DATA POPULATED!")
        
        conn.close()

if __name__ == "__main__":
    limit = 50
    if len(sys.argv) > 1:
        try:
            limit = int(sys.argv[1])
        except ValueError:
            logger.error("Invalid limit argument")
            sys.exit(1)
    
    fetcher = RealDataFetcher()
    fetcher.run(limit)