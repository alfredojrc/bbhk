#!/usr/bin/env python3
"""
Comprehensive HackerOne Data Fetcher
Date: August 20, 2025
Author: BBHK Team

This enhanced script fetches ALL available data from HackerOne HACKER API:
1. Programs and structured scopes (existing)
2. Reports submitted by the user
3. Bounties earned
4. Earnings and payment history
5. Hacktivity (public disclosures)
6. Balance information
7. Invitations (if available)

Stores everything in PostgreSQL for comprehensive analysis.
"""

import requests
import psycopg2
from psycopg2.extras import RealDictCursor, Json
import json
import time
from datetime import datetime, timedelta
import logging
import sys
from typing import Dict, List, Optional, Any
import os
from decimal import Decimal

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from api_data_validator import validate_before_insert

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fetch_comprehensive_data.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# HackerOne API Configuration
USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"

# PostgreSQL Configuration
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'bbhk_db',
    'user': 'bbhk_user',
    'password': os.getenv('POSTGRES_PASSWORD', '')
}

class ComprehensiveHackerOneFetcher:
    def __init__(self):
        self.auth = (USERNAME, API_TOKEN)
        self.headers = {'Accept': 'application/json'}
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update(self.headers)
        self.db_conn = None
        self.stats = {
            'programs_fetched': 0,
            'scopes_fetched': 0,
            'reports_fetched': 0,
            'bounties_fetched': 0,
            'earnings_fetched': 0,
            'hacktivity_fetched': 0
        }
        
    def connect_db(self):
        """Connect to PostgreSQL database"""
        try:
            self.db_conn = psycopg2.connect(**DB_CONFIG)
            logger.info("✅ Connected to PostgreSQL")
            return True
        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            return False
    
    def fetch_with_pagination(self, endpoint: str, params: Dict = None) -> List[Dict]:
        """Generic function to fetch paginated data from any endpoint"""
        all_data = []
        page_number = 1
        next_url = f"{BASE_URL}/{endpoint}"
        
        if params is None:
            params = {}
        params['page[size]'] = 100  # Max page size
        
        while next_url:
            logger.info(f"📄 Fetching page {page_number} from {endpoint}...")
            
            try:
                if page_number == 1:
                    response = self.session.get(next_url, params=params, timeout=30)
                else:
                    response = self.session.get(next_url, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    items = data.get('data', [])
                    
                    logger.info(f"   ✅ Retrieved {len(items)} items")
                    all_data.extend(items)
                    
                    # Get next page
                    links = data.get('links', {})
                    next_url = links.get('next')
                    page_number += 1
                    
                    # Rate limiting
                    time.sleep(0.5)
                    
                elif response.status_code == 404:
                    logger.warning(f"   ⚠️ Endpoint not found: {endpoint}")
                    break
                elif response.status_code == 429:
                    logger.warning(f"   ⚠️ Rate limited. Waiting 60 seconds...")
                    time.sleep(60)
                    continue
                else:
                    logger.error(f"   ❌ Error: HTTP {response.status_code}")
                    logger.error(f"   Response: {response.text[:500]}")
                    break
                    
            except Exception as e:
                logger.error(f"   ❌ Exception: {e}")
                break
        
        logger.info(f"✅ Total items fetched from {endpoint}: {len(all_data)}")
        return all_data
    
    def fetch_all_programs(self) -> List[Dict]:
        """Fetch all programs from HACKER API"""
        logger.info("🔍 Fetching all programs...")
        programs = self.fetch_with_pagination("programs")
        self.stats['programs_fetched'] = len(programs)
        return programs
    
    def fetch_my_reports(self) -> List[Dict]:
        """Fetch all reports submitted by the user"""
        logger.info("📝 Fetching my reports...")
        reports = self.fetch_with_pagination("me/reports")
        self.stats['reports_fetched'] = len(reports)
        return reports
    
    def fetch_earnings(self) -> Dict:
        """Fetch earnings information"""
        logger.info("💰 Fetching earnings...")
        
        try:
            response = self.session.get(f"{BASE_URL}/payments/earnings", timeout=30)
            if response.status_code == 200:
                data = response.json()
                logger.info("   ✅ Earnings data retrieved")
                return data
            else:
                logger.error(f"   ❌ Failed to fetch earnings: {response.status_code}")
                return {}
        except Exception as e:
            logger.error(f"   ❌ Exception fetching earnings: {e}")
            return {}
    
    def fetch_balance(self) -> Dict:
        """Fetch current balance information"""
        logger.info("💳 Fetching balance...")
        
        try:
            response = self.session.get(f"{BASE_URL}/payments/balance", timeout=30)
            if response.status_code == 200:
                data = response.json()
                logger.info("   ✅ Balance data retrieved")
                return data
            else:
                logger.error(f"   ❌ Failed to fetch balance: {response.status_code}")
                return {}
        except Exception as e:
            logger.error(f"   ❌ Exception fetching balance: {e}")
            return {}
    
    def fetch_hacktivity(self, days_back: int = 30) -> List[Dict]:
        """Fetch recent hacktivity (public disclosures)"""
        logger.info(f"🔍 Fetching hacktivity (last {days_back} days)...")
        
        # Build query for recent disclosures
        date_from = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")
        params = {
            'queryString': f'disclosed_at:>={date_from}'
        }
        
        hacktivity = self.fetch_with_pagination("hacktivity", params)
        self.stats['hacktivity_fetched'] = len(hacktivity)
        return hacktivity
    
    def fetch_invitations(self) -> List[Dict]:
        """Attempt to fetch invitations (may not be available in API)"""
        logger.info("📨 Attempting to fetch invitations...")
        
        # Try multiple possible endpoints
        endpoints = ["me/invitations", "invitations", "programs/invitations"]
        
        for endpoint in endpoints:
            try:
                response = self.session.get(f"{BASE_URL}/{endpoint}", timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"   ✅ Found invitations at {endpoint}")
                    return data.get('data', [])
            except:
                continue
        
        logger.info("   ℹ️ Invitations endpoint not available or no invitations")
        return []
    
    def store_reports(self, reports: List[Dict]):
        """Store reports in the database"""
        if not reports:
            return
        
        logger.info(f"💾 Storing {len(reports)} reports...")
        cursor = self.db_conn.cursor()
        
        for report in reports:
            try:
                attrs = report.get('attributes', {})
                relationships = report.get('relationships', {})
                
                # Extract program info
                program_data = relationships.get('program', {}).get('data', {})
                program_handle = program_data.get('attributes', {}).get('handle', '')
                
                # Extract reporter info
                reporter_data = relationships.get('reporter', {}).get('data', {})
                reporter_username = reporter_data.get('attributes', {}).get('username', USERNAME)
                
                # Parse timestamps
                created_at = attrs.get('created_at')
                triaged_at = attrs.get('triaged_at')
                closed_at = attrs.get('closed_at')
                disclosed_at = attrs.get('disclosed_at')
                
                # Calculate response times (in seconds)
                time_to_triage = None
                if created_at and triaged_at:
                    try:
                        created = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                        triaged = datetime.fromisoformat(triaged_at.replace('Z', '+00:00'))
                        time_to_triage = int((triaged - created).total_seconds())
                    except:
                        pass
                
                cursor.execute("""
                    INSERT INTO hacker_reports (
                        report_id, title, state, substate, severity_rating,
                        program_handle, weakness_id, weakness_name,
                        vulnerability_information, impact,
                        structured_scope_id, asset_type, asset_identifier,
                        reporter_username, reporter_reputation, reporter_signal,
                        has_collaboration, collaborator_count,
                        bounty_awarded, total_awarded_amount, currency,
                        created_at, triaged_at, closed_at, disclosed_at,
                        time_to_triage, is_participant, raw_data
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 
                             %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (report_id) DO UPDATE SET
                        state = EXCLUDED.state,
                        substate = EXCLUDED.substate,
                        total_awarded_amount = EXCLUDED.total_awarded_amount,
                        triaged_at = EXCLUDED.triaged_at,
                        closed_at = EXCLUDED.closed_at,
                        disclosed_at = EXCLUDED.disclosed_at,
                        raw_data = EXCLUDED.raw_data,
                        updated_at = CURRENT_TIMESTAMP
                """, (
                    report.get('id'),
                    attrs.get('title'),
                    attrs.get('state'),
                    attrs.get('substate'),
                    attrs.get('severity_rating'),
                    program_handle,
                    attrs.get('weakness', {}).get('id'),
                    attrs.get('weakness', {}).get('name'),
                    attrs.get('vulnerability_information'),
                    attrs.get('impact'),
                    attrs.get('structured_scope', {}).get('id'),
                    attrs.get('structured_scope', {}).get('asset_type'),
                    attrs.get('structured_scope', {}).get('asset_identifier'),
                    reporter_username,
                    reporter_data.get('attributes', {}).get('reputation'),
                    reporter_data.get('attributes', {}).get('signal'),
                    attrs.get('has_collaboration', False),
                    len(attrs.get('collaborators', [])),
                    attrs.get('bounty_awarded', False),
                    attrs.get('total_awarded_amount'),
                    attrs.get('currency', 'USD'),
                    created_at,
                    triaged_at,
                    closed_at,
                    disclosed_at,
                    time_to_triage,
                    True,  # is_participant (these are our reports)
                    Json(report)
                ))
                
            except Exception as e:
                logger.error(f"   ❌ Error storing report {report.get('id')}: {e}")
                self.db_conn.rollback()
                continue
        
        self.db_conn.commit()
        logger.info(f"   ✅ Stored {len(reports)} reports")
    
    def store_hacktivity(self, hacktivity_items: List[Dict]):
        """Store hacktivity items in the database"""
        if not hacktivity_items:
            return
        
        logger.info(f"💾 Storing {len(hacktivity_items)} hacktivity items...")
        cursor = self.db_conn.cursor()
        
        for item in hacktivity_items:
            try:
                attrs = item.get('attributes', {})
                relationships = item.get('relationships', {})
                
                # Extract program info
                program_data = relationships.get('program', {}).get('data', {})
                program_attrs = program_data.get('attributes', {})
                
                # Extract reporter info
                reporter_data = relationships.get('reporter', {}).get('data', {})
                reporter_attrs = reporter_data.get('attributes', {})
                
                cursor.execute("""
                    INSERT INTO hacktivity (
                        hacktivity_id, report_id, report_title,
                        program_handle, program_name,
                        severity_rating, weakness_name,
                        reporter_username, reporter_reputation,
                        total_awarded_amount, currency,
                        disclosed_at, vote_count, comment_count, raw_data
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (hacktivity_id) DO UPDATE SET
                        vote_count = EXCLUDED.vote_count,
                        comment_count = EXCLUDED.comment_count,
                        raw_data = EXCLUDED.raw_data,
                        fetched_at = CURRENT_TIMESTAMP
                """, (
                    item.get('id'),
                    attrs.get('report_id'),
                    attrs.get('title'),
                    program_attrs.get('handle'),
                    program_attrs.get('name'),
                    attrs.get('severity_rating'),
                    attrs.get('weakness', {}).get('name'),
                    reporter_attrs.get('username'),
                    reporter_attrs.get('reputation'),
                    attrs.get('total_awarded_amount'),
                    attrs.get('currency', 'USD'),
                    attrs.get('disclosed_at'),
                    attrs.get('vote_count', 0),
                    attrs.get('comment_count', 0),
                    Json(item)
                ))
                
            except Exception as e:
                logger.error(f"   ❌ Error storing hacktivity {item.get('id')}: {e}")
                self.db_conn.rollback()
                continue
        
        self.db_conn.commit()
        logger.info(f"   ✅ Stored {len(hacktivity_items)} hacktivity items")
    
    def store_balance(self, balance_data: Dict):
        """Store balance information"""
        if not balance_data:
            return
        
        logger.info("💾 Storing balance information...")
        cursor = self.db_conn.cursor()
        
        try:
            data = balance_data.get('data', {})
            attrs = data.get('attributes', {}) if isinstance(data, dict) else {}
            
            # Calculate YTD earnings
            current_year = datetime.now().year
            
            cursor.execute("""
                INSERT INTO balance (
                    available_balance, pending_balance, total_balance, currency,
                    lifetime_earnings, lifetime_payouts,
                    ytd_earnings, ytd_tax_year,
                    fetched_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            """, (
                attrs.get('available_balance', 0),
                attrs.get('pending_balance', 0),
                attrs.get('total_balance', 0),
                attrs.get('currency', 'USD'),
                attrs.get('lifetime_earnings', 0),
                attrs.get('lifetime_payouts', 0),
                attrs.get('ytd_earnings', 0),
                current_year
            ))
            
            self.db_conn.commit()
            logger.info("   ✅ Balance information stored")
            
        except Exception as e:
            logger.error(f"   ❌ Error storing balance: {e}")
            self.db_conn.rollback()
    
    def store_earnings(self, earnings_data: Dict):
        """Store earnings information"""
        if not earnings_data:
            return
        
        logger.info("💾 Storing earnings information...")
        cursor = self.db_conn.cursor()
        
        try:
            # Handle both list and paginated response formats
            if 'data' in earnings_data:
                earnings = earnings_data.get('data', [])
                if isinstance(earnings, dict):
                    earnings = [earnings]
            else:
                earnings = []
            
            for earning in earnings:
                attrs = earning.get('attributes', {})
                
                cursor.execute("""
                    INSERT INTO earnings (
                        earning_id, earning_type, program_handle,
                        report_id, amount, currency,
                        payment_method, payment_status,
                        earned_at, paid_at, description, raw_data
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (earning_id) DO UPDATE SET
                        payment_status = EXCLUDED.payment_status,
                        paid_at = EXCLUDED.paid_at,
                        raw_data = EXCLUDED.raw_data,
                        fetched_at = CURRENT_TIMESTAMP
                """, (
                    earning.get('id'),
                    attrs.get('type', 'bounty'),
                    attrs.get('program_handle'),
                    attrs.get('report_id'),
                    attrs.get('amount'),
                    attrs.get('currency', 'USD'),
                    attrs.get('payment_method'),
                    attrs.get('payment_status'),
                    attrs.get('earned_at'),
                    attrs.get('paid_at'),
                    attrs.get('description'),
                    Json(earning)
                ))
            
            self.db_conn.commit()
            logger.info(f"   ✅ Stored {len(earnings)} earnings records")
            
        except Exception as e:
            logger.error(f"   ❌ Error storing earnings: {e}")
            self.db_conn.rollback()
    
    def print_statistics(self):
        """Print fetch statistics"""
        logger.info("\n" + "="*60)
        logger.info("📊 FETCH STATISTICS")
        logger.info("="*60)
        for key, value in self.stats.items():
            logger.info(f"   {key}: {value}")
        
        # Query database for summary
        try:
            cursor = self.db_conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("SELECT * FROM hacker_statistics")
            stats = cursor.fetchone()
            
            if stats:
                logger.info("\n📈 DATABASE SUMMARY")
                logger.info("="*60)
                logger.info(f"   Total Reports: {stats.get('total_reports', 0)}")
                logger.info(f"   Resolved Reports: {stats.get('resolved_reports', 0)}")
                logger.info(f"   Reports with Bounties: {stats.get('bounty_reports', 0)}")
                logger.info(f"   Total Bounties Earned: ${stats.get('total_bounties_earned', 0):.2f}")
                logger.info(f"   Average Bounty: ${stats.get('average_bounty', 0):.2f}")
                logger.info(f"   Highest Bounty: ${stats.get('highest_bounty', 0):.2f}")
                logger.info(f"   Programs Reported To: {stats.get('programs_reported_to', 0)}")
                
        except Exception as e:
            logger.error(f"Could not fetch statistics: {e}")
    
    def run(self):
        """Main execution function"""
        logger.info("🚀 Starting Comprehensive HackerOne Data Fetch")
        logger.info("="*60)
        
        if not self.connect_db():
            logger.error("Failed to connect to database. Exiting.")
            return
        
        try:
            # 1. Fetch Programs (existing functionality)
            programs = self.fetch_all_programs()
            
            # 2. Fetch My Reports
            reports = self.fetch_my_reports()
            if reports:
                self.store_reports(reports)
            
            # 3. Fetch Earnings
            earnings = self.fetch_earnings()
            if earnings:
                self.store_earnings(earnings)
            
            # 4. Fetch Balance
            balance = self.fetch_balance()
            if balance:
                self.store_balance(balance)
            
            # 5. Fetch Hacktivity
            hacktivity = self.fetch_hacktivity(days_back=90)
            if hacktivity:
                self.store_hacktivity(hacktivity)
            
            # 6. Attempt to fetch invitations
            invitations = self.fetch_invitations()
            # Note: Store invitations if endpoint becomes available
            
            # Print statistics
            self.print_statistics()
            
            logger.info("\n✅ Data fetch completed successfully!")
            
        except Exception as e:
            logger.error(f"❌ Fatal error during fetch: {e}")
            
        finally:
            if self.db_conn:
                self.db_conn.close()
                logger.info("Database connection closed")

if __name__ == "__main__":
    fetcher = ComprehensiveHackerOneFetcher()
    fetcher.run()