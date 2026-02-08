#!/usr/bin/env python3
"""
Find HackerOne Programs with Code Audit Scope using PostgreSQL
Query real data from our PostgreSQL database
"""

import os
import psycopg2
import json
from typing import Dict, List, Tuple
import requests

# PostgreSQL connection
DB_CONFIG = {
    'host': 'localhost',
    'database': 'bbhk_db', 
    'user': 'bbhk_user',
    'password': os.getenv('POSTGRES_PASSWORD', ''),
    'port': 5432
}

# HackerOne API (for additional details)
API_USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"

class PostgreSQLCodeAuditFinder:
    def __init__(self):
        self.conn = None
        self.auth = (API_USERNAME, API_TOKEN)
        self.headers = {'Accept': 'application/json'}
        
    def connect_db(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(**DB_CONFIG)
            print("✅ Connected to PostgreSQL database")
            return True
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return False
    
    def find_programs_with_code(self):
        """Query PostgreSQL for programs with GitHub/source code in scope"""
        if not self.conn:
            if not self.connect_db():
                return []
        
        try:
            cursor = self.conn.cursor()
            
            # Query for programs with code repositories in scope
            query = """
            SELECT DISTINCT
                p.handle,
                p.name,
                p.offers_bounties,
                COALESCE(pb.maximum_bounty, 0) as max_bounty,
                COALESCE(pb.minimum_bounty, 0) as min_bounty,
                s.asset_identifier,
                s.asset_type,
                s.max_severity,
                s.eligible_for_bounty
            FROM bbhk.programs p
            LEFT JOIN bbhk.program_bounties pb ON p.id = pb.program_id
            JOIN bbhk.structured_scopes s ON p.program_id = s.program_id
            WHERE p.offers_bounties = true
                AND s.eligible_for_bounty = true
                AND (
                    s.asset_identifier ILIKE '%github.com%'
                    OR s.asset_identifier ILIKE '%gitlab.com%'
                    OR s.asset_identifier ILIKE '%bitbucket%'
                    OR s.asset_type ILIKE '%source%'
                    OR s.asset_type ILIKE '%smart_contract%'
                    OR s.asset_type = 'SOURCE_CODE'
                    OR s.asset_type = 'SMART_CONTRACT'
                )
                AND p.state = 'public_mode'
            ORDER BY COALESCE(pb.maximum_bounty, 0) DESC
            LIMIT 100;
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            
            print(f"✅ Found {len(results)} programs with code audit scope")
            
            # Group by program
            programs = {}
            for row in results:
                handle = row[0]
                if handle not in programs:
                    programs[handle] = {
                        'handle': handle,
                        'name': row[1],
                        'offers_bounties': row[2],
                        'max_bounty': float(row[3] or 0),
                        'min_bounty': float(row[4] or 0),
                        'code_scopes': []
                    }
                
                programs[handle]['code_scopes'].append({
                    'asset': row[5],
                    'type': row[6],
                    'max_severity': row[7],
                    'eligible_for_bounty': row[8]
                })
            
            cursor.close()
            return list(programs.values())
            
        except Exception as e:
            print(f"❌ Query error: {e}")
            return []
    
    def get_bounty_details(self, handle: str) -> Dict:
        """Get detailed bounty information from API"""
        try:
            response = requests.get(
                f"{BASE_URL}/programs/{handle}",
                auth=self.auth,
                headers=self.headers
            )
            
            if response.status_code == 200:
                data = response.json()
                attrs = data.get('attributes', {})
                bounty_table = attrs.get('bounty_table', {})
                
                critical = bounty_table.get('critical', {})
                high = bounty_table.get('high', {})
                medium = bounty_table.get('medium', {})
                
                return {
                    'critical_max': critical.get('high', 0) if critical else 0,
                    'high_max': high.get('high', 0) if high else 0,
                    'medium_max': medium.get('high', 0) if medium else 0,
                    'response_time': attrs.get('average_time_to_first_program_response'),
                    'bounty_time': attrs.get('average_time_to_bounty_awarded')
                }
        except:
            return {}
    
    def calculate_roi_score(self, program: Dict) -> float:
        """Calculate ROI score for vulnerability research"""
        score = 0
        
        # Max bounty (40 points)
        max_bounty = program.get('max_bounty', 0)
        if max_bounty >= 100000:
            score += 40
        elif max_bounty >= 50000:
            score += 30
        elif max_bounty >= 20000:
            score += 20
        elif max_bounty >= 10000:
            score += 10
        else:
            score += 5
        
        # GitHub repositories (30 points)
        github_count = sum(1 for s in program['code_scopes'] if 'github.com' in s['asset'])
        if github_count > 0:
            score += min(30, github_count * 10)
        
        # Critical severity accepted (20 points)
        has_critical = any(s['max_severity'] == 'critical' for s in program['code_scopes'])
        if has_critical:
            score += 20
        
        # Crypto/blockchain focus (10 points)
        crypto_keywords = ['crypto', 'blockchain', 'defi', 'smart', 'contract', 'chain', 'token']
        if any(kw in program['name'].lower() or kw in program['handle'].lower() for kw in crypto_keywords):
            score += 10
        
        return score
    
    def get_top_programs(self):
        """Get top programs for code audit"""
        programs = self.find_programs_with_code()
        
        if not programs:
            print("⚠️ No programs found with code scope")
            return []
        
        # Calculate ROI scores
        for program in programs:
            program['roi_score'] = self.calculate_roi_score(program)
            
            # Get additional details from API for top programs
            if program['roi_score'] > 50:
                details = self.get_bounty_details(program['handle'])
                program.update(details)
        
        # Sort by ROI score and max bounty
        programs.sort(key=lambda x: (x['roi_score'], x.get('max_bounty', 0)), reverse=True)
        
        return programs[:10]

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║   PostgreSQL Code Audit Program Finder                      ║
║   Finding programs with GitHub/source code in scope         ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    finder = PostgreSQLCodeAuditFinder()
    top_programs = finder.get_top_programs()
    
    if not top_programs:
        print("\n❌ No programs found. Checking database connection...")
        return
    
    print("\n" + "="*80)
    print("🏆 TOP 5 CODE AUDIT PROGRAMS FROM POSTGRESQL (Ordered by ROI)")
    print("="*80)
    
    for i, prog in enumerate(top_programs[:5], 1):
        max_bounty = prog.get('max_bounty', 0)
        
        print(f"\n{i}. {prog['name']} (@{prog['handle']})")
        print(f"   💰 Max Bounty: ${max_bounty:,.0f}")
        if 'critical_max' in prog:
            print(f"   🎯 Critical: ${prog.get('critical_max', 0):,} | High: ${prog.get('high_max', 0):,}")
        print(f"   📊 ROI Score: {prog['roi_score']}/100")
        print(f"   🔍 Code Assets ({len(prog['code_scopes'])} repositories):")
        
        # Show GitHub repos
        github_repos = [s for s in prog['code_scopes'] if 'github.com' in s['asset']]
        for scope in github_repos[:3]:
            asset = scope['asset']
            if len(asset) > 60:
                asset = asset[:57] + "..."
            print(f"      - {asset}")
            print(f"        Max: {scope['max_severity']} | Eligible: ✅")
    
    # Vulnerability research strategy
    print("\n" + "="*80)
    print("🔬 VULNERABILITY RESEARCH STRATEGY")
    print("="*80)
    print("""
Based on Fireblocks success (Report #3303358):

1. Clone GitHub repositories from the list above
2. Search for crypto vulnerabilities:
   rg -i "rounds|iterations|security.*=.*[0-9]" --type c --type cpp --type go --type rust
   
3. Focus on:
   - Reduced security parameters (64 vs 80 rounds)
   - Weak random number generation
   - Integer overflows in crypto
   - Missing input validation
   - Timing attacks
   
4. Use AI analysis with proven prompts
5. Develop PoC demonstrating impact
6. Submit via HackerOne API

Expected bounties: $10k-$100k+ per critical vulnerability
    """)
    
    # Save results
    with open('postgres_code_audit_programs.json', 'w') as f:
        json.dump(top_programs, f, indent=2, default=str)
    print("\n✅ Results saved to postgres_code_audit_programs.json")
    
    if finder.conn:
        finder.conn.close()

if __name__ == "__main__":
    main()