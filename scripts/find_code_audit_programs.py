#!/usr/bin/env python3
"""
Find HackerOne Programs with Code Audit Scope
Similar to Fireblocks MPC - GitHub repos with bounties
"""

import os
import requests
import json
from typing import Dict, List, Tuple
import time

# API Credentials
API_USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"

class CodeAuditProgramFinder:
    def __init__(self):
        self.auth = (API_USERNAME, API_TOKEN)
        self.headers = {'Accept': 'application/json'}
        self.code_audit_programs = []
        
    def get_all_programs(self, limit=100):
        """Get programs with structured scopes"""
        print("🔍 Fetching HackerOne programs...")
        
        try:
            # Get programs with pagination
            page = 1
            all_programs = []
            
            while len(all_programs) < limit:
                response = requests.get(
                    f"{BASE_URL}/programs",
                    auth=self.auth,
                    headers=self.headers,
                    params={
                        'page[size]': 25,
                        'page[number]': page
                    }
                )
                
                if response.status_code != 200:
                    print(f"Error: {response.status_code}")
                    break
                    
                data = response.json()
                programs = data.get('data', [])
                
                if not programs:
                    break
                    
                all_programs.extend(programs)
                page += 1
                time.sleep(0.5)  # Rate limiting
                
            return all_programs[:limit]
            
        except Exception as e:
            print(f"Error fetching programs: {e}")
            return []
    
    def check_code_scope(self, program_handle: str) -> Tuple[bool, Dict]:
        """Check if program has GitHub/code in scope"""
        try:
            response = requests.get(
                f"{BASE_URL}/programs/{program_handle}/structured_scopes",
                auth=self.auth,
                headers=self.headers
            )
            
            if response.status_code != 200:
                return False, {}
            
            data = response.json()
            scopes = data.get('data', [])
            
            code_scopes = []
            for scope in scopes:
                attrs = scope.get('attributes', {})
                asset = attrs.get('asset_identifier', '').lower()
                asset_type = attrs.get('asset_type', '').lower()
                
                # Look for GitHub repos or source code
                if any(keyword in asset for keyword in ['github.com', 'gitlab.com', 'bitbucket']):
                    code_scopes.append({
                        'asset': attrs.get('asset_identifier'),
                        'max_severity': attrs.get('max_severity'),
                        'eligible_for_bounty': attrs.get('eligible_for_bounty', False)
                    })
                elif asset_type in ['source_code', 'smart_contract', 'blockchain']:
                    code_scopes.append({
                        'asset': attrs.get('asset_identifier'),
                        'max_severity': attrs.get('max_severity'),
                        'eligible_for_bounty': attrs.get('eligible_for_bounty', False)
                    })
            
            return len(code_scopes) > 0, code_scopes
            
        except Exception as e:
            print(f"Error checking scope for {program_handle}: {e}")
            return False, {}
    
    def analyze_program(self, program_data: Dict) -> Dict:
        """Analyze program for code audit potential"""
        attrs = program_data.get('attributes', {})
        handle = attrs.get('handle')
        
        # Check for code scope
        has_code, code_scopes = self.check_code_scope(handle)
        
        if not has_code:
            return None
            
        # Get bounty information
        bounty_table = attrs.get('bounty_table', {})
        
        # Calculate max bounty
        max_bounty = 0
        critical_bounty = 0
        high_bounty = 0
        
        for severity, ranges in bounty_table.items():
            if severity == 'critical' and ranges:
                critical_bounty = ranges.get('high', 0)
                max_bounty = max(max_bounty, critical_bounty)
            elif severity == 'high' and ranges:
                high_bounty = ranges.get('high', 0)
                max_bounty = max(max_bounty, high_bounty) if critical_bounty == 0 else max_bounty
        
        # Only include programs with bounties
        if max_bounty == 0:
            return None
            
        return {
            'handle': handle,
            'name': attrs.get('name'),
            'offers_bounties': attrs.get('offers_bounties', False),
            'max_bounty': max_bounty,
            'critical_bounty': critical_bounty,
            'high_bounty': high_bounty,
            'code_scopes': code_scopes,
            'submission_state': attrs.get('submission_state'),
            'average_time_to_bounty': attrs.get('average_time_to_bounty_awarded'),
            'average_time_to_triage': attrs.get('average_time_to_first_program_response'),
            'total_bounties_paid': attrs.get('total_bounties_paid_prefix', 0)
        }
    
    def calculate_roi(self, program: Dict) -> float:
        """Calculate ROI score for program"""
        score = 0
        
        # Bounty amount (weight: 40%)
        if program['max_bounty'] > 100000:
            score += 40
        elif program['max_bounty'] > 50000:
            score += 30
        elif program['max_bounty'] > 20000:
            score += 20
        elif program['max_bounty'] > 10000:
            score += 10
        else:
            score += 5
            
        # Code repository focus (weight: 30%)
        for scope in program['code_scopes']:
            if 'github.com' in scope['asset']:
                score += 10  # GitHub repos are easiest to analyze
            if scope['max_severity'] == 'critical':
                score += 10
            if scope['eligible_for_bounty']:
                score += 10
                
        # Response time (weight: 20%)
        avg_triage = program.get('average_time_to_triage', 999)
        if avg_triage and avg_triage < 24:  # Less than 1 day
            score += 20
        elif avg_triage and avg_triage < 72:  # Less than 3 days
            score += 10
        else:
            score += 5
            
        # Track record (weight: 10%)
        total_paid = program.get('total_bounties_paid', 0)
        if isinstance(total_paid, str):
            total_paid = total_paid.replace('$', '').replace(',', '').replace('k', '000').replace('M', '000000')
            try:
                total_paid = float(total_paid)
            except:
                total_paid = 0
                
        if total_paid > 1000000:
            score += 10
        elif total_paid > 100000:
            score += 5
            
        return score
    
    def find_top_programs(self):
        """Find top code audit programs"""
        programs = self.get_all_programs(limit=100)
        print(f"✅ Found {len(programs)} programs")
        
        print("🔍 Analyzing code audit scope...")
        for program in programs:
            analyzed = self.analyze_program(program)
            if analyzed:
                analyzed['roi_score'] = self.calculate_roi(analyzed)
                self.code_audit_programs.append(analyzed)
                print(f"  ✅ {analyzed['name']}: ${analyzed['max_bounty']:,} max bounty")
        
        # Sort by ROI score and bounty amount
        self.code_audit_programs.sort(
            key=lambda x: (x['roi_score'], x['max_bounty']), 
            reverse=True
        )
        
        return self.code_audit_programs[:10]  # Top 10

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║     Code Audit Program Finder - HackerOne API               ║
║     Finding programs similar to Fireblocks MPC              ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    finder = CodeAuditProgramFinder()
    top_programs = finder.find_top_programs()
    
    print("\n" + "="*80)
    print("🏆 TOP 5 CODE AUDIT PROGRAMS (Ordered by ROI & Rewards)")
    print("="*80)
    
    for i, program in enumerate(top_programs[:5], 1):
        print(f"\n{i}. {program['name']} (@{program['handle']})")
        print(f"   💰 Max Bounty: ${program['max_bounty']:,}")
        print(f"   🎯 Critical: ${program['critical_bounty']:,} | High: ${program['high_bounty']:,}")
        print(f"   📊 ROI Score: {program['roi_score']}/100")
        print(f"   ⏱️ Avg Triage: {program.get('average_time_to_triage', 'N/A')} hours")
        print(f"   💵 Total Paid: {program.get('total_bounties_paid', 'N/A')}")
        print(f"   🔍 Code Assets:")
        for scope in program['code_scopes'][:3]:  # Show first 3
            print(f"      - {scope['asset']}")
            print(f"        Severity: {scope['max_severity']} | Bounty: {scope['eligible_for_bounty']}")
    
    # Save results
    with open('code_audit_programs.json', 'w') as f:
        json.dump(top_programs, f, indent=2)
    print(f"\n✅ Full results saved to code_audit_programs.json")
    
    print("\n" + "="*80)
    print("💡 VULNERABILITY RESEARCH TIPS")
    print("="*80)
    print("""
Focus Areas for Code Audits:
1. 🔐 Cryptographic implementations (reduced parameters)
2. 🔑 Key management and generation
3. 🎲 Random number generation
4. 📝 Smart contract logic (if applicable)
5. 🔒 Authentication and authorization
6. 💾 Memory safety (for C/C++ code)

Apply Fireblocks methodology:
- Search for reduced security parameters
- Check for deviations from standards
- Look for performance vs security trade-offs
- Verify cryptographic validations
    """)

if __name__ == "__main__":
    main()