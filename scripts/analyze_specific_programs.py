#!/usr/bin/env python3
"""
Analyze specific HackerOne programs known to have source code in scope
"""

import os
import requests
import json
from typing import Dict, List
import time

# API Credentials
API_USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"

class SpecificProgramAnalyzer:
    def __init__(self):
        self.auth = (API_USERNAME, API_TOKEN)
        self.headers = {'Accept': 'application/json'}
        
        # Known programs with source code/GitHub in scope
        self.target_programs = [
            'github',
            'blockchain',
            'crypto',
            'chainlink',
            'ethereum',
            'solana',
            'polygon',
            'metamask',
            'opensea',
            'compound',
            'aave',
            'uniswap',
            'synthetix',
            'yearn',
            'makerdao',
            'brave',
            'nodejs',
            'ruby',
            'rails',
            'kubernetes',
            'docker',
            'elastic',
            'grafana',
            'gitlab',
            'nextcloud',
            'owncloud',
            'matrix',
            'signal',
            'bitwarden',
            'protonmail',
            'tor'
        ]
        
    def analyze_program(self, handle: str) -> Dict:
        """Analyze a specific program"""
        try:
            # Get program details
            response = requests.get(
                f"{BASE_URL}/programs/{handle}",
                auth=self.auth,
                headers=self.headers
            )
            
            if response.status_code != 200:
                return None
                
            program_data = response.json()
            attrs = program_data.get('attributes', {})
            
            # Get structured scopes
            scope_response = requests.get(
                f"{BASE_URL}/programs/{handle}/structured_scopes",
                auth=self.auth,
                headers=self.headers
            )
            
            code_scopes = []
            if scope_response.status_code == 200:
                scope_data = scope_response.json()
                scopes = scope_data.get('data', [])
                
                for scope in scopes:
                    scope_attrs = scope.get('attributes', {})
                    asset = scope_attrs.get('asset_identifier', '').lower()
                    asset_type = scope_attrs.get('asset_type', '').lower()
                    
                    # Check for code repositories
                    if any(repo in asset for repo in ['github.com', 'gitlab.com', 'source', '.git']):
                        code_scopes.append({
                            'asset': scope_attrs.get('asset_identifier'),
                            'type': scope_attrs.get('asset_type'),
                            'max_severity': scope_attrs.get('max_severity'),
                            'eligible_for_bounty': scope_attrs.get('eligible_for_bounty', False)
                        })
                    elif asset_type in ['source_code', 'smart_contract', 'blockchain', 'desktop_application']:
                        code_scopes.append({
                            'asset': scope_attrs.get('asset_identifier'),
                            'type': scope_attrs.get('asset_type'),
                            'max_severity': scope_attrs.get('max_severity'),
                            'eligible_for_bounty': scope_attrs.get('eligible_for_bounty', False)
                        })
            
            # Get bounty information
            bounty_table = attrs.get('bounty_table', {})
            
            # Calculate bounties
            max_bounty = 0
            critical_bounty = 0
            high_bounty = 0
            medium_bounty = 0
            
            for severity, ranges in bounty_table.items():
                if ranges:
                    if severity == 'critical':
                        critical_bounty = ranges.get('high', 0)
                        max_bounty = max(max_bounty, critical_bounty)
                    elif severity == 'high':
                        high_bounty = ranges.get('high', 0)
                    elif severity == 'medium':
                        medium_bounty = ranges.get('high', 0)
            
            # Only include if has code scope and bounties
            if not code_scopes or max_bounty == 0:
                return None
                
            return {
                'handle': handle,
                'name': attrs.get('name'),
                'offers_bounties': attrs.get('offers_bounties', False),
                'max_bounty': max_bounty,
                'critical_bounty': critical_bounty,
                'high_bounty': high_bounty,
                'medium_bounty': medium_bounty,
                'code_scopes': code_scopes,
                'submission_state': attrs.get('submission_state'),
                'average_time_to_bounty': attrs.get('average_time_to_bounty_awarded'),
                'average_time_to_triage': attrs.get('average_time_to_first_program_response'),
                'total_bounties_paid': attrs.get('total_bounties_paid_prefix', 'N/A')
            }
            
        except Exception as e:
            print(f"  ⚠️ Error analyzing {handle}: {e}")
            return None
    
    def calculate_roi_score(self, program: Dict) -> float:
        """Calculate ROI score for vulnerability research"""
        score = 0
        
        # Bounty amount (40 points max)
        if program['critical_bounty'] >= 100000:
            score += 40
        elif program['critical_bounty'] >= 50000:
            score += 35
        elif program['critical_bounty'] >= 20000:
            score += 25
        elif program['high_bounty'] >= 10000:
            score += 15
        else:
            score += 5
        
        # Code repository quality (30 points max)
        for scope in program['code_scopes']:
            if 'github.com' in scope.get('asset', ''):
                score += 15  # GitHub is easiest to analyze
                break
                
        if any(s.get('max_severity') == 'critical' for s in program['code_scopes']):
            score += 15
            
        # Crypto/blockchain focus (20 points max)
        if any(keyword in program['handle'].lower() or keyword in program['name'].lower() 
               for keyword in ['crypto', 'blockchain', 'chain', 'defi', 'ethereum', 'solana']):
            score += 20
            
        # Response time (10 points max)
        avg_triage = program.get('average_time_to_triage', 999)
        if avg_triage and avg_triage < 24:
            score += 10
        elif avg_triage and avg_triage < 72:
            score += 5
            
        return score
    
    def find_programs(self):
        """Find and analyze target programs"""
        print("🔍 Analyzing specific programs with code audit scope...")
        
        results = []
        for handle in self.target_programs:
            print(f"  Checking @{handle}...", end='')
            program = self.analyze_program(handle)
            
            if program:
                program['roi_score'] = self.calculate_roi_score(program)
                results.append(program)
                print(f" ✅ ${program['max_bounty']:,} max")
            else:
                print(" ❌ No code scope or bounties")
                
            time.sleep(0.3)  # Rate limiting
        
        # Sort by ROI and bounty
        results.sort(key=lambda x: (x['roi_score'], x['max_bounty']), reverse=True)
        return results

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║   Top Code Audit Programs - Similar to Fireblocks MPC       ║
║   Focus: Source Code, Crypto, High Bounties                 ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    analyzer = SpecificProgramAnalyzer()
    programs = analyzer.find_programs()
    
    print("\n" + "="*80)
    print("🏆 TOP 5 CODE AUDIT PROGRAMS - ORDERED BY ROI & REWARDS")
    print("="*80)
    
    for i, prog in enumerate(programs[:5], 1):
        print(f"\n{i}. {prog['name']} (@{prog['handle']})")
        print(f"   💰 Max Bounty: ${prog['max_bounty']:,}")
        print(f"   🎯 Bounties: Critical ${prog['critical_bounty']:,} | High ${prog['high_bounty']:,}")
        print(f"   📊 ROI Score: {prog['roi_score']}/100")
        print(f"   ⏱️ Avg Triage: {prog.get('average_time_to_triage', 'N/A')} hours")
        print(f"   💵 Total Paid: {prog.get('total_bounties_paid', 'N/A')}")
        print(f"   🔍 Code Assets ({len(prog['code_scopes'])} total):")
        for scope in prog['code_scopes'][:2]:  # Show first 2
            print(f"      - {scope['asset'][:60]}...")
            print(f"        Max: {scope['max_severity']} | Bounty: {scope['eligible_for_bounty']}")
    
    # Vulnerability research tips
    print("\n" + "="*80)
    print("🎯 VULNERABILITY RESEARCH STRATEGY")
    print("="*80)
    print("""
Apply the Fireblocks methodology to these programs:

1. 🔍 Clone their GitHub repositories
2. 🔐 Search for cryptographic implementations:
   rg -i "rounds|iterations|security.*=.*[0-9]" --type c --type cpp --type go --type rust
   
3. 🎯 Focus areas:
   - Reduced security parameters (like 64 vs 80 rounds)
   - Weak RNG or predictable seeds
   - Missing input validation
   - Integer overflows in crypto operations
   - Timing attacks in constant-time code
   
4. 📝 Use AI analysis:
   - Feed suspicious code to Claude/GPT-5
   - Compare against academic papers
   - Check for CVE patterns
   
5. 💰 Expected returns:
   - Critical crypto bugs: $50k-$250k
   - High severity: $10k-$50k
   - Time investment: 8-40 hours per vulnerability
    """)
    
    # Save results
    with open('top_code_audit_programs.json', 'w') as f:
        json.dump(programs[:10], f, indent=2)
    print("\n✅ Results saved to top_code_audit_programs.json")

if __name__ == "__main__":
    main()