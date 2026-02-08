#!/usr/bin/env python3
"""
Bug Bounty Program Deep Scanner
Gathers comprehensive intelligence on programs for ROI analysis
Date: August 20, 2025
"""

import json
import yaml
import requests
from datetime import datetime
import os
import time

import os

# API Credentials for HackerOne
API_USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"

class ProgramScanner:
    def __init__(self):
        self.auth = (API_USERNAME, API_TOKEN)
        self.headers = {'Accept': 'application/json'}
        self.programs_data = []
        
        # Priority target categories based on our proven attacks
        self.priority_categories = {
            'crm': {'weight': 10, 'reason': 'IDOR pattern proven on HubSpot'},
            'saas': {'weight': 8, 'reason': 'Often have search APIs vulnerable to IDOR'},
            'api': {'weight': 9, 'reason': 'Direct API access = more attack surface'},
            'platform': {'weight': 7, 'reason': 'Complex systems with auth issues'},
            'cloud': {'weight': 6, 'reason': 'Often misconfigured'},
            'business': {'weight': 5, 'reason': 'B2B often less secure'},
            'marketplace': {'weight': 6, 'reason': 'Multi-tenant = IDOR opportunities'},
            'collaboration': {'weight': 7, 'reason': 'Access control issues common'},
            'automation': {'weight': 8, 'reason': 'Workflow systems like HubSpot'},
            'ecommerce': {'weight': 7, 'reason': 'Payment and PII data'}
        }
        
        # Known vulnerable patterns
        self.attack_patterns = {
            'idor': {
                'endpoints': ['/search', '/api/v*/search', '/query', '/filter', '/export'],
                'severity': 'medium',
                'bounty_range': '$1000-$2000',
                'success_rate': 0.4
            },
            'user_enum': {
                'endpoints': ['/users', '/api/users', '/settings/users', '/members'],
                'severity': 'low-medium',
                'bounty_range': '$500-$1000',
                'success_rate': 0.6
            },
            'ssrf': {
                'endpoints': ['/webhook', '/callback', '/integration', '/proxy'],
                'severity': 'high',
                'bounty_range': '$2000-$5000',
                'success_rate': 0.2
            },
            'info_disclosure': {
                'endpoints': ['/api', '/graphql', '/.git', '/config'],
                'severity': 'low',
                'bounty_range': '$200-$500',
                'success_rate': 0.7
            }
        }
    
    def get_all_programs(self, max_programs=200):
        """Fetch available programs from HackerOne with limit"""
        print(f"\n🔍 Fetching HackerOne programs (max: {max_programs})...")
        
        programs = []
        page = 1
        max_pages = (max_programs // 100) + 1
        
        while page <= max_pages:
            try:
                response = requests.get(
                    f"{BASE_URL}/programs",
                    auth=self.auth,
                    headers=self.headers,
                    params={'page[number]': page, 'page[size]': 100},
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    page_programs = data.get('data', [])
                    
                    if not page_programs:
                        break
                    
                    programs.extend(page_programs)
                    print(f"   Fetched page {page}: {len(page_programs)} programs (Total: {len(programs)})")
                    
                    if len(programs) >= max_programs:
                        programs = programs[:max_programs]
                        print(f"   Reached max limit of {max_programs} programs")
                        break
                    
                    page += 1
                    time.sleep(0.5)  # Rate limiting
                    
                    # Check if there's a next page
                    if not data.get('links', {}).get('next'):
                        break
                else:
                    print(f"   Error fetching programs: {response.status_code}")
                    break
                    
            except requests.exceptions.Timeout:
                print(f"   Timeout on page {page}, continuing with {len(programs)} programs")
                break
            except Exception as e:
                print(f"   Error: {e}")
                break
        
        print(f"✅ Total programs fetched: {len(programs)}")
        return programs
    
    def analyze_program(self, program):
        """Deep analysis of a single program"""
        attrs = program.get('attributes', {})
        handle = attrs.get('handle', '')
        name = attrs.get('name', '')
        
        # Calculate priority score
        score = 0
        matched_categories = []
        name_lower = name.lower()
        
        for category, info in self.priority_categories.items():
            if category in name_lower or category in handle.lower():
                score += info['weight']
                matched_categories.append(category)
        
        # Check for API scopes
        has_api = False
        api_targets = []
        
        # Get structured scopes if available
        try:
            scopes_response = requests.get(
                f"{BASE_URL}/programs/{handle}/structured_scopes",
                auth=self.auth,
                headers=self.headers,
                timeout=10
            )
            
            if scopes_response.status_code == 200:
                scopes_data = scopes_response.json()
                scopes = scopes_data.get('data', [])
                
                for scope in scopes:
                    scope_attrs = scope.get('attributes', {})
                    asset = scope_attrs.get('asset_identifier', '')
                    asset_type = scope_attrs.get('asset_type', '')
                    
                    if 'api' in asset.lower() or asset_type == 'URL':
                        has_api = True
                        api_targets.append({
                            'asset': asset,
                            'type': asset_type,
                            'severity': scope_attrs.get('max_severity', 'unknown')
                        })
                        score += 5
                        
        except:
            pass
        
        # Extract bounty information
        offers_bounties = attrs.get('offers_bounties', False)
        bounty_ranges = attrs.get('bounty_table', {})
        
        # Estimate potential value based on our attack patterns
        potential_value = 0
        applicable_attacks = []
        
        if has_api:
            for pattern_name, pattern_info in self.attack_patterns.items():
                if pattern_name == 'idor' and ('crm' in matched_categories or 'saas' in matched_categories):
                    applicable_attacks.append(pattern_name)
                    # Parse bounty range
                    min_bounty = int(pattern_info['bounty_range'].split('-')[0].replace('$', '').replace(',', ''))
                    max_bounty = int(pattern_info['bounty_range'].split('-')[1].replace('$', '').replace(',', ''))
                    expected = (min_bounty + max_bounty) / 2 * pattern_info['success_rate']
                    potential_value += expected
        
        return {
            'handle': handle,
            'name': name,
            'url': f"https://hackerone.com/{handle}",
            'offers_bounties': offers_bounties,
            'state': attrs.get('state', 'unknown'),
            'submission_state': attrs.get('submission_state', 'unknown'),
            'priority_score': score,
            'matched_categories': matched_categories,
            'has_api': has_api,
            'api_targets': api_targets,
            'applicable_attacks': applicable_attacks,
            'estimated_value': potential_value,
            'reports_resolved': attrs.get('number_of_reports_for_user', 0),
            'bounty_ranges': bounty_ranges,
            'response_efficiency': attrs.get('response_efficiency_percentage', 0),
            'analysis_date': datetime.now().isoformat()
        }
    
    def filter_high_value_programs(self, programs):
        """Filter and rank programs by ROI potential"""
        analyzed = []
        
        for program in programs:
            analysis = self.analyze_program(program)
            
            # Only include programs that are open and offer bounties
            # States can be: public_mode, invite_only, etc.
            if (analysis['submission_state'] == 'open' and
                analysis['offers_bounties'] and
                analysis['state'] in ['public_mode', 'open']):
                analyzed.append(analysis)
        
        # Sort by priority score and estimated value
        analyzed.sort(key=lambda x: (x['priority_score'], x['estimated_value']), reverse=True)
        
        return analyzed
    
    def generate_reports(self, programs):
        """Generate detailed reports for Grok4 analysis"""
        
        # Top programs report
        top_20 = programs[:20]
        
        report = {
            'scan_date': datetime.now().isoformat(),
            'total_programs_scanned': len(programs),
            'programs_with_bounties': len([p for p in programs if p['offers_bounties']]),
            'programs_with_api': len([p for p in programs if p['has_api']]),
            'top_roi_programs': top_20,
            'attack_patterns': self.attack_patterns,
            'methodology': {
                'idor_success_rate': '40% on CRM/SaaS',
                'proven_on': 'HubSpot ($1700-$3500 expected)',
                'time_investment': '5-10 hours per program',
                'tools': ['Search API testing', 'Authorization bypass', 'User enumeration']
            }
        }
        
        # Save main report in JSON
        with open('program_intelligence_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save main report in YAML (more readable)
        with open('program_intelligence_report.yaml', 'w') as f:
            yaml.dump(report, f, default_flow_style=False, sort_keys=False)
        
        # Generate simplified YAML for top programs
        self.generate_yaml_report(top_20)
        
        # Generate markdown report for easy reading
        self.generate_markdown_report(top_20)
        
        # Generate Grok4 analysis request
        self.generate_grok4_request(top_20)
        
        return report
    
    def generate_yaml_report(self, programs):
        """Generate simplified YAML report for easy parsing"""
        
        yaml_data = {
            'metadata': {
                'generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_programs': len(programs),
                'methodology': 'IDOR-focused with proven HubSpot pattern'
            },
            'top_targets': []
        }
        
        for prog in programs[:20]:
            target = {
                'name': prog['name'],
                'handle': prog['handle'],
                'priority_score': prog['priority_score'],
                'estimated_value': f"${prog['estimated_value']:.0f}",
                'has_api': prog['has_api'],
                'categories': prog['matched_categories'],
                'api_endpoints': []
            }
            
            # Add top 3 API targets
            for api in prog['api_targets'][:3]:
                target['api_endpoints'].append({
                    'url': api['asset'],
                    'severity': api['severity']
                })
            
            yaml_data['top_targets'].append(target)
        
        with open('TOP_PROGRAMS.yaml', 'w') as f:
            yaml.dump(yaml_data, f, default_flow_style=False, sort_keys=False)
    
    def generate_markdown_report(self, programs):
        """Generate human-readable markdown report"""
        
        md_content = f"""# 🎯 Bug Bounty Program Intelligence Report

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Programs Analyzed**: {len(programs)}

---

## 🏆 Top 20 High-ROI Programs

"""
        
        for i, prog in enumerate(programs[:20], 1):
            md_content += f"""
### {i}. {prog['name']}

- **Handle**: {prog['handle']}
- **URL**: {prog['url']}
- **Priority Score**: {prog['priority_score']}
- **Has API**: {'✅' if prog['has_api'] else '❌'}
- **Estimated Value**: ${prog['estimated_value']:.0f}
- **Categories**: {', '.join(prog['matched_categories'])}
- **Applicable Attacks**: {', '.join(prog['applicable_attacks'])}
- **Response Rate**: {prog['response_efficiency']}%

**API Targets**:
"""
            for target in prog['api_targets'][:3]:
                md_content += f"- {target['asset']} ({target['severity']})\n"
            
            md_content += "\n---\n"
        
        with open('TOP_PROGRAMS_ANALYSIS.md', 'w') as f:
            f.write(md_content)
    
    def generate_grok4_request(self, programs):
        """Generate analysis request for Grok4"""
        
        grok_request = f"""# 📊 GROK4 ROI ANALYSIS REQUEST

## Context
We've successfully earned $1,700-$3,500 from HubSpot using IDOR attack pattern on their Search API.
Time invested: 40 hours (but now we have reusable methodology).

## Proven Attack Patterns
1. **IDOR in Search APIs** - 40% success rate on CRM/SaaS
2. **User Enumeration** - 60% success rate
3. **Input Validation Bypass** - 70% success rate but low value

## Top 20 Programs for Analysis

"""
        
        for i, prog in enumerate(programs[:20], 1):
            grok_request += f"""
### {i}. {prog['name']}
- Priority Score: {prog['priority_score']}
- Has API: {prog['has_api']}
- Estimated Value: ${prog['estimated_value']:.0f}
- Categories: {prog['matched_categories']}
"""
            if prog['api_targets']:
                grok_request += f"- API Example: {prog['api_targets'][0]['asset']}\n"
        
        grok_request += """

## Questions for Grok4

1. **Which 5 programs should we target FIRST for maximum ROI?**
2. **What's the optimal time allocation per program?**
3. **Should we focus on depth (one program thoroughly) or breadth (quick IDOR tests on many)?**
4. **Are there any programs where our IDOR pattern is GUARANTEED to work?**
5. **What's the expected monthly income if we dedicate 40 hours/week?**

## Our Constraints
- 40 hours/week available
- Proven IDOR methodology ready
- Need quick wins to build reputation
- Prefer programs with <7 day response time

Please provide brutal, honest assessment focused on MONEY and TIME EFFICIENCY.
"""
        
        with open('GROK4_ANALYSIS_REQUEST.md', 'w') as f:
            f.write(grok_request)
    
    def run(self):
        """Main execution"""
        print("""
╔══════════════════════════════════════════════════════════════╗
║            Bug Bounty Program Intelligence Scanner           ║
║                 Preparing Data for Grok4 Analysis           ║
╚══════════════════════════════════════════════════════════════╝
        """)
        
        # Get all programs
        programs = self.get_all_programs()
        
        if not programs:
            print("❌ No programs fetched. Check API credentials.")
            return
        
        # Analyze and filter
        print("\n📊 Analyzing programs for ROI potential...")
        high_value = self.filter_high_value_programs(programs)
        
        print(f"✅ Found {len(high_value)} programs with bounties")
        
        # Generate reports
        print("\n📝 Generating intelligence reports...")
        report = self.generate_reports(high_value)
        
        print("\n✅ Reports generated:")
        print("   - program_intelligence_report.json")
        print("   - program_intelligence_report.yaml")
        print("   - TOP_PROGRAMS.yaml")
        print("   - TOP_PROGRAMS_ANALYSIS.md")
        print("   - GROK4_ANALYSIS_REQUEST.md")
        
        print(f"\n💰 Top 5 programs by priority:")
        for i, prog in enumerate(high_value[:5], 1):
            print(f"   {i}. {prog['name']} (Score: {prog['priority_score']})")
        
        print("\n🎯 Next step: Share GROK4_ANALYSIS_REQUEST.md with Grok4 for ROI analysis")


if __name__ == "__main__":
    scanner = ProgramScanner()
    scanner.run()