#!/usr/bin/env python3
"""
Bug Bounty Program Deep Scanner V2
Enhanced with Grok feedback: Real value calculations, better error handling
Date: August 20, 2025
"""

import json
import yaml
import requests
from datetime import datetime
import os
import time
import argparse
import sys
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# API Configuration from environment
API_USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"
MAX_PROGRAMS = int(os.getenv('MAX_PROGRAMS', 500))
RATE_LIMIT_DELAY = float(os.getenv('RATE_LIMIT_DELAY', 0.5))
REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', 30))

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
            'ecommerce': {'weight': 7, 'reason': 'Payment and PII data'},
            'travel': {'weight': 10, 'reason': 'Booking IDs perfect for IDOR'},
            'booking': {'weight': 10, 'reason': 'Reservation systems vulnerable'},
            'hotel': {'weight': 9, 'reason': 'Property management systems'},
            'financial': {'weight': 8, 'reason': 'High value targets'},
            'payment': {'weight': 8, 'reason': 'Financial data access'}
        }
        
        # Known vulnerable patterns with realistic bounty data
        self.attack_patterns = {
            'idor': {
                'endpoints': ['/search', '/api/v*/search', '/query', '/filter', '/export', '/booking', '/reservation'],
                'severity': 'medium',
                'bounty_range': '$1000-$3000',
                'avg_bounty': 2000,
                'success_rate': 0.4
            },
            'user_enum': {
                'endpoints': ['/users', '/api/users', '/settings/users', '/members'],
                'severity': 'low-medium',
                'bounty_range': '$500-$1500',
                'avg_bounty': 1000,
                'success_rate': 0.6
            },
            'ssrf': {
                'endpoints': ['/webhook', '/callback', '/integration', '/proxy'],
                'severity': 'high',
                'bounty_range': '$2000-$5000',
                'avg_bounty': 3500,
                'success_rate': 0.2
            },
            'info_disclosure': {
                'endpoints': ['/api', '/graphql', '/.git', '/config'],
                'severity': 'low',
                'bounty_range': '$200-$800',
                'avg_bounty': 500,
                'success_rate': 0.7
            },
            'auth_bypass': {
                'endpoints': ['/admin', '/portal', '/dashboard', '/settings'],
                'severity': 'critical',
                'bounty_range': '$3000-$10000',
                'avg_bounty': 6500,
                'success_rate': 0.15
            },
            'mass_assignment': {
                'endpoints': ['/create', '/update', '/object', '/api/v*/objects', '/users/create', '/profile/update'],
                'severity': 'high',
                'bounty_range': '$1500-$4000',
                'avg_bounty': 2500,
                'success_rate': 0.35
            },
            'bac': {  # Broken Access Control
                'endpoints': ['/profile', '/account', '/permissions', '/roles', '/user/*', '/org/*'],
                'severity': 'high',
                'bounty_range': '$2000-$5000',
                'avg_bounty': 4000,
                'success_rate': 0.25
            },
            'api_rate_limit': {
                'endpoints': ['/api/*', '/search', '/export', '/query'],
                'severity': 'medium',
                'bounty_range': '$800-$2000',
                'avg_bounty': 1500,
                'success_rate': 0.50
            },
            'jwt_misconfiguration': {
                'endpoints': ['/auth', '/login', '/refresh', '/token'],
                'severity': 'critical',
                'bounty_range': '$3000-$8000',
                'avg_bounty': 5500,
                'success_rate': 0.10
            }
        }
        
        # Validate API credentials on init
        if not self.validate_credentials():
            logger.error("Invalid API credentials. Please check your .env file")
            sys.exit(1)
    
    def validate_credentials(self):
        """Validate API credentials are working"""
        try:
            # Use programs endpoint to validate (Hacker API doesn't support /me)
            response = requests.get(
                f"{BASE_URL}/programs",
                auth=self.auth,
                headers=self.headers,
                params={'page[size]': 1},  # Just fetch 1 to validate
                timeout=10
            )
            if response.status_code == 200:
                logger.info("✅ API credentials validated successfully")
                return True
            else:
                logger.error(f"❌ API authentication failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"❌ Could not validate credentials: {e}")
            return False
    
    def get_all_programs(self, max_programs=None):
        """Fetch available programs from HackerOne with limit"""
        max_programs = max_programs or MAX_PROGRAMS
        logger.info(f"🔍 Fetching HackerOne programs (max: {max_programs})...")
        
        programs = []
        page = 1
        retry_count = 0
        max_retries = 3
        
        while len(programs) < max_programs:
            try:
                response = requests.get(
                    f"{BASE_URL}/programs",
                    auth=self.auth,
                    headers=self.headers,
                    params={'page[number]': page, 'page[size]': 100},
                    timeout=REQUEST_TIMEOUT
                )
                
                if response.status_code == 200:
                    data = response.json()
                    page_programs = data.get('data', [])
                    
                    if not page_programs:
                        break
                    
                    programs.extend(page_programs)
                    logger.info(f"   Fetched page {page}: {len(page_programs)} programs (Total: {len(programs)})")
                    
                    if len(programs) >= max_programs:
                        programs = programs[:max_programs]
                        logger.info(f"   Reached max limit of {max_programs} programs")
                        break
                    
                    page += 1
                    time.sleep(RATE_LIMIT_DELAY)
                    retry_count = 0  # Reset retry count on success
                    
                    # Check if there's a next page
                    if not data.get('links', {}).get('next'):
                        break
                        
                elif response.status_code == 429:  # Rate limited
                    retry_count += 1
                    if retry_count > max_retries:
                        logger.warning("Rate limit exceeded, continuing with collected programs")
                        break
                    wait_time = 2 ** retry_count  # Exponential backoff
                    logger.warning(f"Rate limited, waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                    
                else:
                    logger.error(f"   Error fetching programs: {response.status_code}")
                    break
                    
            except requests.exceptions.Timeout:
                logger.warning(f"   Timeout on page {page}, continuing with {len(programs)} programs")
                break
            except Exception as e:
                logger.error(f"   Error: {e}")
                break
        
        logger.info(f"✅ Total programs fetched: {len(programs)}")
        return programs
    
    def determine_applicable_attacks(self, program_data):
        """Determine which attacks are applicable based on program characteristics"""
        applicable = []
        
        # Check categories for pattern matches
        categories = program_data.get('matched_categories', [])
        api_targets = program_data.get('api_targets', [])
        
        # IDOR is applicable to travel, booking, CRM, SaaS
        if any(cat in categories for cat in ['travel', 'booking', 'crm', 'saas', 'hotel']) or \
           any('booking' in str(api.get('asset', '')).lower() for api in api_targets) or \
           any('reservation' in str(api.get('asset', '')).lower() for api in api_targets):
            applicable.append('idor')
        
        # User enum applicable to any platform with user accounts
        if program_data.get('has_api'):
            applicable.append('user_enum')
        
        # SSRF for webhook/integration endpoints
        if any('webhook' in str(api.get('asset', '')).lower() for api in api_targets) or \
           any('callback' in str(api.get('asset', '')).lower() for api in api_targets) or \
           any('integration' in str(api.get('asset', '')).lower() for api in api_targets):
            applicable.append('ssrf')
        
        # Info disclosure for any API
        if program_data.get('has_api'):
            applicable.append('info_disclosure')
        
        # Auth bypass for admin/dashboard endpoints
        if any('admin' in str(api.get('asset', '')).lower() for api in api_targets) or \
           any('dashboard' in str(api.get('asset', '')).lower() for api in api_targets):
            applicable.append('auth_bypass')
        
        # Mass assignment for create/update endpoints
        if any('create' in str(api.get('asset', '')).lower() for api in api_targets) or \
           any('update' in str(api.get('asset', '')).lower() for api in api_targets) or \
           any('object' in str(api.get('asset', '')).lower() for api in api_targets):
            applicable.append('mass_assignment')
        
        # Broken Access Control for profile/account endpoints
        if any('profile' in str(api.get('asset', '')).lower() for api in api_targets) or \
           any('account' in str(api.get('asset', '')).lower() for api in api_targets) or \
           any('user' in str(api.get('asset', '')).lower() for api in api_targets):
            applicable.append('bac')
        
        # API rate limit bypass for search/export endpoints
        if any('search' in str(api.get('asset', '')).lower() for api in api_targets) or \
           any('export' in str(api.get('asset', '')).lower() for api in api_targets) or \
           any('query' in str(api.get('asset', '')).lower() for api in api_targets):
            applicable.append('api_rate_limit')
        
        # JWT misconfiguration for auth endpoints
        if any('auth' in str(api.get('asset', '')).lower() for api in api_targets) or \
           any('login' in str(api.get('asset', '')).lower() for api in api_targets) or \
           any('token' in str(api.get('asset', '')).lower() for api in api_targets):
            applicable.append('jwt_misconfiguration')
        
        return applicable
    
    def calculate_estimated_value(self, applicable_attacks):
        """Calculate realistic estimated value based on applicable attacks"""
        total_value = 0
        
        for attack in applicable_attacks:
            if attack in self.attack_patterns:
                pattern = self.attack_patterns[attack]
                # Expected value = average bounty * success rate
                expected = pattern['avg_bounty'] * pattern['success_rate']
                total_value += expected
        
        return total_value
    
    def analyze_program(self, program):
        """Deep analysis of a single program"""
        attrs = program.get('attributes', {})
        handle = attrs.get('handle', '')
        name = attrs.get('name', '')
        
        # Calculate priority score
        score = 0
        matched_categories = []
        name_lower = name.lower()
        handle_lower = handle.lower()
        
        # Check name and handle against categories
        for category, info in self.priority_categories.items():
            if category in name_lower or category in handle_lower:
                score += info['weight']
                matched_categories.append(category)
        
        # Special boost for known high-value targets
        if 'booking' in name_lower:
            score += 25  # Major boost for booking platforms
            if 'booking' not in matched_categories:
                matched_categories.append('booking')
        if 'marriott' in name_lower or 'hyatt' in name_lower or 'hilton' in name_lower:
            score += 20
            if 'hotel' not in matched_categories:
                matched_categories.append('hotel')
        if 'goldman' in name_lower or 'jpmorgan' in name_lower or 'bank' in name_lower:
            score += 15
            if 'financial' not in matched_categories:
                matched_categories.append('financial')
        
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
                
                for scope in scopes[:30]:  # Limit to top 30
                    scope_attrs = scope.get('attributes', {})
                    asset = scope_attrs.get('asset_identifier', '')
                    asset_type = scope_attrs.get('asset_type', '')
                    severity = scope_attrs.get('max_severity', 'unknown')
                    
                    # Check for API indicators
                    if 'api' in asset.lower() or \
                       'json' in asset.lower() or \
                       'webhook' in asset.lower() or \
                       'graphql' in asset.lower() or \
                       asset_type == 'URL':
                        has_api = True
                        api_targets.append({
                            'asset': asset,
                            'type': asset_type,
                            'severity': severity
                        })
                        score += 5
                        
        except Exception as e:
            logger.debug(f"Could not fetch scopes for {handle}: {e}")
        
        # Extract bounty information
        offers_bounties = attrs.get('offers_bounties', False)
        bounty_table = attrs.get('bounty_table', {})
        
        # Build analysis result
        analysis_result = {
            'handle': handle,
            'name': name,
            'url': f"https://hackerone.com/{handle}",
            'offers_bounties': offers_bounties,
            'state': attrs.get('state', 'unknown'),
            'submission_state': attrs.get('submission_state', 'unknown'),
            'priority_score': score,
            'matched_categories': matched_categories,
            'has_api': has_api,
            'api_targets': api_targets[:10],  # Limit to top 10 for report
            'reports_resolved': attrs.get('number_of_reports_for_user', 0),
            'bounty_ranges': bounty_table,
            'response_efficiency': attrs.get('response_efficiency_percentage', 0),
            'analysis_date': datetime.now().isoformat()
        }
        
        # Determine applicable attacks and calculate value
        analysis_result['applicable_attacks'] = self.determine_applicable_attacks(analysis_result)
        analysis_result['estimated_value'] = self.calculate_estimated_value(analysis_result['applicable_attacks'])
        
        return analysis_result
    
    def filter_high_value_programs(self, programs):
        """Filter and rank programs by ROI potential"""
        analyzed = []
        
        for i, program in enumerate(programs):
            if i % 10 == 0:
                logger.info(f"   Analyzing program {i+1}/{len(programs)}...")
            
            analysis = self.analyze_program(program)
            
            # Only include programs that are open and offer bounties
            if (analysis['submission_state'] == 'open' and
                analysis['offers_bounties'] and
                analysis['state'] in ['public_mode', 'open']):
                analyzed.append(analysis)
        
        # Sort by estimated value first, then priority score
        analyzed.sort(key=lambda x: (x['estimated_value'], x['priority_score']), reverse=True)
        
        return analyzed
    
    def generate_reports(self, programs):
        """Generate detailed reports for Grok4 analysis"""
        
        # Top programs report
        top_20 = programs[:20]
        
        # Calculate totals
        total_potential = sum(p['estimated_value'] for p in top_20)
        
        report = {
            'scan_date': datetime.now().isoformat(),
            'total_programs_scanned': len(programs),
            'programs_with_bounties': len([p for p in programs if p['offers_bounties']]),
            'programs_with_api': len([p for p in programs if p['has_api']]),
            'total_potential_value': f"${total_potential:.0f}",
            'top_roi_programs': top_20,
            'attack_patterns': self.attack_patterns,
            'methodology': {
                'idor_success_rate': '40% on CRM/SaaS/Travel',
                'proven_on': 'HubSpot ($1700-$3500 earned)',
                'time_investment': '5-10 hours per program',
                'tools': ['Search API testing', 'Authorization bypass', 'User enumeration', 'Booking ID manipulation']
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
                'total_potential_monthly': f"${sum(p['estimated_value'] for p in programs) * 4:.0f}",
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
                'monthly_potential': f"${prog['estimated_value'] * 4:.0f}",
                'has_api': prog['has_api'],
                'categories': prog['matched_categories'],
                'applicable_attacks': prog['applicable_attacks'],
                'api_endpoints': []
            }
            
            # Add top 5 critical/high severity API targets
            critical_apis = [api for api in prog['api_targets'] if api['severity'] in ['critical', 'high']][:5]
            for api in critical_apis:
                target['api_endpoints'].append({
                    'url': api['asset'],
                    'severity': api['severity']
                })
            
            yaml_data['top_targets'].append(target)
        
        with open('TOP_PROGRAMS.yaml', 'w') as f:
            yaml.dump(yaml_data, f, default_flow_style=False, sort_keys=False)
    
    def generate_markdown_report(self, programs):
        """Generate human-readable markdown report"""
        
        total_monthly = sum(p['estimated_value'] for p in programs) * 4
        
        md_content = f"""# 🎯 Bug Bounty Program Intelligence Report

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Programs Analyzed**: {len(programs)}
**Total Monthly Potential**: ${total_monthly:.0f}

---

## 🏆 Top 20 High-ROI Programs

"""
        
        for i, prog in enumerate(programs[:20], 1):
            attacks_str = ', '.join(prog['applicable_attacks']) if prog['applicable_attacks'] else 'None identified'
            
            md_content += f"""
### {i}. {prog['name']}

- **Handle**: {prog['handle']}
- **URL**: {prog['url']}
- **Priority Score**: {prog['priority_score']}
- **Has API**: {'✅' if prog['has_api'] else '❌'}
- **Estimated Value**: ${prog['estimated_value']:.0f}
- **Monthly Potential**: ${prog['estimated_value'] * 4:.0f}
- **Categories**: {', '.join(prog['matched_categories']) if prog['matched_categories'] else 'General'}
- **Applicable Attacks**: {attacks_str}
- **Response Rate**: {prog['response_efficiency']}%

**Top API Targets**:
"""
            critical_apis = [api for api in prog['api_targets'] if api['severity'] in ['critical', 'high']][:3]
            for target in critical_apis:
                md_content += f"- {target['asset']} ({target['severity']})\n"
            
            if not critical_apis:
                md_content += "- No critical/high severity APIs found\n"
            
            md_content += "\n---\n"
        
        with open('TOP_PROGRAMS_ANALYSIS.md', 'w') as f:
            f.write(md_content)
    
    def generate_grok4_request(self, programs):
        """Generate analysis request for Grok4"""
        
        total_monthly = sum(p['estimated_value'] for p in programs) * 4
        
        grok_request = f"""# 📊 GROK4 ROI ANALYSIS REQUEST

## Context
We've successfully earned $1,700-$3,500 from HubSpot using IDOR attack pattern on their Search API.
Time invested: 40 hours (but now we have reusable methodology).

## Proven Attack Patterns (Enhanced with 9 Vectors)
1. **IDOR in Search/Booking APIs** - 40% success rate, $2000 avg
2. **User Enumeration** - 60% success rate, $1000 avg
3. **Auth Bypass** - 15% success rate, $6500 avg
4. **SSRF** - 20% success rate, $3500 avg
5. **Info Disclosure** - 70% success rate, $500 avg
6. **Mass Assignment** - 35% success rate, $2500 avg
7. **Broken Access Control** - 25% success rate, $4000 avg
8. **API Rate Limit Bypass** - 50% success rate, $1500 avg
9. **JWT Misconfiguration** - 10% success rate, $5500 avg

## Expected Tools/Methodology
- Burp Suite for API testing
- Custom Python scripts for automation
- Focus on booking/reservation ID manipulation
- Prioritize travel platforms (proven vulnerable)

## Top 20 Programs for Analysis (Total Monthly Potential: ${total_monthly:.0f})

"""
        
        for i, prog in enumerate(programs[:20], 1):
            attacks = ', '.join(prog['applicable_attacks'][:3]) if prog['applicable_attacks'] else 'TBD'
            
            grok_request += f"""
### {i}. {prog['name']}
- Priority Score: {prog['priority_score']}
- Has API: {prog['has_api']}
- Estimated Value: ${prog['estimated_value']:.0f}
- Monthly Potential: ${prog['estimated_value'] * 4:.0f}
- Categories: {prog['matched_categories']}
- Applicable Attacks: {attacks}
"""
            if prog['api_targets']:
                grok_request += f"- Key API: {prog['api_targets'][0]['asset']}\n"
        
        grok_request += """

## Questions for Grok4

1. **Which 5 programs should we target FIRST for maximum ROI?**
2. **What's the optimal time allocation per program?**
3. **Should we focus on depth (one program thoroughly) or breadth (quick IDOR tests on many)?**
4. **Are there any programs where our IDOR pattern is GUARANTEED to work?**
5. **What's the expected monthly income if we dedicate 40 hours/week?**
6. **Should we prioritize high-value auth bypass (15% success) or reliable IDOR (40% success)?**

## Our Constraints
- 40 hours/week available
- Proven IDOR methodology ready
- Need quick wins to build reputation
- Prefer programs with <7 day response time
- Current success: HubSpot report #3306949 pending

Please provide brutal, honest assessment focused on MONEY and TIME EFFICIENCY.
Target: $20,000+/month within 3 months.
"""
        
        with open('GROK4_ANALYSIS_REQUEST.md', 'w') as f:
            f.write(grok_request)
    
    def run(self, max_programs=None):
        """Main execution"""
        print("""
╔══════════════════════════════════════════════════════════════╗
║        Bug Bounty Program Intelligence Scanner V2            ║
║         Enhanced with Real Value Calculations                ║
║           Preparing Data for Grok4 Analysis                  ║
╚══════════════════════════════════════════════════════════════╝
        """)
        
        # Get all programs
        programs = self.get_all_programs(max_programs)
        
        if not programs:
            logger.error("❌ No programs fetched. Check API credentials.")
            return
        
        # Analyze and filter
        logger.info("📊 Analyzing programs for ROI potential...")
        high_value = self.filter_high_value_programs(programs)
        
        logger.info(f"✅ Found {len(high_value)} programs with bounties")
        
        # Generate reports
        logger.info("📝 Generating intelligence reports...")
        report = self.generate_reports(high_value)
        
        print("\n✅ Reports generated:")
        print("   - program_intelligence_report.json")
        print("   - program_intelligence_report.yaml")
        print("   - TOP_PROGRAMS.yaml")
        print("   - TOP_PROGRAMS_ANALYSIS.md")
        print("   - GROK4_ANALYSIS_REQUEST.md")
        
        print(f"\n💰 Top 5 programs by estimated value:")
        for i, prog in enumerate(high_value[:5], 1):
            print(f"   {i}. {prog['name']} (${prog['estimated_value']:.0f}/finding, Score: {prog['priority_score']})")
        
        total_monthly = sum(p['estimated_value'] for p in high_value[:20]) * 4
        print(f"\n💵 Total monthly potential (top 20): ${total_monthly:.0f}")
        
        print("\n🎯 Next step: Share GROK4_ANALYSIS_REQUEST.md with Grok4 for ROI analysis")


def main():
    parser = argparse.ArgumentParser(description='Bug Bounty Program Intelligence Scanner')
    parser.add_argument('--max-programs', type=int, help='Maximum programs to fetch', default=None)
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    scanner = ProgramScanner()
    scanner.run(args.max_programs)


if __name__ == "__main__":
    main()