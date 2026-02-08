#!/usr/bin/env python3
"""
Find Similar CRM/SaaS Programs for IDOR Testing
Based on our proven HubSpot Search API pattern
Date: August 20, 2025
"""

import psycopg2
import json
from datetime import datetime

# Database connection
DB_CONFIG = {
    'dbname': 'bbhk_db',
    'user': 'bbhk_user',
    'password': 'Bbhk2025!@#',
    'host': 'localhost',
    'port': 5432
}

class SimilarTargetFinder:
    def __init__(self):
        self.conn = psycopg2.connect(**DB_CONFIG)
        self.cur = self.conn.cursor()
        
        # Our proven IDOR pattern keywords
        self.idor_keywords = [
            'api', 'crm', 'saas', 'platform', 'cloud', 'contact', 
            'customer', 'search', 'filter', 'query', 'rest',
            'management', 'enterprise', 'business', 'sales',
            'marketing', 'automation', 'workflow', 'integration'
        ]
        
        # High-value target categories
        self.target_categories = [
            'crm', 'saas', 'business', 'enterprise', 'marketing',
            'sales', 'automation', 'platform', 'cloud', 'api'
        ]
    
    def find_similar_programs(self):
        """Find programs similar to HubSpot where IDOR might work"""
        
        print("\n🔍 Finding Similar CRM/SaaS Programs for IDOR Testing")
        print("="*60)
        
        # Query for programs with API scopes and good bounties
        query = """
        SELECT DISTINCT 
            p.handle,
            p.name,
            p.offers_bounties,
            p.state,
            p.submission_state,
            s.asset_identifier,
            s.asset_type,
            s.max_severity
        FROM programs p
        LEFT JOIN structured_scopes s ON p.handle = s.program_handle
        WHERE p.state = 'open'
        AND p.submission_state = 'open'
        AND p.offers_bounties = true
        AND (
            LOWER(p.name) SIMILAR TO '%(crm|saas|sales|marketing|cloud|platform|business|enterprise|api)%'
            OR LOWER(s.asset_identifier) LIKE '%api%'
            OR s.asset_type = 'URL'
        )
        ORDER BY 
            CASE 
                WHEN LOWER(p.name) LIKE '%crm%' THEN 1
                WHEN LOWER(p.name) LIKE '%sales%' THEN 2
                WHEN LOWER(p.name) LIKE '%saas%' THEN 3
                ELSE 4
            END,
            p.name
        LIMIT 50;
        """
        
        self.cur.execute(query)
        results = self.cur.fetchall()
        
        # Categorize programs
        high_priority = []
        medium_priority = []
        low_priority = []
        
        for row in results:
            handle, name, bounties, state, sub_state, asset, asset_type, severity = row
            
            # Skip if no API assets
            if asset and 'api' not in str(asset).lower():
                continue
            
            # Calculate priority score
            score = 0
            name_lower = name.lower() if name else ""
            
            # High priority indicators
            if 'crm' in name_lower: score += 30
            if 'salesforce' in name_lower: score += 25
            if 'hubspot' in name_lower: continue  # Skip HubSpot itself
            if 'pipedrive' in name_lower: score += 20
            if 'zoho' in name_lower: score += 20
            if 'monday' in name_lower: score += 15
            if 'freshworks' in name_lower: score += 15
            if 'dynamics' in name_lower: score += 20
            
            # Medium priority indicators
            if 'saas' in name_lower: score += 10
            if 'platform' in name_lower: score += 10
            if 'cloud' in name_lower: score += 10
            if 'business' in name_lower: score += 8
            if 'enterprise' in name_lower: score += 8
            
            # API indicators
            if asset and 'api' in str(asset).lower(): score += 15
            if severity == 'critical': score += 10
            if severity == 'high': score += 5
            
            program_info = {
                'handle': handle,
                'name': name,
                'asset': asset,
                'severity': severity,
                'score': score,
                'api_endpoint': asset if asset and 'api' in str(asset).lower() else None
            }
            
            if score >= 20:
                high_priority.append(program_info)
            elif score >= 10:
                medium_priority.append(program_info)
            elif score > 0:
                low_priority.append(program_info)
        
        # Sort by score
        high_priority.sort(key=lambda x: x['score'], reverse=True)
        medium_priority.sort(key=lambda x: x['score'], reverse=True)
        low_priority.sort(key=lambda x: x['score'], reverse=True)
        
        return high_priority, medium_priority, low_priority
    
    def generate_test_plan(self, programs):
        """Generate IDOR test plan for similar programs"""
        
        test_plan = {
            'generated': datetime.now().isoformat(),
            'pattern': 'HubSpot Search API IDOR',
            'expected_bounty_per_program': '$1,000-$2,000',
            'success_rate_estimate': '30-40%',
            'high_priority_targets': [],
            'test_payload': {
                'endpoint_patterns': [
                    '/api/v*/search',
                    '/api/v*/contacts/search',
                    '/api/v*/customers/search',
                    '/api/v*/objects/*/search',
                    '/api/v*/query'
                ],
                'payload': {
                    'filterGroups': [{
                        'filters': [{
                            'propertyName': 'id',
                            'operator': 'GT',
                            'value': '0'
                        }]
                    }],
                    'limit': 100
                }
            }
        }
        
        for program in programs[:10]:  # Top 10 programs
            target = {
                'program': program['name'],
                'handle': program['handle'],
                'api_endpoint': program['api_endpoint'],
                'priority_score': program['score'],
                'test_urls': [],
                'notes': ''
            }
            
            # Generate test URLs based on common patterns
            if program['api_endpoint']:
                base_url = program['api_endpoint'].replace('*.', 'api.')
                target['test_urls'] = [
                    f"{base_url}/v1/search",
                    f"{base_url}/v2/search",
                    f"{base_url}/api/search",
                    f"{base_url}/contacts/search",
                    f"{base_url}/customers/search"
                ]
            
            # Add specific notes
            if 'salesforce' in program['name'].lower():
                target['notes'] = "Test SOQL injection patterns as well"
            elif 'pipedrive' in program['name'].lower():
                target['notes'] = "Check /v1/persons and /v1/deals endpoints"
            elif 'zoho' in program['name'].lower():
                target['notes'] = "Test both CRM and Desk APIs"
            
            test_plan['high_priority_targets'].append(target)
        
        return test_plan
    
    def save_results(self, high, medium, low, test_plan):
        """Save results to files"""
        
        # Save program lists
        with open('similar_programs.json', 'w') as f:
            json.dump({
                'high_priority': high[:20],
                'medium_priority': medium[:10],
                'low_priority': low[:10],
                'total_found': len(high) + len(medium) + len(low)
            }, f, indent=2)
        
        # Save test plan
        with open('idor_test_plan.json', 'w') as f:
            json.dump(test_plan, f, indent=2)
        
        # Generate markdown report
        report = f"""# 🎯 IDOR Testing Targets - Similar to HubSpot

## Pattern: Search API Authorization Bypass
**Proven Bounty**: $1,700-$3,500 (HubSpot)
**Expected per Program**: $1,000-$2,000
**Success Rate**: 30-40% estimated

---

## 🔴 HIGH PRIORITY TARGETS (Score 20+)

"""
        for prog in high[:10]:
            report += f"### {prog['name']}\n"
            report += f"- **Handle**: {prog['handle']}\n"
            report += f"- **API**: {prog['api_endpoint']}\n"
            report += f"- **Severity**: {prog['severity']}\n"
            report += f"- **Score**: {prog['score']}\n"
            report += f"- **URL**: https://hackerone.com/{prog['handle']}\n\n"
        
        report += """
## 📋 Test Methodology

1. **Obtain API Access**
   - Sign up for trial/free account
   - Get API token with minimal permissions

2. **Test Search Endpoints**
   ```bash
   curl -X POST "[API_URL]/search" \\
     -H "Authorization: Bearer [TOKEN]" \\
     -d '{"filters":[{"property":"id","operator":"GT","value":"0"}]}'
   ```

3. **Check for IDOR**
   - Can you see all records?
   - Are results properly scoped?
   - Can you access other tenants' data?

4. **Document Evidence**
   - Save API responses
   - Note PII exposed
   - Calculate impact

---

Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open('IDOR_TARGET_PROGRAMS.md', 'w') as f:
            f.write(report)
        
        print(f"\n✅ Results saved to:")
        print(f"   - similar_programs.json")
        print(f"   - idor_test_plan.json")
        print(f"   - IDOR_TARGET_PROGRAMS.md")
    
    def run(self):
        """Main execution"""
        try:
            high, medium, low = self.find_similar_programs()
            
            print(f"\n📊 Results:")
            print(f"   High Priority: {len(high)} programs")
            print(f"   Medium Priority: {len(medium)} programs")
            print(f"   Low Priority: {len(low)} programs")
            
            if high:
                print(f"\n🎯 Top 5 Targets:")
                for prog in high[:5]:
                    print(f"   - {prog['name']} (Score: {prog['score']})")
            
            # Generate test plan
            test_plan = self.generate_test_plan(high)
            
            # Save everything
            self.save_results(high, medium, low, test_plan)
            
            print(f"\n💰 Potential Value:")
            print(f"   If 30% success rate: ${len(high[:10]) * 0.3 * 1500:.0f}")
            print(f"   If 40% success rate: ${len(high[:10]) * 0.4 * 2000:.0f}")
            
        finally:
            self.cur.close()
            self.conn.close()


if __name__ == "__main__":
    finder = SimilarTargetFinder()
    finder.run()