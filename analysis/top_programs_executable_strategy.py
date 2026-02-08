#!/usr/bin/env python3
"""
HackerOne Top Programs Executable Strategy
Creates actionable hunting strategy for top ROI programs

Author: BBHK Team + Claude-Flow Hive Mind
Date: August 17, 2025
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
import json
from datetime import datetime

DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'bbhk_db',
    'user': 'bbhk_user',
    'password': os.getenv('POSTGRES_PASSWORD', '')
}

class HackerOneStrategy:
    def __init__(self):
        self.conn = None
        self.top_programs = [
            'watson_group', '8x8-bounty', 'nordsecurity', 'nba-public', 
            'mercadolibre', 'oppo_bbp', 'flutteruki', 'metamask', 
            'crypto', 'grammarly'
        ]
    
    def connect_db(self):
        """Connect to PostgreSQL"""
        self.conn = psycopg2.connect(**DB_CONFIG)
        return True
    
    def get_program_attack_surface(self, handle):
        """Get detailed attack surface for a program"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        query = """
        SELECT 
            p.name,
            p.handle,
            p.offers_bounties,
            p.gold_standard_safe_harbor,
            p.fast_payments,
            
            s.asset_type,
            s.asset_identifier,
            s.max_severity,
            s.eligible_for_bounty,
            s.confidentiality_requirement,
            s.integrity_requirement,
            s.availability_requirement,
            s.instruction
            
        FROM programs p
        JOIN structured_scopes s ON p.program_id = s.program_id
        WHERE p.handle = %s
          AND s.eligible_for_bounty = true
        ORDER BY 
            CASE s.max_severity 
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2  
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            s.asset_identifier;
        """
        
        cursor.execute(query, (handle,))
        return cursor.fetchall()
    
    def generate_hunting_strategy(self):
        """Generate executable hunting strategy"""
        self.connect_db()
        
        strategies = {}
        
        for handle in self.top_programs:
            print(f"\n🎯 Analyzing {handle}...")
            
            scopes = self.get_program_attack_surface(handle)
            if not scopes:
                continue
                
            program_info = scopes[0]  # Get program details
            
            # Categorize assets
            url_assets = [s for s in scopes if s['asset_type'] == 'URL']
            mobile_assets = [s for s in scopes if 'APP_ID' in s['asset_type']]
            critical_assets = [s for s in scopes if s['max_severity'] == 'critical']
            
            strategy = {
                'program_name': program_info['name'],
                'handle': handle,
                'gold_standard': program_info['gold_standard_safe_harbor'],
                'fast_payments': program_info['fast_payments'],
                'total_scope_items': len(scopes),
                'critical_assets': len(critical_assets),
                'url_targets': len(url_assets),
                'mobile_targets': len(mobile_assets),
                
                'priority_targets': [
                    {
                        'asset': s['asset_identifier'],
                        'type': s['asset_type'],
                        'severity': s['max_severity'],
                        'cia': f"C:{s['confidentiality_requirement']}/I:{s['integrity_requirement']}/A:{s['availability_requirement']}",
                        'notes': s['instruction'] or 'No special instructions'
                    }
                    for s in critical_assets[:10]  # Top 10 critical assets
                ],
                
                'hunting_approach': self.get_hunting_approach(scopes),
                'estimated_time': self.estimate_time_investment(scopes)
            }
            
            strategies[handle] = strategy
        
        self.save_strategies(strategies)
        self.conn.close()
        
        return strategies
    
    def get_hunting_approach(self, scopes):
        """Determine optimal hunting approach"""
        url_count = len([s for s in scopes if s['asset_type'] == 'URL'])
        mobile_count = len([s for s in scopes if 'APP_ID' in s['asset_type']])
        critical_count = len([s for s in scopes if s['max_severity'] == 'critical'])
        
        approaches = []
        
        if url_count > 50:
            approaches.append("🌐 Web Application Focus: Large attack surface")
        elif url_count > 10:
            approaches.append("🎯 Targeted Web Testing: Quality over quantity")
        
        if mobile_count > 0:
            approaches.append("📱 Mobile Application Testing: API endpoints")
        
        if critical_count > 20:
            approaches.append("🔥 High-Impact Focus: Many critical assets")
        
        if critical_count / len(scopes) > 0.8:
            approaches.append("💎 Premium Targets: High critical ratio")
        
        return approaches
    
    def estimate_time_investment(self, scopes):
        """Estimate time investment for program"""
        total_scopes = len(scopes)
        critical_scopes = len([s for s in scopes if s['max_severity'] == 'critical'])
        
        # Base hours per scope type
        base_hours = total_scopes * 2  # 2 hours per scope
        critical_multiplier = critical_scopes * 3  # Extra 3 hours for critical
        
        total_hours = base_hours + critical_multiplier
        
        if total_hours <= 20:
            return "Low (1-3 days)"
        elif total_hours <= 40:
            return "Medium (1 week)"
        elif total_hours <= 80:
            return "High (2 weeks)"
        else:
            return "Very High (1 month+)"
    
    def save_strategies(self, strategies):
        """Save strategies to file"""
        output = {
            'generated_date': datetime.now().isoformat(),
            'total_programs': len(strategies),
            'strategies': strategies,
            'summary': self.generate_summary(strategies)
        }
        
        with open('/home/kali/bbhk/analysis/executable_hunting_strategies.json', 'w') as f:
            json.dump(output, f, indent=2, default=str)
        
        print(f"\n💾 Strategies saved to: /home/kali/bbhk/analysis/executable_hunting_strategies.json")
    
    def generate_summary(self, strategies):
        """Generate executive summary"""
        total_critical = sum(s['critical_assets'] for s in strategies.values())
        total_scopes = sum(s['total_scope_items'] for s in strategies.values())
        gold_standard = sum(1 for s in strategies.values() if s['gold_standard'])
        
        return {
            'total_programs_analyzed': len(strategies),
            'total_scope_items': total_scopes,
            'total_critical_assets': total_critical,
            'gold_standard_programs': gold_standard,
            'critical_ratio': f"{(total_critical/total_scopes)*100:.1f}%",
            'recommended_start': list(strategies.keys())[:3]
        }
    
    def print_top_recommendations(self, strategies):
        """Print actionable recommendations"""
        print("\n" + "="*80)
        print("🎯 TOP 3 EXECUTABLE STRATEGIES")
        print("="*80)
        
        for i, (handle, strategy) in enumerate(list(strategies.items())[:3], 1):
            print(f"\n{i}. {strategy['program_name']} (@{handle})")
            print(f"   🎯 Critical Assets: {strategy['critical_assets']}")
            print(f"   ⏱️  Time Investment: {strategy['estimated_time']}")
            print(f"   🛡️  Gold Standard: {'✅' if strategy['gold_standard'] else '❌'}")
            print(f"   ⚡ Fast Payments: {'✅' if strategy['fast_payments'] else '❌'}")
            print(f"   📋 Hunting Approach:")
            for approach in strategy['hunting_approach']:
                print(f"      • {approach}")
            
            print(f"   🎯 Top 3 Priority Targets:")
            for j, target in enumerate(strategy['priority_targets'][:3], 1):
                print(f"      {j}. {target['asset']} ({target['severity']} - {target['cia']})")

if __name__ == "__main__":
    strategy_generator = HackerOneStrategy()
    strategies = strategy_generator.generate_hunting_strategy()
    strategy_generator.print_top_recommendations(strategies)