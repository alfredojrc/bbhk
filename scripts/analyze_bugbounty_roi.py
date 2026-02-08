#!/usr/bin/env python3
"""
Bug Bounty Program ROI Analysis Script
Analyzes 570 HackerOne programs for success potential and ROI

Author: BBHK Team + Claude-Flow Hive Mind
Date: August 17, 2025
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import pandas as pd
from datetime import datetime
import numpy as np

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'bbhk_db',
    'user': 'bbhk_user',
    'password': os.getenv('POSTGRES_PASSWORD', '')
}

class BugBountyROIAnalyzer:
    def __init__(self):
        self.conn = None
        self.analysis_results = {}
        
    def connect_db(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(**DB_CONFIG)
            print("✅ Connected to PostgreSQL database")
            return True
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return False
    
    def get_program_metrics(self):
        """Get comprehensive program metrics"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        query = """
        SELECT 
            p.program_id,
            p.handle,
            p.name,
            p.offers_bounties,
            p.gold_standard_safe_harbor,
            p.submission_state,
            p.state,
            p.triage_active,
            p.fast_payments,
            
            -- Scope metrics
            COUNT(s.id) as total_scopes,
            COUNT(CASE WHEN s.eligible_for_bounty = true THEN 1 END) as bounty_eligible_scopes,
            COUNT(CASE WHEN s.max_severity = 'critical' THEN 1 END) as critical_scopes,
            COUNT(CASE WHEN s.max_severity = 'high' THEN 1 END) as high_scopes,
            COUNT(CASE WHEN s.max_severity = 'medium' THEN 1 END) as medium_scopes,
            COUNT(CASE WHEN s.max_severity = 'low' THEN 1 END) as low_scopes,
            
            -- Asset type distribution
            COUNT(CASE WHEN s.asset_type = 'URL' THEN 1 END) as url_assets,
            COUNT(CASE WHEN s.asset_type = 'IP_ADDRESS' THEN 1 END) as ip_assets,
            COUNT(CASE WHEN s.asset_type = 'GOOGLE_PLAY_APP_ID' THEN 1 END) as mobile_assets,
            COUNT(CASE WHEN s.asset_type = 'APPLE_STORE_APP_ID' THEN 1 END) as ios_assets,
            
            -- CIA requirements (security criticality)
            COUNT(CASE WHEN s.confidentiality_requirement = 'high' THEN 1 END) as high_confidentiality,
            COUNT(CASE WHEN s.integrity_requirement = 'high' THEN 1 END) as high_integrity,
            COUNT(CASE WHEN s.availability_requirement = 'high' THEN 1 END) as high_availability
            
        FROM programs p
        LEFT JOIN structured_scopes s ON p.program_id = s.program_id
        WHERE p.submission_state = 'open'
        GROUP BY p.program_id, p.handle, p.name, p.offers_bounties, 
                 p.gold_standard_safe_harbor, p.submission_state, p.state,
                 p.triage_active, p.fast_payments
        ORDER BY total_scopes DESC;
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        # Convert to list of dicts for easier processing
        programs = [dict(row) for row in results]
        
        print(f"📊 Analyzed {len(programs)} open programs")
        return programs
    
    def calculate_roi_scores(self, programs):
        """Calculate ROI potential scores for each program"""
        scored_programs = []
        
        for program in programs:
            # Base scoring factors
            score = 0
            factors = {}
            
            # 1. Scope Volume Score (0-25 points)
            scope_count = program['total_scopes']
            if scope_count >= 1000:
                scope_score = 25
            elif scope_count >= 500:
                scope_score = 20
            elif scope_count >= 100:
                scope_score = 15
            elif scope_count >= 50:
                scope_score = 10
            elif scope_count >= 10:
                scope_score = 5
            else:
                scope_score = 1
            
            factors['scope_volume'] = scope_score
            score += scope_score
            
            # 2. Critical Asset Score (0-30 points)
            critical_ratio = program['critical_scopes'] / max(scope_count, 1)
            critical_score = min(30, int(critical_ratio * 100))
            factors['critical_assets'] = critical_score
            score += critical_score
            
            # 3. Bounty Program Bonus (0-20 points)
            bounty_score = 20 if program['offers_bounties'] else 0
            factors['offers_bounties'] = bounty_score
            score += bounty_score
            
            # 4. Gold Standard Bonus (0-15 points)
            gold_score = 15 if program['gold_standard_safe_harbor'] else 0
            factors['gold_standard'] = gold_score
            score += gold_score
            
            # 5. Fast Payments Bonus (0-10 points)
            fast_score = 10 if program['fast_payments'] else 0
            factors['fast_payments'] = fast_score
            score += fast_score
            
            # 6. Asset Diversity Score (0-15 points)
            asset_types = 0
            if program['url_assets'] > 0: asset_types += 1
            if program['ip_assets'] > 0: asset_types += 1
            if program['mobile_assets'] > 0: asset_types += 1
            if program['ios_assets'] > 0: asset_types += 1
            
            diversity_score = asset_types * 3  # Max 12, giving buffer to 15
            factors['asset_diversity'] = diversity_score
            score += diversity_score
            
            # 7. High CIA Requirements Bonus (0-10 points)
            cia_score = 0
            if program['high_confidentiality'] > scope_count * 0.5: cia_score += 3
            if program['high_integrity'] > scope_count * 0.5: cia_score += 3
            if program['high_availability'] > scope_count * 0.5: cia_score += 4
            factors['cia_requirements'] = cia_score
            score += cia_score
            
            # Calculate final metrics
            program['roi_score'] = score
            program['roi_factors'] = factors
            program['success_probability'] = min(100, score) / 100  # Normalize to 0-1
            program['risk_level'] = 'Low' if score >= 80 else 'Medium' if score >= 50 else 'High'
            
            scored_programs.append(program)
        
        # Sort by ROI score
        scored_programs.sort(key=lambda x: x['roi_score'], reverse=True)
        
        print(f"✅ Calculated ROI scores for {len(scored_programs)} programs")
        return scored_programs
    
    def identify_top_programs(self, scored_programs, top_n=20):
        """Identify top N programs by ROI potential"""
        top_programs = scored_programs[:top_n]
        
        print(f"🏆 Top {top_n} Programs by ROI Potential:")
        print("=" * 80)
        
        for i, program in enumerate(top_programs, 1):
            print(f"{i:2d}. {program['name']} (@{program['handle']})")
            print(f"    ROI Score: {program['roi_score']}/115")
            print(f"    Success Probability: {program['success_probability']:.1%}")
            print(f"    Scopes: {program['total_scopes']:,} ({program['critical_scopes']} critical)")
            print(f"    Bounties: {'✅' if program['offers_bounties'] else '❌'} | "
                  f"Gold Standard: {'✅' if program['gold_standard_safe_harbor'] else '❌'}")
            print(f"    Risk Level: {program['risk_level']}")
            print()
        
        return top_programs
    
    def generate_category_analysis(self, scored_programs):
        """Generate analysis by different categories"""
        analysis = {}
        
        # Category 1: High Volume Programs (1000+ scopes)
        high_volume = [p for p in scored_programs if p['total_scopes'] >= 1000]
        analysis['high_volume'] = {
            'count': len(high_volume),
            'top_5': high_volume[:5],
            'avg_roi': np.mean([p['roi_score'] for p in high_volume]) if high_volume else 0
        }
        
        # Category 2: Gold Standard Programs
        gold_standard = [p for p in scored_programs if p['gold_standard_safe_harbor']]
        analysis['gold_standard'] = {
            'count': len(gold_standard),
            'top_5': gold_standard[:5],
            'avg_roi': np.mean([p['roi_score'] for p in gold_standard]) if gold_standard else 0
        }
        
        # Category 3: High Critical Asset Ratio
        high_critical = [p for p in scored_programs 
                        if p['critical_scopes'] / max(p['total_scopes'], 1) >= 0.3]
        analysis['high_critical'] = {
            'count': len(high_critical),
            'top_5': high_critical[:5],
            'avg_roi': np.mean([p['roi_score'] for p in high_critical]) if high_critical else 0
        }
        
        # Category 4: Fast Payment Programs
        fast_payment = [p for p in scored_programs if p['fast_payments']]
        analysis['fast_payment'] = {
            'count': len(fast_payment),
            'top_5': fast_payment[:5],
            'avg_roi': np.mean([p['roi_score'] for p in fast_payment]) if fast_payment else 0
        }
        
        return analysis
    
    def save_analysis_results(self, scored_programs, top_programs, category_analysis):
        """Save analysis results to JSON file"""
        results = {
            'analysis_date': datetime.now().isoformat(),
            'total_programs_analyzed': len(scored_programs),
            'top_20_programs': top_programs,
            'category_analysis': category_analysis,
            'summary_stats': {
                'avg_roi_score': np.mean([p['roi_score'] for p in scored_programs]),
                'max_roi_score': max([p['roi_score'] for p in scored_programs]),
                'min_roi_score': min([p['roi_score'] for p in scored_programs]),
                'programs_with_bounties': len([p for p in scored_programs if p['offers_bounties']]),
                'gold_standard_programs': len([p for p in scored_programs if p['gold_standard_safe_harbor']]),
                'total_scopes_analyzed': sum([p['total_scopes'] for p in scored_programs]),
                'total_critical_assets': sum([p['critical_scopes'] for p in scored_programs])
            }
        }
        
        # Save to file
        output_file = '/home/kali/bbhk/analysis/bugbounty_roi_analysis.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"💾 Analysis results saved to: {output_file}")
        return results
    
    def run_analysis(self):
        """Run the complete ROI analysis"""
        print("🚀 Starting Bug Bounty ROI Analysis")
        print("=" * 60)
        
        # Connect to database
        if not self.connect_db():
            return None
        
        # Get program metrics
        programs = self.get_program_metrics()
        
        # Calculate ROI scores
        scored_programs = self.calculate_roi_scores(programs)
        
        # Identify top programs
        top_programs = self.identify_top_programs(scored_programs)
        
        # Generate category analysis
        category_analysis = self.generate_category_analysis(scored_programs)
        
        # Save results
        results = self.save_analysis_results(scored_programs, top_programs, category_analysis)
        
        # Close database connection
        self.conn.close()
        
        print("✅ ROI Analysis Complete!")
        return results

if __name__ == "__main__":
    analyzer = BugBountyROIAnalyzer()
    results = analyzer.run_analysis()