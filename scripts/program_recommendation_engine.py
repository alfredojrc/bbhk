#!/usr/bin/env python3
"""
Advanced Bug Bounty Program Recommendation Engine
Date: August 20, 2025
Author: BBHK Team

This system provides intelligent program recommendations based on:
1. Historical performance analysis
2. Skill matching
3. ROI calculations
4. Program health metrics
5. Real-time opportunities from HackerOne API
"""

import os
import requests
import psycopg2
from psycopg2.extras import RealDictCursor, Json
import json
import time
from datetime import datetime, timedelta
import logging
import sys
from typing import Dict, List, Optional, Any, Tuple
import numpy as np
from decimal import Decimal
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('program_recommendations.log'),
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

class ProgramRecommendationEngine:
    """
    Advanced recommendation engine for bug bounty programs
    """
    
    def __init__(self):
        self.auth = (USERNAME, API_TOKEN)
        self.headers = {'Accept': 'application/json'}
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update(self.headers)
        self.db_conn = None
        
        # Scoring weights (configurable)
        self.weights = {
            'bounty_amount': 0.25,      # Financial incentive
            'response_time': 0.20,      # Program responsiveness
            'resolution_rate': 0.15,    # Valid report acceptance
            'skill_match': 0.15,        # Alignment with hacker skills
            'program_health': 0.10,     # Overall program quality
            'competition': 0.05,        # Number of hackers
            'scope_quality': 0.05,      # Asset value and breadth
            'historical_roi': 0.05      # Past success rate
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
    
    def fetch_opportunities(self) -> List[Dict]:
        """Fetch opportunities from HackerOne API"""
        logger.info("🔍 Fetching opportunities from HackerOne...")
        
        try:
            # Try the opportunities endpoint
            response = self.session.get(f"{BASE_URL}/opportunities", timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                opportunities = data.get('data', [])
                logger.info(f"   ✅ Retrieved {len(opportunities)} opportunities")
                return opportunities
            elif response.status_code == 404:
                logger.info("   ℹ️ Opportunities endpoint not available, using programs")
                # Fall back to programs endpoint
                return self.fetch_programs_as_opportunities()
            else:
                logger.error(f"   ❌ Error fetching opportunities: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"   ❌ Exception: {e}")
            return []
    
    def fetch_programs_as_opportunities(self) -> List[Dict]:
        """Fetch programs as opportunities fallback"""
        cursor = self.db_conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT p.*, 
                   COUNT(DISTINCT ss.id) as scope_count,
                   COUNT(DISTINCT ss.id) FILTER (WHERE ss.max_severity = 'critical') as critical_scopes
            FROM programs p
            LEFT JOIN structured_scopes ss ON p.program_id = ss.program_id
            WHERE p.submission_state = 'open'
            GROUP BY p.id, p.program_id
        """)
        
        return cursor.fetchall()
    
    def analyze_hacker_profile(self) -> Dict:
        """Analyze the hacker's profile and performance"""
        logger.info("👤 Analyzing hacker profile...")
        
        cursor = self.db_conn.cursor(cursor_factory=RealDictCursor)
        
        # Get report statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_reports,
                COUNT(*) FILTER (WHERE state = 'resolved') as resolved_reports,
                COUNT(*) FILTER (WHERE bounty_awarded = true) as bounty_reports,
                AVG(total_awarded_amount) FILTER (WHERE bounty_awarded = true) as avg_bounty,
                MAX(total_awarded_amount) as max_bounty,
                COUNT(DISTINCT program_handle) as programs_reported,
                COUNT(*) FILTER (WHERE severity_rating = 'critical') as critical_reports,
                COUNT(*) FILTER (WHERE severity_rating = 'high') as high_reports,
                COUNT(*) FILTER (WHERE severity_rating = 'medium') as medium_reports,
                COUNT(*) FILTER (WHERE severity_rating = 'low') as low_reports,
                AVG(time_to_triage) FILTER (WHERE time_to_triage IS NOT NULL) as avg_triage_time,
                AVG(time_to_bounty) FILTER (WHERE time_to_bounty IS NOT NULL) as avg_bounty_time
            FROM hacker_reports
        """)
        
        stats = cursor.fetchone()
        
        # Get most successful programs
        cursor.execute("""
            SELECT 
                program_handle,
                COUNT(*) as report_count,
                SUM(total_awarded_amount) as total_earned,
                AVG(total_awarded_amount) as avg_earned,
                COUNT(*) FILTER (WHERE bounty_awarded = true) as bounty_count
            FROM hacker_reports
            WHERE program_handle IS NOT NULL
            GROUP BY program_handle
            ORDER BY total_earned DESC NULLS LAST
            LIMIT 10
        """)
        
        top_programs = cursor.fetchall()
        
        # Get vulnerability type expertise
        cursor.execute("""
            SELECT 
                weakness_name,
                COUNT(*) as count,
                AVG(total_awarded_amount) as avg_bounty
            FROM hacker_reports
            WHERE weakness_name IS NOT NULL
            GROUP BY weakness_name
            ORDER BY count DESC
            LIMIT 10
        """)
        
        expertise = cursor.fetchall()
        
        # Calculate success rate
        success_rate = 0
        if stats['total_reports'] > 0:
            success_rate = (stats['resolved_reports'] or 0) / stats['total_reports']
        
        profile = {
            'statistics': dict(stats),
            'success_rate': success_rate,
            'top_programs': [dict(p) for p in top_programs],
            'expertise': [dict(e) for e in expertise],
            'skill_level': self.calculate_skill_level(stats)
        }
        
        logger.info(f"   ✅ Profile analysis complete. Success rate: {success_rate:.2%}")
        return profile
    
    def calculate_skill_level(self, stats: Dict) -> str:
        """Calculate hacker skill level based on performance"""
        points = 0
        
        # Award points based on achievements
        if stats.get('total_reports', 0) > 50:
            points += 3
        elif stats.get('total_reports', 0) > 20:
            points += 2
        elif stats.get('total_reports', 0) > 5:
            points += 1
        
        if stats.get('critical_reports', 0) > 5:
            points += 3
        elif stats.get('critical_reports', 0) > 2:
            points += 2
        elif stats.get('critical_reports', 0) > 0:
            points += 1
        
        avg_bounty = stats.get('avg_bounty') or 0
        if avg_bounty > 5000:
            points += 3
        elif avg_bounty > 1000:
            points += 2
        elif avg_bounty > 500:
            points += 1
        
        # Determine skill level
        if points >= 7:
            return "expert"
        elif points >= 4:
            return "advanced"
        elif points >= 2:
            return "intermediate"
        else:
            return "beginner"
    
    def calculate_program_score(self, program: Dict, profile: Dict) -> Tuple[float, Dict]:
        """
        Calculate a comprehensive score for a program
        Returns: (score, breakdown)
        """
        scores = {}
        
        # 1. Bounty Amount Score (0-100)
        avg_bounty = self.get_program_avg_bounty(program.get('handle'))
        if avg_bounty > 10000:
            scores['bounty_amount'] = 100
        elif avg_bounty > 5000:
            scores['bounty_amount'] = 80
        elif avg_bounty > 1000:
            scores['bounty_amount'] = 60
        elif avg_bounty > 500:
            scores['bounty_amount'] = 40
        else:
            scores['bounty_amount'] = 20
        
        # 2. Response Time Score (0-100)
        response_time = self.get_program_response_time(program.get('handle'))
        if response_time and response_time < 86400:  # < 1 day
            scores['response_time'] = 100
        elif response_time and response_time < 259200:  # < 3 days
            scores['response_time'] = 70
        elif response_time and response_time < 604800:  # < 7 days
            scores['response_time'] = 40
        else:
            scores['response_time'] = 20
        
        # 3. Resolution Rate Score (0-100)
        resolution_rate = self.get_program_resolution_rate(program.get('handle'))
        scores['resolution_rate'] = resolution_rate * 100
        
        # 4. Skill Match Score (0-100)
        scores['skill_match'] = self.calculate_skill_match(program, profile)
        
        # 5. Program Health Score (0-100)
        scores['program_health'] = self.calculate_program_health(program)
        
        # 6. Competition Score (0-100) - Less competition is better
        hacker_count = self.get_program_hacker_count(program.get('handle'))
        if hacker_count < 100:
            scores['competition'] = 100
        elif hacker_count < 500:
            scores['competition'] = 70
        elif hacker_count < 1000:
            scores['competition'] = 40
        else:
            scores['competition'] = 20
        
        # 7. Scope Quality Score (0-100)
        scores['scope_quality'] = self.calculate_scope_quality(program)
        
        # 8. Historical ROI Score (0-100)
        scores['historical_roi'] = self.calculate_historical_roi(program, profile)
        
        # Calculate weighted total score
        total_score = sum(
            scores.get(metric, 0) * weight 
            for metric, weight in self.weights.items()
        )
        
        return total_score, scores
    
    def get_program_avg_bounty(self, handle: str) -> float:
        """Get average bounty for a program"""
        if not handle:
            return 0
            
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT AVG(total_awarded_amount) 
            FROM hacker_reports 
            WHERE program_handle = %s AND bounty_awarded = true
        """, (handle,))
        
        result = cursor.fetchone()
        return float(result[0] or 0)
    
    def get_program_response_time(self, handle: str) -> Optional[int]:
        """Get average response time in seconds"""
        if not handle:
            return None
            
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT AVG(time_to_triage) 
            FROM hacker_reports 
            WHERE program_handle = %s AND time_to_triage IS NOT NULL
        """, (handle,))
        
        result = cursor.fetchone()
        return int(result[0]) if result[0] else None
    
    def get_program_resolution_rate(self, handle: str) -> float:
        """Get resolution rate for a program"""
        if not handle:
            return 0
            
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT 
                COUNT(*) FILTER (WHERE state = 'resolved') as resolved,
                COUNT(*) as total
            FROM hacker_reports 
            WHERE program_handle = %s
        """, (handle,))
        
        result = cursor.fetchone()
        if result[1] > 0:
            return result[0] / result[1]
        return 0
    
    def get_program_hacker_count(self, handle: str) -> int:
        """Estimate number of hackers on a program"""
        # This is an estimate based on hacktivity
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT COUNT(DISTINCT reporter_username) 
            FROM hacktivity 
            WHERE program_handle = %s
        """, (handle,))
        
        result = cursor.fetchone()
        return result[0] or 0
    
    def calculate_skill_match(self, program: Dict, profile: Dict) -> float:
        """Calculate how well program matches hacker's skills"""
        score = 50  # Base score
        
        # Check if hacker has experience with this program
        for top_program in profile.get('top_programs', []):
            if top_program.get('program_handle') == program.get('handle'):
                # Strong match - hacker has success history here
                score = 90
                break
        
        # Check vulnerability type alignment
        # (Would need program vulnerability type data for full implementation)
        
        # Adjust based on skill level
        skill_level = profile.get('skill_level', 'beginner')
        if skill_level == 'expert' and program.get('offers_bounties'):
            score += 10
        elif skill_level == 'beginner' and not program.get('offers_bounties'):
            score -= 10
        
        return min(100, max(0, score))
    
    def calculate_program_health(self, program: Dict) -> float:
        """Calculate overall program health score"""
        score = 50  # Base score
        
        # Check various health indicators
        if program.get('submission_state') == 'open':
            score += 20
        
        if program.get('offers_bounties'):
            score += 15
        
        if program.get('triage_active'):
            score += 10
        
        if program.get('fast_payments'):
            score += 5
        
        return min(100, score)
    
    def calculate_scope_quality(self, program: Dict) -> float:
        """Calculate scope quality score"""
        cursor = self.db_conn.cursor()
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total_assets,
                COUNT(*) FILTER (WHERE eligible_for_bounty = true) as bounty_assets,
                COUNT(*) FILTER (WHERE max_severity = 'critical') as critical_assets,
                COUNT(*) FILTER (WHERE max_severity = 'high') as high_assets
            FROM structured_scopes
            WHERE program_id = %s
        """, (program.get('program_id'),))
        
        result = cursor.fetchone()
        
        if not result or result[0] == 0:
            return 20  # Low score if no scope data
        
        score = 0
        
        # More assets = better
        if result[0] > 50:
            score += 30
        elif result[0] > 20:
            score += 20
        elif result[0] > 5:
            score += 10
        
        # Critical assets = better
        if result[2] > 0:
            score += 30
        
        # High severity assets
        if result[3] > 0:
            score += 20
        
        # Bounty eligible assets
        if result[1] > 0:
            bounty_ratio = result[1] / result[0]
            score += bounty_ratio * 20
        
        return min(100, score)
    
    def calculate_historical_roi(self, program: Dict, profile: Dict) -> float:
        """Calculate ROI based on historical performance"""
        # Check if hacker has reported to this program before
        for top_program in profile.get('top_programs', []):
            if top_program.get('program_handle') == program.get('handle'):
                # Calculate ROI: earnings per report
                if top_program.get('report_count', 0) > 0:
                    roi = top_program.get('total_earned', 0) / top_program.get('report_count')
                    
                    if roi > 5000:
                        return 100
                    elif roi > 2000:
                        return 80
                    elif roi > 1000:
                        return 60
                    elif roi > 500:
                        return 40
                    else:
                        return 20
        
        # No history with this program
        return 50  # Neutral score
    
    def generate_recommendations(self, top_n: int = 20) -> List[Dict]:
        """Generate top N program recommendations"""
        logger.info(f"🎯 Generating top {top_n} program recommendations...")
        
        # Analyze hacker profile
        profile = self.analyze_hacker_profile()
        
        # Fetch opportunities/programs
        opportunities = self.fetch_opportunities()
        if not opportunities:
            opportunities = self.fetch_programs_as_opportunities()
        
        recommendations = []
        
        for program in opportunities:
            score, breakdown = self.calculate_program_score(program, profile)
            
            recommendations.append({
                'program': program,
                'total_score': score,
                'score_breakdown': breakdown,
                'recommendation_reason': self.generate_recommendation_reason(
                    program, score, breakdown
                )
            })
        
        # Sort by total score
        recommendations.sort(key=lambda x: x['total_score'], reverse=True)
        
        # Return top N
        return recommendations[:top_n]
    
    def generate_recommendation_reason(self, program: Dict, score: float, breakdown: Dict) -> str:
        """Generate human-readable recommendation reason"""
        reasons = []
        
        # Find top scoring factors
        top_factors = sorted(
            breakdown.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:3]
        
        for factor, factor_score in top_factors:
            if factor == 'bounty_amount' and factor_score > 70:
                reasons.append("High bounty payouts")
            elif factor == 'response_time' and factor_score > 70:
                reasons.append("Fast response times")
            elif factor == 'skill_match' and factor_score > 70:
                reasons.append("Excellent skill match")
            elif factor == 'resolution_rate' and factor_score > 70:
                reasons.append("High resolution rate")
            elif factor == 'scope_quality' and factor_score > 70:
                reasons.append("Quality scope with critical assets")
            elif factor == 'historical_roi' and factor_score > 70:
                reasons.append("Strong historical ROI")
        
        if not reasons:
            reasons.append("Balanced opportunity")
        
        return " • ".join(reasons)
    
    def store_recommendations(self, recommendations: List[Dict]):
        """Store recommendations in database"""
        logger.info("💾 Storing recommendations...")
        
        cursor = self.db_conn.cursor()
        
        for rec in recommendations:
            program = rec['program']
            
            # Generate unique recommendation ID
            rec_id = hashlib.md5(
                f"{program.get('handle', '')}_{datetime.now().isoformat()}".encode()
            ).hexdigest()[:12]
            
            cursor.execute("""
                INSERT INTO program_recommendations (
                    recommendation_id, program_handle, program_id,
                    total_score, score_breakdown, recommendation_reason,
                    recommendation_rank, generated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (recommendation_id) DO UPDATE SET
                    total_score = EXCLUDED.total_score,
                    score_breakdown = EXCLUDED.score_breakdown,
                    updated_at = CURRENT_TIMESTAMP
            """, (
                rec_id,
                program.get('handle'),
                program.get('program_id'),
                rec['total_score'],
                Json(rec['score_breakdown']),
                rec['recommendation_reason'],
                recommendations.index(rec) + 1,
                datetime.now()
            ))
        
        self.db_conn.commit()
        logger.info(f"   ✅ Stored {len(recommendations)} recommendations")
    
    def print_recommendations(self, recommendations: List[Dict]):
        """Print recommendations in a readable format"""
        print("\n" + "="*80)
        print("🎯 TOP PROGRAM RECOMMENDATIONS")
        print("="*80)
        
        for i, rec in enumerate(recommendations, 1):
            program = rec['program']
            print(f"\n#{i}. {program.get('name', 'Unknown')} (@{program.get('handle', 'N/A')})")
            print(f"   Score: {rec['total_score']:.1f}/100")
            print(f"   Reason: {rec['recommendation_reason']}")
            
            if program.get('offers_bounties'):
                print(f"   💰 Offers Bounties: Yes")
            
            # Show score breakdown
            print("   Breakdown:")
            for metric, score in rec['score_breakdown'].items():
                print(f"      • {metric.replace('_', ' ').title()}: {score:.0f}")
        
        print("\n" + "="*80)
    
    def run(self, top_n: int = 20):
        """Main execution function"""
        logger.info("🚀 Starting Program Recommendation Engine")
        logger.info("="*60)
        
        if not self.connect_db():
            logger.error("Failed to connect to database. Exiting.")
            return
        
        try:
            # Generate recommendations
            recommendations = self.generate_recommendations(top_n)
            
            # Store in database
            self.store_recommendations(recommendations)
            
            # Print results
            self.print_recommendations(recommendations)
            
            logger.info("\n✅ Recommendation generation completed!")
            
        except Exception as e:
            logger.error(f"❌ Fatal error: {e}")
            import traceback
            traceback.print_exc()
            
        finally:
            if self.db_conn:
                self.db_conn.close()
                logger.info("Database connection closed")

if __name__ == "__main__":
    engine = ProgramRecommendationEngine()
    engine.run(top_n=20)