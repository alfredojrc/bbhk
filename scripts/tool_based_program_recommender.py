#!/usr/bin/env python3
"""
Tool-Based Bug Bounty Program Recommender
Date: August 20, 2025
Author: BBHK Team

This system matches bug bounty programs to available Kali Linux tools
and creates learning-focused recommendations for skill development.
"""

import os
import requests
import psycopg2
from psycopg2.extras import RealDictCursor, Json
import json
import subprocess
import time
from datetime import datetime
import logging
import sys
from typing import Dict, List, Optional, Any, Tuple
import re
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tool_recommendations.log'),
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

class ToolBasedProgramRecommender:
    """
    Recommends programs based on tool availability and learning opportunities
    """
    
    def __init__(self):
        self.auth = (USERNAME, API_TOKEN)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update({'Accept': 'application/json'})
        self.db_conn = None
        
        # Tool categories and their mappings
        self.tool_categories = {
            'reconnaissance': {
                'tools': ['amass', 'subfinder', 'sublist3r', 'dnsrecon', 'fierce', 'httpx'],
                'vulnerability_types': ['Information Disclosure', 'Subdomain Takeover'],
                'skill_level': 'beginner',
                'learning_value': 8
            },
            'web_scanning': {
                'tools': ['nuclei', 'nikto', 'wapiti', 'ffuf', 'gobuster', 'dirb'],
                'vulnerability_types': ['Security Misconfiguration', 'Sensitive Data Exposure'],
                'skill_level': 'beginner',
                'learning_value': 7
            },
            'sql_injection': {
                'tools': ['sqlmap'],
                'vulnerability_types': ['SQL Injection'],
                'skill_level': 'intermediate',
                'learning_value': 9
            },
            'xss_testing': {
                'tools': ['xsstrike', 'dalfox'],
                'vulnerability_types': ['Cross-Site Scripting (XSS)'],
                'skill_level': 'intermediate',
                'learning_value': 9
            },
            'authentication': {
                'tools': ['hydra', 'jwt_tool', 'john', 'hashcat'],
                'vulnerability_types': ['Authentication Bypass', 'Weak Password', 'Session Fixation'],
                'skill_level': 'intermediate',
                'learning_value': 8
            },
            'cms_specific': {
                'tools': ['wpscan', 'joomscan', 'droopescan'],
                'vulnerability_types': ['CMS Vulnerabilities', 'Plugin Vulnerabilities'],
                'skill_level': 'beginner',
                'learning_value': 6
            },
            'api_testing': {
                'tools': ['postman', 'insomnia', 'graphql-voyager'],
                'vulnerability_types': ['API Security', 'GraphQL Vulnerabilities', 'IDOR'],
                'skill_level': 'advanced',
                'learning_value': 10
            },
            'command_injection': {
                'tools': ['commix'],
                'vulnerability_types': ['Command Injection', 'RCE'],
                'skill_level': 'advanced',
                'learning_value': 10
            },
            'ssrf_testing': {
                'tools': ['ssrfmap', 'custom'],
                'vulnerability_types': ['Server-Side Request Forgery (SSRF)'],
                'skill_level': 'advanced',
                'learning_value': 10
            },
            'manual_testing': {
                'tools': ['burpsuite', 'zaproxy'],
                'vulnerability_types': ['Business Logic', 'Race Conditions', 'IDOR'],
                'skill_level': 'intermediate',
                'learning_value': 10
            }
        }
        
        # OWASP Top 10 mapping to tools
        self.owasp_mapping = {
            'A01:2021': ['burpsuite', 'custom'],  # Broken Access Control
            'A02:2021': ['sslyze', 'testssl', 'nmap'],  # Cryptographic Failures
            'A03:2021': ['sqlmap', 'commix', 'nosqlmap'],  # Injection
            'A04:2021': ['burpsuite'],  # Insecure Design
            'A05:2021': ['nikto', 'nuclei'],  # Security Misconfiguration
            'A06:2021': ['retire.js', 'npm-audit'],  # Vulnerable Components
            'A07:2021': ['hydra', 'jwt_tool'],  # Authentication Failures
            'A08:2021': ['burpsuite'],  # Software and Data Integrity
            'A09:2021': ['custom'],  # Security Logging Failures
            'A10:2021': ['ssrfmap', 'custom']  # SSRF
        }
        
        # Learning paths
        self.learning_paths = {
            'web_fundamentals': {
                'description': 'Master web application security basics',
                'tools_sequence': ['nikto', 'dirb', 'burpsuite', 'sqlmap', 'xsstrike'],
                'target_vulns': ['XSS', 'SQL Injection', 'IDOR', 'Security Misconfiguration'],
                'estimated_time': '2-3 months',
                'skill_progression': ['beginner', 'intermediate']
            },
            'api_specialist': {
                'description': 'Become an API security expert',
                'tools_sequence': ['postman', 'burpsuite', 'jwt_tool', 'graphql-voyager'],
                'target_vulns': ['IDOR', 'Authentication Bypass', 'GraphQL Injection', 'JWT Vulnerabilities'],
                'estimated_time': '3-4 months',
                'skill_progression': ['intermediate', 'advanced']
            },
            'infrastructure_hunter': {
                'description': 'Focus on infrastructure and cloud security',
                'tools_sequence': ['amass', 'subfinder', 'nuclei', 'ssrfmap'],
                'target_vulns': ['Subdomain Takeover', 'SSRF', 'Cloud Misconfigurations'],
                'estimated_time': '3-4 months',
                'skill_progression': ['intermediate', 'advanced']
            },
            'cms_explorer': {
                'description': 'Specialize in CMS vulnerabilities',
                'tools_sequence': ['wpscan', 'joomscan', 'droopescan', 'nuclei'],
                'target_vulns': ['Plugin Vulnerabilities', 'Theme Vulnerabilities', 'CVEs'],
                'estimated_time': '1-2 months',
                'skill_progression': ['beginner', 'intermediate']
            },
            'advanced_exploitation': {
                'description': 'Master advanced exploitation techniques',
                'tools_sequence': ['commix', 'sqlmap', 'burpsuite', 'custom'],
                'target_vulns': ['RCE', 'Deserialization', 'Race Conditions', 'Business Logic'],
                'estimated_time': '4-6 months',
                'skill_progression': ['advanced', 'expert']
            }
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
    
    def check_installed_tools(self) -> Dict[str, bool]:
        """Check which tools are installed on the system"""
        logger.info("🔍 Checking installed tools...")
        installed_tools = {}
        
        # List of tools to check
        tools_to_check = set()
        for category in self.tool_categories.values():
            tools_to_check.update(category['tools'])
        
        for tool in tools_to_check:
            try:
                # Try to find the tool in PATH
                result = subprocess.run(
                    ['which', tool],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                installed = result.returncode == 0
                installed_tools[tool] = installed
                
                if installed:
                    logger.info(f"   ✅ {tool}: Installed")
                else:
                    logger.debug(f"   ❌ {tool}: Not found")
                    
            except Exception as e:
                installed_tools[tool] = False
                logger.debug(f"   ❌ {tool}: Check failed - {e}")
        
        # Special check for Burp Suite (might be in different location)
        if not installed_tools.get('burpsuite', False):
            burp_paths = [
                '/usr/bin/burpsuite',
                '/opt/burpsuite/burpsuite',
                '/usr/local/bin/burpsuite'
            ]
            for path in burp_paths:
                try:
                    if subprocess.run(['test', '-f', path], capture_output=True).returncode == 0:
                        installed_tools['burpsuite'] = True
                        logger.info(f"   ✅ burpsuite: Found at {path}")
                        break
                except:
                    pass
        
        return installed_tools
    
    def analyze_program_scope(self, program_id: str) -> Dict:
        """Analyze program scope to determine tool applicability"""
        cursor = self.db_conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT 
                asset_type,
                asset_identifier,
                eligible_for_bounty,
                max_severity,
                COUNT(*) as asset_count
            FROM structured_scopes
            WHERE program_id = %s
            GROUP BY asset_type, asset_identifier, eligible_for_bounty, max_severity
        """, (program_id,))
        
        scopes = cursor.fetchall()
        
        analysis = {
            'has_web_assets': False,
            'has_api_assets': False,
            'has_mobile_assets': False,
            'has_cloud_assets': False,
            'has_source_code': False,
            'has_hardware': False,
            'cms_detected': None,
            'total_assets': len(scopes),
            'critical_assets': 0,
            'technologies': []
        }
        
        for scope in scopes:
            asset_type = scope.get('asset_type', '').upper()
            asset_id = scope.get('asset_identifier', '').lower()
            
            # Categorize assets
            if asset_type in ['URL', 'DOMAIN']:
                analysis['has_web_assets'] = True
                
                # Detect CMS
                if 'wordpress' in asset_id or 'wp-' in asset_id:
                    analysis['cms_detected'] = 'wordpress'
                elif 'joomla' in asset_id:
                    analysis['cms_detected'] = 'joomla'
                elif 'drupal' in asset_id:
                    analysis['cms_detected'] = 'drupal'
                
                # Detect API
                if 'api' in asset_id or 'graphql' in asset_id:
                    analysis['has_api_assets'] = True
                    
            elif asset_type in ['ANDROID_APP_ID', 'IOS_APP_ID', 'APPLE_STORE_APP_ID', 'GOOGLE_PLAY_APP_ID']:
                analysis['has_mobile_assets'] = True
                
            elif asset_type in ['SOURCE_CODE', 'GITHUB_USERNAME']:
                analysis['has_source_code'] = True
                
            elif 'AWS' in asset_type or 'AZURE' in asset_type or 'GCP' in asset_type:
                analysis['has_cloud_assets'] = True
                
            elif asset_type in ['HARDWARE', 'IOT']:
                analysis['has_hardware'] = True
            
            # Count critical assets
            if scope.get('max_severity') == 'critical':
                analysis['critical_assets'] += 1
        
        return analysis
    
    def calculate_tool_match_score(self, program: Dict, scope_analysis: Dict, installed_tools: Dict) -> Tuple[float, Dict]:
        """Calculate how well a program matches available tools"""
        scores = defaultdict(float)
        applicable_tools = []
        learning_opportunities = []
        
        # Check which tool categories apply
        for category, info in self.tool_categories.items():
            category_score = 0
            category_tools = []
            
            # Check if tools are installed
            for tool in info['tools']:
                if installed_tools.get(tool, False):
                    category_tools.append(tool)
            
            if not category_tools:
                continue
            
            # Check if category is relevant to program
            if category == 'reconnaissance' and scope_analysis['has_web_assets']:
                category_score = 80
                applicable_tools.extend(category_tools)
                learning_opportunities.append({
                    'category': category,
                    'skills': 'Subdomain enumeration, asset discovery',
                    'value': info['learning_value']
                })
                
            elif category == 'web_scanning' and scope_analysis['has_web_assets']:
                category_score = 75
                applicable_tools.extend(category_tools)
                learning_opportunities.append({
                    'category': category,
                    'skills': 'Vulnerability scanning, misconfiguration detection',
                    'value': info['learning_value']
                })
                
            elif category == 'cms_specific' and scope_analysis['cms_detected']:
                if scope_analysis['cms_detected'] == 'wordpress' and 'wpscan' in category_tools:
                    category_score = 90
                elif scope_analysis['cms_detected'] == 'joomla' and 'joomscan' in category_tools:
                    category_score = 90
                elif scope_analysis['cms_detected'] == 'drupal' and 'droopescan' in category_tools:
                    category_score = 90
                    
                if category_score > 0:
                    applicable_tools.extend(category_tools)
                    learning_opportunities.append({
                        'category': category,
                        'skills': f'{scope_analysis["cms_detected"].title()} security',
                        'value': info['learning_value']
                    })
                    
            elif category == 'api_testing' and scope_analysis['has_api_assets']:
                category_score = 85
                applicable_tools.extend(category_tools)
                learning_opportunities.append({
                    'category': category,
                    'skills': 'API security, GraphQL, JWT testing',
                    'value': info['learning_value']
                })
                
            elif category == 'sql_injection' and scope_analysis['has_web_assets']:
                category_score = 70
                applicable_tools.extend(category_tools)
                learning_opportunities.append({
                    'category': category,
                    'skills': 'Database security, injection attacks',
                    'value': info['learning_value']
                })
                
            elif category == 'manual_testing':
                # Always applicable if we have Burp/ZAP
                if 'burpsuite' in category_tools or 'zaproxy' in category_tools:
                    category_score = 80
                    applicable_tools.extend(category_tools)
                    learning_opportunities.append({
                        'category': category,
                        'skills': 'Manual testing, business logic, IDOR',
                        'value': info['learning_value']
                    })
            
            scores[category] = category_score
        
        # Calculate overall score
        if scores:
            total_score = sum(scores.values()) / len(scores)
        else:
            total_score = 0
        
        # Bonus for diversity of learning opportunities
        if len(learning_opportunities) > 3:
            total_score += 10
        
        # Bonus for critical assets
        if scope_analysis['critical_assets'] > 0:
            total_score += 15
        
        return min(100, total_score), {
            'category_scores': dict(scores),
            'applicable_tools': list(set(applicable_tools)),
            'learning_opportunities': learning_opportunities,
            'tool_coverage': len(applicable_tools)
        }
    
    def recommend_learning_path(self, installed_tools: Dict) -> Dict:
        """Recommend a learning path based on available tools"""
        best_path = None
        best_score = 0
        
        for path_name, path_info in self.learning_paths.items():
            # Check how many tools in the path are available
            available_tools = sum(
                1 for tool in path_info['tools_sequence']
                if installed_tools.get(tool, False) or tool == 'custom'
            )
            
            coverage = available_tools / len(path_info['tools_sequence'])
            
            if coverage > best_score:
                best_score = coverage
                best_path = path_name
        
        if best_path:
            return {
                'path_name': best_path,
                'info': self.learning_paths[best_path],
                'tool_coverage': f"{best_score:.0%}"
            }
        
        return None
    
    def generate_tool_recommendations(self, top_n: int = 20) -> List[Dict]:
        """Generate program recommendations based on tools"""
        logger.info("🎯 Generating tool-based program recommendations...")
        
        # Check installed tools
        installed_tools = self.check_installed_tools()
        tools_count = sum(1 for installed in installed_tools.values() if installed)
        logger.info(f"   📦 Found {tools_count} installed tools")
        
        # Get programs from database
        cursor = self.db_conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT DISTINCT p.*
            FROM programs p
            WHERE p.submission_state = 'open'
            AND EXISTS (
                SELECT 1 FROM structured_scopes ss 
                WHERE ss.program_id = p.program_id
            )
            ORDER BY p.offers_bounties DESC, p.name
        """)
        
        programs = cursor.fetchall()
        recommendations = []
        
        for program in programs:
            # Analyze program scope
            scope_analysis = self.analyze_program_scope(program['program_id'])
            
            # Calculate tool match score
            score, details = self.calculate_tool_match_score(
                program, scope_analysis, installed_tools
            )
            
            # Calculate learning value
            learning_value = sum(
                opp['value'] for opp in details.get('learning_opportunities', [])
            )
            
            recommendations.append({
                'program': program,
                'tool_match_score': score,
                'learning_value': learning_value,
                'scope_analysis': scope_analysis,
                'match_details': details,
                'recommendation_reason': self.generate_tool_recommendation_reason(
                    program, score, details, scope_analysis
                )
            })
        
        # Sort by combined score (tool match + learning value)
        recommendations.sort(
            key=lambda x: (x['tool_match_score'] * 0.7 + x['learning_value'] * 3),
            reverse=True
        )
        
        # Get learning path recommendation
        learning_path = self.recommend_learning_path(installed_tools)
        
        return {
            'recommendations': recommendations[:top_n],
            'learning_path': learning_path,
            'installed_tools_summary': {
                'total': tools_count,
                'categories': self.categorize_installed_tools(installed_tools)
            }
        }
    
    def categorize_installed_tools(self, installed_tools: Dict) -> Dict:
        """Categorize installed tools by type"""
        categories = defaultdict(list)
        
        for category, info in self.tool_categories.items():
            for tool in info['tools']:
                if installed_tools.get(tool, False):
                    categories[category].append(tool)
        
        return dict(categories)
    
    def generate_tool_recommendation_reason(self, program: Dict, score: float, details: Dict, scope_analysis: Dict) -> str:
        """Generate recommendation reason based on tools"""
        reasons = []
        
        # Tool coverage
        tool_count = details.get('tool_coverage', 0)
        if tool_count > 5:
            reasons.append(f"Excellent tool coverage ({tool_count} applicable tools)")
        elif tool_count > 3:
            reasons.append(f"Good tool coverage ({tool_count} applicable tools)")
        
        # Learning opportunities
        learning_opps = details.get('learning_opportunities', [])
        if learning_opps:
            top_skills = ', '.join([opp['skills'] for opp in learning_opps[:2]])
            reasons.append(f"Learn: {top_skills}")
        
        # Scope highlights
        if scope_analysis.get('cms_detected'):
            reasons.append(f"{scope_analysis['cms_detected'].title()} target")
        
        if scope_analysis.get('has_api_assets'):
            reasons.append("API testing opportunities")
        
        if scope_analysis.get('critical_assets', 0) > 0:
            reasons.append(f"{scope_analysis['critical_assets']} critical assets")
        
        if not reasons:
            reasons.append("General testing opportunity")
        
        return " • ".join(reasons)
    
    def store_tool_recommendations(self, recommendations: Dict):
        """Store recommendations in database and Qdrant"""
        logger.info("💾 Storing tool-based recommendations...")
        
        cursor = self.db_conn.cursor()
        
        # Create table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tool_recommendations (
                id SERIAL PRIMARY KEY,
                program_handle VARCHAR(100),
                program_id VARCHAR(50),
                tool_match_score FLOAT,
                learning_value INTEGER,
                applicable_tools TEXT[],
                learning_opportunities JSONB,
                scope_analysis JSONB,
                recommendation_reason TEXT,
                generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        for rec in recommendations['recommendations']:
            program = rec['program']
            
            cursor.execute("""
                INSERT INTO tool_recommendations (
                    program_handle, program_id, tool_match_score,
                    learning_value, applicable_tools, learning_opportunities,
                    scope_analysis, recommendation_reason
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                program.get('handle'),
                program.get('program_id'),
                rec['tool_match_score'],
                rec['learning_value'],
                rec['match_details'].get('applicable_tools', []),
                Json(rec['match_details'].get('learning_opportunities', [])),
                Json(rec['scope_analysis']),
                rec['recommendation_reason']
            ))
        
        self.db_conn.commit()
        logger.info(f"   ✅ Stored {len(recommendations['recommendations'])} recommendations")
    
    def print_recommendations(self, results: Dict):
        """Print recommendations in a readable format"""
        print("\n" + "="*80)
        print("🛠️  TOOL-BASED PROGRAM RECOMMENDATIONS")
        print("="*80)
        
        # Print installed tools summary
        print(f"\n📦 Installed Tools: {results['installed_tools_summary']['total']}")
        for category, tools in results['installed_tools_summary']['categories'].items():
            print(f"   • {category}: {', '.join(tools)}")
        
        # Print learning path
        if results['learning_path']:
            path = results['learning_path']
            print(f"\n📚 Recommended Learning Path: {path['path_name'].replace('_', ' ').title()}")
            print(f"   Description: {path['info']['description']}")
            print(f"   Duration: {path['info']['estimated_time']}")
            print(f"   Tool Coverage: {path['tool_coverage']}")
        
        # Print program recommendations
        print("\n🎯 Top Programs for Your Tools:\n")
        
        for i, rec in enumerate(results['recommendations'], 1):
            program = rec['program']
            print(f"#{i}. {program.get('name', 'Unknown')} (@{program.get('handle', 'N/A')})")
            print(f"   Tool Match: {rec['tool_match_score']:.1f}/100")
            print(f"   Learning Value: {rec['learning_value']}/10")
            print(f"   Reason: {rec['recommendation_reason']}")
            
            # Show applicable tools
            tools = rec['match_details'].get('applicable_tools', [])
            if tools:
                print(f"   Tools: {', '.join(tools[:5])}")
            
            # Show learning opportunities
            learning = rec['match_details'].get('learning_opportunities', [])
            if learning:
                skills = [l['skills'] for l in learning[:2]]
                print(f"   Skills: {', '.join(skills)}")
            
            print()
        
        print("="*80)
    
    def run(self, top_n: int = 20):
        """Main execution function"""
        logger.info("🚀 Starting Tool-Based Program Recommender")
        logger.info("="*60)
        
        if not self.connect_db():
            logger.error("Failed to connect to database. Exiting.")
            return
        
        try:
            # Generate recommendations
            results = self.generate_tool_recommendations(top_n)
            
            # Store in database
            self.store_tool_recommendations(results)
            
            # Print results
            self.print_recommendations(results)
            
            logger.info("\n✅ Tool-based recommendations completed!")
            
        except Exception as e:
            logger.error(f"❌ Fatal error: {e}")
            import traceback
            traceback.print_exc()
            
        finally:
            if self.db_conn:
                self.db_conn.close()
                logger.info("Database connection closed")

if __name__ == "__main__":
    recommender = ToolBasedProgramRecommender()
    recommender.run(top_n=20)