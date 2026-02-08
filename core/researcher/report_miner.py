#!/usr/bin/env python3
"""
BBHK Report Miner - Fetches and processes disclosed bug bounty reports
Mines HackerOne and Bugcrowd for vulnerability patterns
"""

import json
import sqlite3
import time
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging
import re
from pathlib import Path

class ReportMiner:
    """Mines disclosed vulnerability reports for patterns"""
    
    def __init__(self, db_path: str = "data/bbhk.db", config_path: str = "core/config/system.yaml"):
        self.db_path = db_path
        self.config_path = config_path
        self.cache_dir = Path("data/cache/reports")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Load API keys from config
        self.api_keys = self._load_api_keys()
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Initialize database
        self._init_database()
    
    def _load_api_keys(self) -> Dict:
        """Load API keys from config file"""
        import yaml
        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config.get('api_keys', {})
    
    def _init_database(self):
        """Initialize database tables for report storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS disclosed_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform VARCHAR(50) NOT NULL,
                report_id VARCHAR(100) NOT NULL,
                title TEXT,
                vulnerability_type VARCHAR(100),
                severity VARCHAR(20),
                description TEXT,
                technical_details TEXT,
                reward_amount INTEGER,
                disclosed_at TIMESTAMP,
                cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(platform, report_id)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vuln_type 
            ON disclosed_reports(vulnerability_type)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_severity 
            ON disclosed_reports(severity)
        """)
        
        conn.commit()
        conn.close()
    
    def mine_hackerone_reports(self, limit: int = 100) -> List[Dict]:
        """Fetch disclosed reports from HackerOne"""
        reports = []
        
        # HackerOne GraphQL endpoint
        url = "https://api.hackerone.com/v1/hackers/reports"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_keys['hackerone']['token']}"
        }
        
        params = {
            "filter[disclosed]": "true",
            "filter[state]": "resolved",
            "page[size]": min(limit, 100)
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            for report in data.get('data', []):
                processed = self._process_hackerone_report(report)
                if processed:
                    reports.append(processed)
                    self._save_report(processed)
            
            self.logger.info(f"Mined {len(reports)} HackerOne reports")
            
        except Exception as e:
            self.logger.error(f"Error mining HackerOne: {e}")
        
        return reports
    
    def mine_bugcrowd_reports(self, limit: int = 100) -> List[Dict]:
        """Fetch disclosed reports from Bugcrowd"""
        reports = []
        
        # Bugcrowd API endpoint
        url = "https://api.bugcrowd.com/submissions"
        headers = {
            "Accept": "application/vnd.bugcrowd+json",
            "Authorization": f"Token {self.api_keys['bugcrowd']['token']}"
        }
        
        params = {
            "filter[disclosed]": "true",
            "filter[state]": "resolved",
            "limit": min(limit, 100)
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            for report in data.get('data', []):
                processed = self._process_bugcrowd_report(report)
                if processed:
                    reports.append(processed)
                    self._save_report(processed)
            
            self.logger.info(f"Mined {len(reports)} Bugcrowd reports")
            
        except Exception as e:
            self.logger.error(f"Error mining Bugcrowd: {e}")
        
        return reports
    
    def _process_hackerone_report(self, report: Dict) -> Optional[Dict]:
        """Process a HackerOne report into standard format"""
        try:
            return {
                'platform': 'hackerone',
                'report_id': report.get('id'),
                'title': report.get('attributes', {}).get('title'),
                'vulnerability_type': self._extract_vuln_type(report),
                'severity': report.get('relationships', {}).get('severity', {}).get('data', {}).get('attributes', {}).get('rating'),
                'description': report.get('attributes', {}).get('vulnerability_information'),
                'technical_details': self._extract_technical_details(report),
                'reward_amount': report.get('attributes', {}).get('bounty_amount'),
                'disclosed_at': report.get('attributes', {}).get('disclosed_at')
            }
        except Exception as e:
            self.logger.warning(f"Error processing HackerOne report: {e}")
            return None
    
    def _process_bugcrowd_report(self, report: Dict) -> Optional[Dict]:
        """Process a Bugcrowd report into standard format"""
        try:
            return {
                'platform': 'bugcrowd',
                'report_id': report.get('uuid'),
                'title': report.get('title'),
                'vulnerability_type': report.get('vulnerability_type'),
                'severity': report.get('severity'),
                'description': report.get('description'),
                'technical_details': report.get('extra_info'),
                'reward_amount': report.get('monetary_reward', {}).get('amount'),
                'disclosed_at': report.get('disclosed_at')
            }
        except Exception as e:
            self.logger.warning(f"Error processing Bugcrowd report: {e}")
            return None
    
    def _extract_vuln_type(self, report: Dict) -> str:
        """Extract vulnerability type from report"""
        # Common vulnerability keywords
        vuln_patterns = {
            'sqli': r'sql.?injection|sqli',
            'xss': r'cross.?site.?scripting|xss',
            'xxe': r'xml.?external.?entity|xxe',
            'ssrf': r'server.?side.?request.?forgery|ssrf',
            'idor': r'insecure.?direct.?object.?reference|idor',
            'rce': r'remote.?code.?execution|rce',
            'lfi': r'local.?file.?inclusion|lfi',
            'open_redirect': r'open.?redirect',
            'csrf': r'cross.?site.?request.?forgery|csrf',
            'auth_bypass': r'authentication.?bypass|auth.?bypass'
        }
        
        text = str(report).lower()
        
        for vuln_type, pattern in vuln_patterns.items():
            if re.search(pattern, text):
                return vuln_type
        
        return 'unknown'
    
    def _extract_technical_details(self, report: Dict) -> str:
        """Extract technical details from report"""
        details = []
        
        # Look for code snippets, URLs, payloads
        if 'vulnerability_information' in str(report):
            info = report.get('attributes', {}).get('vulnerability_information', '')
            
            # Extract code blocks
            code_blocks = re.findall(r'```[\s\S]*?```', info)
            details.extend(code_blocks)
            
            # Extract URLs
            urls = re.findall(r'https?://[^\s]+', info)
            details.extend(urls)
            
            # Extract potential payloads
            payloads = re.findall(r'<[^>]+>|[\'"][^\'"]+[\'"]', info)
            details.extend(payloads[:5])  # Limit to avoid noise
        
        return '\n'.join(details)
    
    def _save_report(self, report: Dict):
        """Save report to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO disclosed_reports 
                (platform, report_id, title, vulnerability_type, severity, 
                 description, technical_details, reward_amount, disclosed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report['platform'],
                report['report_id'],
                report['title'],
                report['vulnerability_type'],
                report['severity'],
                report['description'],
                report['technical_details'],
                report['reward_amount'],
                report['disclosed_at']
            ))
            
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error saving report: {e}")
        finally:
            conn.close()
    
    def search_reports(self, vuln_type: Optional[str] = None, 
                      severity: Optional[str] = None,
                      days_back: int = 30) -> List[Dict]:
        """Search cached reports by criteria"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM disclosed_reports WHERE 1=1"
        params = []
        
        if vuln_type:
            query += " AND vulnerability_type = ?"
            params.append(vuln_type)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if days_back:
            cutoff = datetime.now() - timedelta(days=days_back)
            query += " AND disclosed_at > ?"
            params.append(cutoff.isoformat())
        
        query += " ORDER BY disclosed_at DESC"
        
        cursor.execute(query, params)
        
        columns = [desc[0] for desc in cursor.description]
        reports = []
        
        for row in cursor.fetchall():
            reports.append(dict(zip(columns, row)))
        
        conn.close()
        
        return reports
    
    def get_statistics(self) -> Dict:
        """Get mining statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total reports
        cursor.execute("SELECT COUNT(*) FROM disclosed_reports")
        stats['total_reports'] = cursor.fetchone()[0]
        
        # By platform
        cursor.execute("""
            SELECT platform, COUNT(*) 
            FROM disclosed_reports 
            GROUP BY platform
        """)
        stats['by_platform'] = dict(cursor.fetchall())
        
        # By vulnerability type
        cursor.execute("""
            SELECT vulnerability_type, COUNT(*) 
            FROM disclosed_reports 
            GROUP BY vulnerability_type
            ORDER BY COUNT(*) DESC
            LIMIT 10
        """)
        stats['top_vulnerabilities'] = dict(cursor.fetchall())
        
        # By severity
        cursor.execute("""
            SELECT severity, COUNT(*) 
            FROM disclosed_reports 
            WHERE severity IS NOT NULL
            GROUP BY severity
        """)
        stats['by_severity'] = dict(cursor.fetchall())
        
        # Average reward
        cursor.execute("""
            SELECT AVG(reward_amount) 
            FROM disclosed_reports 
            WHERE reward_amount > 0
        """)
        stats['avg_reward'] = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return stats


def main():
    """CLI interface for report miner"""
    import argparse
    
    parser = argparse.ArgumentParser(description='BBHK Report Miner')
    parser.add_argument('action', choices=['mine', 'search', 'stats'],
                       help='Action to perform')
    parser.add_argument('--platform', choices=['hackerone', 'bugcrowd', 'all'],
                       default='all', help='Platform to mine')
    parser.add_argument('--limit', type=int, default=100,
                       help='Number of reports to mine')
    parser.add_argument('--vuln-type', help='Vulnerability type to search')
    parser.add_argument('--severity', help='Severity level to search')
    
    args = parser.parse_args()
    
    miner = ReportMiner()
    
    if args.action == 'mine':
        if args.platform in ['hackerone', 'all']:
            miner.mine_hackerone_reports(args.limit)
        if args.platform in ['bugcrowd', 'all']:
            miner.mine_bugcrowd_reports(args.limit)
        print(f"Mining complete. Check database for results.")
    
    elif args.action == 'search':
        reports = miner.search_reports(
            vuln_type=args.vuln_type,
            severity=args.severity
        )
        print(f"Found {len(reports)} reports")
        for report in reports[:10]:
            print(f"- [{report['platform']}] {report['title']}")
    
    elif args.action == 'stats':
        stats = miner.get_statistics()
        print("\n=== Report Mining Statistics ===")
        print(f"Total Reports: {stats['total_reports']}")
        print(f"\nBy Platform:")
        for platform, count in stats['by_platform'].items():
            print(f"  {platform}: {count}")
        print(f"\nTop Vulnerabilities:")
        for vuln, count in list(stats['top_vulnerabilities'].items())[:5]:
            print(f"  {vuln}: {count}")
        print(f"\nAverage Reward: ${stats['avg_reward']:.2f}")


if __name__ == "__main__":
    main()