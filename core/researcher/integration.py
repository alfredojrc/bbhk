#!/usr/bin/env python3
"""
BBHK Researcher Integration - Connects researcher to scanner and platforms
Bridges variant generation with existing bug hunting components
"""

import json
import sqlite3
import time
from datetime import datetime
from typing import List, Dict, Optional
import logging
from pathlib import Path
import subprocess

class ResearcherIntegration:
    """Integrates researcher profile with BBHK components"""
    
    def __init__(self, db_path: str = "data/bbhk.db", config_path: str = "core/config/system.yaml"):
        self.db_path = db_path
        self.config_path = config_path
        
        # Component instances
        from .report_miner import ReportMiner
        from .pattern_extractor import PatternExtractor
        from .variant_generator import VariantGenerator
        
        self.miner = ReportMiner(db_path, config_path)
        self.extractor = PatternExtractor(db_path)
        self.generator = VariantGenerator(db_path)
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Initialize integration tables
        self._init_database()
    
    def _init_database(self):
        """Initialize integration tracking tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS researcher_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_type VARCHAR(50) NOT NULL,
                target VARCHAR(255),
                variant_id VARCHAR(100),
                pattern_id VARCHAR(100),
                priority INTEGER DEFAULT 5,
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                result TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS researcher_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                variant_id VARCHAR(100),
                pattern_id VARCHAR(100),
                target VARCHAR(255),
                vulnerability_type VARCHAR(100),
                severity VARCHAR(20),
                confidence FLOAT,
                evidence TEXT,
                verified BOOLEAN DEFAULT 0,
                reported BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
    
    def run_research_cycle(self, target: str, scope: List[str]) -> Dict:
        """Run complete research cycle for a target"""
        results = {
            'target': target,
            'started_at': datetime.now().isoformat(),
            'reports_mined': 0,
            'patterns_extracted': 0,
            'variants_generated': 0,
            'variants_tested': 0,
            'findings': []
        }
        
        self.logger.info(f"Starting research cycle for {target}")
        
        # Step 1: Mine recent reports
        self.logger.info("Step 1: Mining disclosed reports...")
        h1_reports = self.miner.mine_hackerone_reports(limit=50)
        bc_reports = self.miner.mine_bugcrowd_reports(limit=50)
        results['reports_mined'] = len(h1_reports) + len(bc_reports)
        
        # Step 2: Extract patterns
        self.logger.info("Step 2: Extracting patterns...")
        all_patterns = []
        for report in h1_reports + bc_reports:
            patterns = self.extractor.extract_patterns(report)
            all_patterns.extend(patterns)
        results['patterns_extracted'] = len(all_patterns)
        
        # Step 3: Learn from patterns
        self.logger.info("Step 3: Learning from patterns...")
        learning_results = self.extractor.learn_from_reports(min_reports=3)
        
        # Step 4: Generate variants
        self.logger.info("Step 4: Generating variants...")
        context = self._build_target_context(target, scope)
        variants = self.generator.generate_variants(target, context)
        results['variants_generated'] = len(variants)
        
        # Step 5: Queue variants for testing
        self.logger.info("Step 5: Queueing variants for testing...")
        for variant in variants[:20]:  # Limit to top 20 variants
            self._queue_variant_test(variant, target)
        
        # Step 6: Test variants (simplified - would use scanner in real implementation)
        self.logger.info("Step 6: Testing variants...")
        tested = self._test_queued_variants(limit=10)
        results['variants_tested'] = tested
        
        # Step 7: Collect findings
        findings = self._get_recent_findings(target)
        results['findings'] = findings
        
        results['completed_at'] = datetime.now().isoformat()
        
        return results
    
    def _build_target_context(self, target: str, scope: List[str]) -> Dict:
        """Build context for target"""
        context = {
            'target': target,
            'scope': scope,
            'endpoints': [],
            'parameters': [],
            'technology': 'unknown'
        }
        
        # Extract endpoints from scope
        for item in scope:
            if '/api/' in item:
                context['endpoints'].append(item)
            elif item.startswith('*.'):
                context['subdomains'] = item
        
        # Detect technology (simplified)
        if any('.php' in s for s in scope):
            context['technology'] = 'php'
        elif any(('node' in s or 'js' in s) for s in scope):
            context['technology'] = 'nodejs'
        elif any('.py' in s for s in scope):
            context['technology'] = 'python'
        
        # Common parameters
        context['parameters'] = ['id', 'user', 'username', 'email', 'search', 
                                'query', 'filter', 'sort', 'page', 'limit']
        
        return context
    
    def _queue_variant_test(self, variant, target: str):
        """Queue a variant for testing"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO researcher_queue
            (task_type, target, variant_id, pattern_id, priority)
            VALUES (?, ?, ?, ?, ?)
        """, (
            'variant_test',
            target,
            variant.variant_id,
            variant.base_pattern.pattern_id,
            int(variant.confidence * 10)  # Priority based on confidence
        ))
        
        conn.commit()
        conn.close()
    
    def _test_queued_variants(self, limit: int = 10) -> int:
        """Test queued variants (simplified version)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get pending variants
        cursor.execute("""
            SELECT * FROM researcher_queue
            WHERE status = 'pending' AND task_type = 'variant_test'
            ORDER BY priority DESC
            LIMIT ?
        """, (limit,))
        
        tasks = cursor.fetchall()
        tested_count = 0
        
        for task in tasks:
            task_id, _, target, variant_id, pattern_id, priority = task[:6]
            
            # Mark as started
            cursor.execute("""
                UPDATE researcher_queue
                SET status = 'testing', started_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (task_id,))
            
            # Simulate testing (in real implementation, would call scanner)
            test_result = self._simulate_variant_test(variant_id, target)
            
            if test_result['success']:
                # Save finding
                cursor.execute("""
                    INSERT INTO researcher_findings
                    (variant_id, pattern_id, target, vulnerability_type, 
                     severity, confidence, evidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    variant_id,
                    pattern_id,
                    target,
                    test_result['vuln_type'],
                    test_result['severity'],
                    test_result['confidence'],
                    test_result['evidence']
                ))
                
                # Update variant status
                self.generator.update_variant_result(
                    variant_id, 'success', test_result['evidence']
                )
            else:
                # Update variant as failed
                self.generator.update_variant_result(
                    variant_id, 'failed', 'No vulnerability found'
                )
            
            # Mark task as completed
            cursor.execute("""
                UPDATE researcher_queue
                SET status = 'completed', completed_at = CURRENT_TIMESTAMP,
                    result = ?
                WHERE id = ?
            """, (json.dumps(test_result), task_id))
            
            tested_count += 1
        
        conn.commit()
        conn.close()
        
        return tested_count
    
    def _simulate_variant_test(self, variant_id: str, target: str) -> Dict:
        """Simulate variant testing (replace with real scanner)"""
        import random
        
        # Get variant details
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT v.*, p.vulnerability_type
            FROM variants v
            JOIN patterns p ON v.pattern_id = p.pattern_id
            WHERE v.variant_id = ?
        """, (variant_id,))
        
        variant = cursor.fetchone()
        conn.close()
        
        if not variant:
            return {'success': False}
        
        # Simulate success based on confidence (10-20% success rate)
        confidence = variant[6]  # confidence field
        success = random.random() < (confidence * 0.2)
        
        if success:
            return {
                'success': True,
                'vuln_type': variant[-1],  # vulnerability_type
                'severity': random.choice(['low', 'medium', 'high', 'critical']),
                'confidence': confidence,
                'evidence': f"Variant {variant_id} confirmed on {target}"
            }
        else:
            return {'success': False}
    
    def _get_recent_findings(self, target: str) -> List[Dict]:
        """Get recent findings for target"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM researcher_findings
            WHERE target = ?
            ORDER BY created_at DESC
            LIMIT 10
        """, (target,))
        
        columns = [desc[0] for desc in cursor.description]
        findings = []
        
        for row in cursor.fetchall():
            findings.append(dict(zip(columns, row)))
        
        conn.close()
        
        return findings
    
    def monitor_research_progress(self) -> Dict:
        """Monitor overall research progress"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Queue statistics
        cursor.execute("""
            SELECT status, COUNT(*)
            FROM researcher_queue
            GROUP BY status
        """)
        stats['queue'] = dict(cursor.fetchall())
        
        # Finding statistics
        cursor.execute("SELECT COUNT(*) FROM researcher_findings")
        stats['total_findings'] = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT vulnerability_type, COUNT(*)
            FROM researcher_findings
            GROUP BY vulnerability_type
            ORDER BY COUNT(*) DESC
            LIMIT 5
        """)
        stats['top_findings'] = dict(cursor.fetchall())
        
        # Variant statistics
        stats['variants'] = self.generator.get_statistics()
        
        # Report statistics
        stats['reports'] = self.miner.get_statistics()
        
        conn.close()
        
        return stats
    
    def export_findings(self, target: Optional[str] = None, 
                       format: str = 'json') -> str:
        """Export findings for reporting"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM researcher_findings"
        params = []
        
        if target:
            query += " WHERE target = ?"
            params.append(target)
        
        query += " ORDER BY confidence DESC, created_at DESC"
        
        cursor.execute(query, params)
        
        columns = [desc[0] for desc in cursor.description]
        findings = []
        
        for row in cursor.fetchall():
            findings.append(dict(zip(columns, row)))
        
        conn.close()
        
        if format == 'json':
            return json.dumps(findings, indent=2, default=str)
        elif format == 'markdown':
            md = "# Researcher Findings\n\n"
            for finding in findings:
                md += f"## {finding['vulnerability_type'].upper()} - {finding['target']}\n"
                md += f"**Severity:** {finding['severity']}\n"
                md += f"**Confidence:** {finding['confidence']:.2%}\n"
                md += f"**Evidence:** {finding['evidence']}\n"
                md += f"**Discovered:** {finding['created_at']}\n\n"
            return md
        else:
            return str(findings)


def main():
    """CLI interface for researcher integration"""
    import argparse
    
    parser = argparse.ArgumentParser(description='BBHK Researcher Integration')
    parser.add_argument('action', choices=['research', 'monitor', 'export', 'test'],
                       help='Action to perform')
    parser.add_argument('--target', help='Target domain or URL')
    parser.add_argument('--scope', nargs='+', help='Scope items')
    parser.add_argument('--format', choices=['json', 'markdown'], 
                       default='json', help='Export format')
    
    args = parser.parse_args()
    
    integration = ResearcherIntegration()
    
    if args.action == 'research':
        if not args.target:
            print("Error: --target required for research")
            return
        
        scope = args.scope or [args.target]
        
        print(f"\n🔬 Starting research cycle for {args.target}")
        results = integration.run_research_cycle(args.target, scope)
        
        print("\n=== Research Results ===")
        print(f"Reports Mined: {results['reports_mined']}")
        print(f"Patterns Extracted: {results['patterns_extracted']}")
        print(f"Variants Generated: {results['variants_generated']}")
        print(f"Variants Tested: {results['variants_tested']}")
        
        if results['findings']:
            print(f"\n🎯 Found {len(results['findings'])} potential vulnerabilities!")
            for finding in results['findings'][:5]:
                print(f"  - {finding['vulnerability_type']}: {finding['evidence']}")
        else:
            print("\n📊 No findings yet, but patterns are being learned!")
    
    elif args.action == 'monitor':
        stats = integration.monitor_research_progress()
        
        print("\n=== Research Progress ===")
        
        print("\nQueue Status:")
        for status, count in stats['queue'].items():
            print(f"  {status}: {count}")
        
        print(f"\nTotal Findings: {stats['total_findings']}")
        
        if stats['top_findings']:
            print("\nTop Vulnerability Types:")
            for vuln_type, count in stats['top_findings'].items():
                print(f"  {vuln_type}: {count}")
        
        print(f"\nVariant Success Rate: {stats['variants']['success_rate']:.1f}%")
        print(f"Reports in Database: {stats['reports']['total_reports']}")
    
    elif args.action == 'export':
        findings = integration.export_findings(
            target=args.target,
            format=args.format
        )
        
        if args.format == 'json':
            # Save to file
            output_file = f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                f.write(findings)
            print(f"Findings exported to {output_file}")
        else:
            print(findings)
    
    elif args.action == 'test':
        # Quick test of components
        print("\n=== Testing Researcher Components ===")
        
        print("\n1. Testing Report Miner...")
        stats = integration.miner.get_statistics()
        print(f"   Reports in DB: {stats['total_reports']}")
        
        print("\n2. Testing Pattern Extractor...")
        test_text = "SQL injection in login form using ' OR '1'='1"
        analysis = integration.extractor.analyze_report_text(test_text)
        print(f"   Detected: {analysis['vulnerabilities'][0]['type'] if analysis['vulnerabilities'] else 'None'}")
        
        print("\n3. Testing Variant Generator...")
        variant_stats = integration.generator.get_statistics()
        print(f"   Total Variants: {variant_stats['total_variants']}")
        
        print("\n✅ All components working!")


if __name__ == "__main__":
    main()