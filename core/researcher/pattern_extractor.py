#!/usr/bin/env python3
"""
BBHK Pattern Extractor - Extracts vulnerability patterns from reports
Uses NLP and regex to identify exploitable patterns
"""

import re
import json
import sqlite3
from typing import List, Dict, Tuple, Optional
from collections import Counter
import logging

class PatternExtractor:
    """Extracts patterns from vulnerability reports"""
    
    def __init__(self, db_path: str = "data/bbhk.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        
        # Pattern templates for different vulnerability types
        self.pattern_templates = {
            'sqli': [
                r"['\"]?\s*(OR|AND)\s+.*=.*",
                r"UNION\s+(ALL\s+)?SELECT",
                r"';?\s*--",
                r"1\s*=\s*1",
                r"admin'\s*--"
            ],
            'xss': [
                r"<script[^>]*>.*</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<img[^>]*onerror",
                r"alert\(['\"].*['\"]\)"
            ],
            'idor': [
                r"/\w+/\d+",
                r"[?&](id|user|uid|account)=\d+",
                r"/api/v\d+/\w+/\d+",
                r"user_id=\d+"
            ],
            'ssrf': [
                r"(url|uri|path|dest|redirect)=https?://",
                r"fetch\(['\"]https?://",
                r"@[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
                r"localhost:\d+"
            ],
            'xxe': [
                r"<!DOCTYPE[^>]*\[",
                r"<!ENTITY",
                r"SYSTEM\s+['\"]",
                r"&xxe;",
                r"file:///"
            ],
            'lfi': [
                r"\.\./\.\./",
                r"\.\.\\\\\.\.\\\\",
                r"/etc/passwd",
                r"C:\\\\Windows\\\\",
                r"file=/\w+"
            ],
            'rce': [
                r";\s*\w+\s+",
                r"\|\s*\w+",
                r"`.*`",
                r"\$\(.*\)",
                r"eval\("
            ]
        }
        
        # Context indicators for each vulnerability type
        self.context_indicators = {
            'sqli': ['database', 'query', 'sql', 'select', 'where', 'table'],
            'xss': ['input', 'reflect', 'script', 'html', 'dom', 'javascript'],
            'idor': ['authorization', 'access', 'object', 'reference', 'id'],
            'ssrf': ['request', 'url', 'fetch', 'webhook', 'callback'],
            'xxe': ['xml', 'entity', 'dtd', 'parse', 'external'],
            'lfi': ['file', 'include', 'path', 'directory', 'traversal'],
            'rce': ['command', 'execute', 'shell', 'system', 'eval']
        }
    
    def extract_patterns(self, report: Dict) -> List[Dict]:
        """Extract patterns from a vulnerability report"""
        patterns = []
        
        # Combine all text fields
        text = ' '.join([
            str(report.get('title', '')),
            str(report.get('description', '')),
            str(report.get('technical_details', ''))
        ])
        
        # Identify vulnerability type
        vuln_type = self._identify_vuln_type(text, report.get('vulnerability_type'))
        
        # Extract code patterns
        code_patterns = self._extract_code_patterns(text, vuln_type)
        
        # Extract URL patterns
        url_patterns = self._extract_url_patterns(text)
        
        # Extract payload patterns
        payload_patterns = self._extract_payload_patterns(text, vuln_type)
        
        # Combine and score patterns
        for pattern in code_patterns + url_patterns + payload_patterns:
            pattern['report_id'] = report.get('report_id')
            pattern['platform'] = report.get('platform')
            pattern['confidence'] = self._calculate_confidence(pattern, report)
            patterns.append(pattern)
        
        return patterns
    
    def _identify_vuln_type(self, text: str, reported_type: Optional[str]) -> str:
        """Identify vulnerability type from text"""
        if reported_type and reported_type != 'unknown':
            return reported_type
        
        text_lower = text.lower()
        scores = {}
        
        # Score each vulnerability type based on context indicators
        for vuln_type, indicators in self.context_indicators.items():
            score = sum(1 for indicator in indicators if indicator in text_lower)
            scores[vuln_type] = score
        
        # Return highest scoring type
        if scores:
            return max(scores, key=scores.get)
        
        return 'unknown'
    
    def _extract_code_patterns(self, text: str, vuln_type: str) -> List[Dict]:
        """Extract code patterns from text"""
        patterns = []
        
        # Extract code blocks
        code_blocks = re.findall(r'```[\s\S]*?```', text)
        code_blocks.extend(re.findall(r'`[^`]+`', text))
        
        for block in code_blocks:
            # Clean code block
            clean_block = block.strip('`').strip()
            
            # Look for vulnerability patterns
            if vuln_type in self.pattern_templates:
                for template in self.pattern_templates[vuln_type]:
                    if re.search(template, clean_block, re.IGNORECASE):
                        patterns.append({
                            'type': 'code',
                            'vulnerability_type': vuln_type,
                            'pattern': template,
                            'context': clean_block[:200],
                            'source': 'code_block'
                        })
        
        return patterns
    
    def _extract_url_patterns(self, text: str) -> List[Dict]:
        """Extract URL patterns from text"""
        patterns = []
        
        # Find all URLs
        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
        
        for url in urls:
            # Parse URL for patterns
            if '/api/' in url:
                # API endpoint pattern
                api_pattern = re.sub(r'\d+', '{id}', url)
                patterns.append({
                    'type': 'url',
                    'vulnerability_type': 'idor',
                    'pattern': api_pattern,
                    'context': url,
                    'source': 'api_endpoint'
                })
            
            if re.search(r'[?&]\w+=[^&]+', url):
                # Parameter pattern
                param_pattern = re.sub(r'=[^&]+', '={value}', url)
                patterns.append({
                    'type': 'url',
                    'vulnerability_type': 'injection',
                    'pattern': param_pattern,
                    'context': url,
                    'source': 'url_parameter'
                })
        
        return patterns
    
    def _extract_payload_patterns(self, text: str, vuln_type: str) -> List[Dict]:
        """Extract payload patterns from text"""
        patterns = []
        
        # Common payload indicators
        payload_patterns = {
            'sqli': [
                r"['\"].*OR.*['\"]",
                r"['\"];.*--",
                r"UNION.*SELECT"
            ],
            'xss': [
                r"<[^>]+>",
                r"javascript:[^\\s]+",
                r"on\w+=['\"][^'\"]+['\"]"
            ],
            'command': [
                r"[;&|].*[;&|]",
                r"`[^`]+`",
                r"\$\([^)]+\)"
            ]
        }
        
        # Look for payloads in text
        for vuln, templates in payload_patterns.items():
            for template in templates:
                matches = re.findall(template, text, re.IGNORECASE)
                for match in matches[:3]:  # Limit to avoid noise
                    patterns.append({
                        'type': 'payload',
                        'vulnerability_type': vuln if vuln != 'command' else 'rce',
                        'pattern': template,
                        'context': match,
                        'source': 'payload_example'
                    })
        
        return patterns
    
    def _calculate_confidence(self, pattern: Dict, report: Dict) -> float:
        """Calculate confidence score for a pattern"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on report severity
        severity = report.get('severity', '').lower()
        if severity == 'critical':
            confidence += 0.2
        elif severity == 'high':
            confidence += 0.15
        elif severity == 'medium':
            confidence += 0.1
        
        # Increase confidence if pattern type matches report type
        if pattern['vulnerability_type'] == report.get('vulnerability_type'):
            confidence += 0.15
        
        # Increase confidence for code patterns
        if pattern['type'] == 'code':
            confidence += 0.1
        
        # Cap at 0.95
        return min(confidence, 0.95)
    
    def learn_from_reports(self, min_reports: int = 5) -> Dict:
        """Learn new patterns from multiple reports"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get recent disclosed reports
        cursor.execute("""
            SELECT * FROM disclosed_reports
            WHERE disclosed_at > date('now', '-30 days')
            ORDER BY disclosed_at DESC
            LIMIT 100
        """)
        
        columns = [desc[0] for desc in cursor.description]
        reports = []
        
        for row in cursor.fetchall():
            reports.append(dict(zip(columns, row)))
        
        # Extract patterns from each report
        all_patterns = []
        for report in reports:
            patterns = self.extract_patterns(report)
            all_patterns.extend(patterns)
        
        # Find common patterns
        pattern_counter = Counter()
        for pattern in all_patterns:
            key = f"{pattern['vulnerability_type']}:{pattern['pattern']}"
            pattern_counter[key] += 1
        
        # Save patterns that appear in multiple reports
        learned_patterns = []
        for pattern_key, count in pattern_counter.items():
            if count >= min_reports:
                vuln_type, pattern_str = pattern_key.split(':', 1)
                
                # Save to database
                cursor.execute("""
                    INSERT OR IGNORE INTO patterns
                    (pattern_id, vulnerability_type, pattern_regex, confidence_score)
                    VALUES (?, ?, ?, ?)
                """, (
                    f"learned_{hash(pattern_key) % 10000}",
                    vuln_type,
                    pattern_str,
                    min(count / 10, 0.9)  # Confidence based on frequency
                ))
                
                learned_patterns.append({
                    'type': vuln_type,
                    'pattern': pattern_str,
                    'frequency': count,
                    'confidence': min(count / 10, 0.9)
                })
        
        conn.commit()
        conn.close()
        
        return {
            'total_reports': len(reports),
            'total_patterns': len(all_patterns),
            'learned_patterns': learned_patterns
        }
    
    def analyze_report_text(self, text: str) -> Dict:
        """Analyze arbitrary text for vulnerability patterns"""
        results = {
            'vulnerabilities': [],
            'indicators': [],
            'payloads': []
        }
        
        text_lower = text.lower()
        
        # Check for vulnerability indicators
        for vuln_type, indicators in self.context_indicators.items():
            found_indicators = [ind for ind in indicators if ind in text_lower]
            if found_indicators:
                results['indicators'].append({
                    'type': vuln_type,
                    'indicators': found_indicators,
                    'confidence': len(found_indicators) / len(indicators)
                })
        
        # Check for vulnerability patterns
        for vuln_type, templates in self.pattern_templates.items():
            for template in templates:
                if re.search(template, text, re.IGNORECASE):
                    results['vulnerabilities'].append({
                        'type': vuln_type,
                        'pattern': template,
                        'matched': True
                    })
        
        # Extract potential payloads
        code_blocks = re.findall(r'`[^`]+`', text)
        for block in code_blocks:
            results['payloads'].append(block.strip('`'))
        
        return results


def main():
    """CLI interface for pattern extractor"""
    import argparse
    
    parser = argparse.ArgumentParser(description='BBHK Pattern Extractor')
    parser.add_argument('action', choices=['extract', 'learn', 'analyze'],
                       help='Action to perform')
    parser.add_argument('--report-id', help='Report ID to extract from')
    parser.add_argument('--text', help='Text to analyze')
    parser.add_argument('--min-reports', type=int, default=5,
                       help='Minimum reports for pattern learning')
    
    args = parser.parse_args()
    
    extractor = PatternExtractor()
    
    if args.action == 'extract':
        if not args.report_id:
            print("Error: --report-id required for extraction")
            return
        
        # Get report from database
        conn = sqlite3.connect(extractor.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM disclosed_reports WHERE report_id = ?", (args.report_id,))
        
        row = cursor.fetchone()
        if not row:
            print(f"Report {args.report_id} not found")
            return
        
        columns = [desc[0] for desc in cursor.description]
        report = dict(zip(columns, row))
        conn.close()
        
        patterns = extractor.extract_patterns(report)
        
        print(f"\nExtracted {len(patterns)} patterns from report {args.report_id}:")
        for pattern in patterns:
            print(f"\n[{pattern['vulnerability_type']}] {pattern['type']}")
            print(f"  Pattern: {pattern['pattern']}")
            print(f"  Confidence: {pattern['confidence']:.2%}")
    
    elif args.action == 'learn':
        results = extractor.learn_from_reports(args.min_reports)
        
        print("\n=== Pattern Learning Results ===")
        print(f"Analyzed: {results['total_reports']} reports")
        print(f"Found: {results['total_patterns']} patterns")
        print(f"Learned: {len(results['learned_patterns'])} new patterns")
        
        if results['learned_patterns']:
            print("\nTop learned patterns:")
            for pattern in results['learned_patterns'][:5]:
                print(f"  [{pattern['type']}] Frequency: {pattern['frequency']}, Confidence: {pattern['confidence']:.2%}")
    
    elif args.action == 'analyze':
        if not args.text:
            print("Error: --text required for analysis")
            return
        
        results = extractor.analyze_report_text(args.text)
        
        print("\n=== Text Analysis Results ===")
        
        if results['indicators']:
            print("\nVulnerability Indicators:")
            for ind in results['indicators']:
                print(f"  {ind['type']}: {', '.join(ind['indicators'])} (confidence: {ind['confidence']:.2%})")
        
        if results['vulnerabilities']:
            print("\nDetected Patterns:")
            for vuln in results['vulnerabilities']:
                print(f"  {vuln['type']}: {vuln['pattern']}")
        
        if results['payloads']:
            print("\nPotential Payloads:")
            for payload in results['payloads']:
                print(f"  {payload}")


if __name__ == "__main__":
    main()