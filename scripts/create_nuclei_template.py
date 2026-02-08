#!/usr/bin/env python3
"""
Create Nuclei Template from Manual Bug Finding
Converts manual vulnerability discoveries into reusable Nuclei YAML templates
"""

import os
import sys
import yaml
import argparse
from datetime import datetime
from pathlib import Path

def create_template(args):
    """Generate Nuclei YAML template from manual finding"""
    
    # Template structure
    template = {
        'id': args.id or f'custom-{args.type}-{datetime.now().strftime("%Y%m%d")}',
        'info': {
            'name': args.name,
            'author': 'BBHK',
            'severity': args.severity,
            'description': args.description or f'Custom {args.type} vulnerability template',
            'reference': args.reference or [],
            'tags': args.tags.split(',') if args.tags else [args.type, 'custom'],
            'metadata': {
                'created': datetime.now().isoformat(),
                'program': args.program or 'unknown'
            }
        }
    }
    
    # Request configuration
    requests = []
    
    if args.type == 'xss':
        request = {
            'method': args.method,
            'path': [args.path],
            'headers': {}
        }
        
        if args.headers:
            for header in args.headers.split(','):
                key, value = header.split(':')
                request['headers'][key.strip()] = value.strip()
        
        if args.payload_param:
            request['path'] = [f"{{{{BaseURL}}}}{args.path}?{args.payload_param}={{{{payload}}}}"]
            request['payloads'] = {
                'payload': [
                    '<script>alert(document.domain)</script>',
                    '"><script>alert(1)</script>',
                    "';alert(1);//",
                    '{{7*7}}',
                    args.custom_payload
                ] if args.custom_payload else [
                    '<script>alert(document.domain)</script>',
                    '"><script>alert(1)</script>'
                ]
            }
        
        request['matchers'] = [{
            'type': 'word',
            'words': args.match_words.split(',') if args.match_words else ['<script>alert']
        }]
        
    elif args.type == 'sqli':
        request = {
            'method': args.method,
            'path': [f"{{{{BaseURL}}}}{args.path}"],
            'payloads': {
                'injection': [
                    "' OR '1'='1",
                    "\" OR \"1\"=\"1",
                    "' OR '1'='1' --",
                    "1' AND '1'='2",
                    args.custom_payload
                ] if args.custom_payload else ["' OR '1'='1", "\" OR \"1\"=\"1"]
            }
        }
        
        request['matchers'] = [{
            'type': 'regex',
            'regex': args.match_regex.split(',') if args.match_regex else [
                'SQL syntax.*MySQL',
                'Warning.*mysql_',
                'PostgreSQL.*ERROR',
                'Warning.*pg_',
                'Microsoft.*ODBC.*SQL',
                'ORA-[0-9]{5}'
            ]
        }]
        
    elif args.type == 'idor':
        request = {
            'method': args.method,
            'path': [f"{{{{BaseURL}}}}{args.path}"],
            'headers': {}
        }
        
        if args.auth_header:
            request['headers']['Authorization'] = args.auth_header
            
        request['matchers'] = [{
            'type': 'status',
            'status': [200]
        }, {
            'type': 'word',
            'words': args.match_words.split(',') if args.match_words else ['user', 'email', 'data'],
            'condition': 'or'
        }]
        
        request['matchers-condition'] = 'and'
        
    elif args.type == 'ssrf':
        request = {
            'method': args.method,
            'path': [f"{{{{BaseURL}}}}{args.path}?{args.payload_param}={{{{interactsh-url}}}}"],
            'matchers': [{
                'type': 'word',
                'part': 'interactsh_protocol',
                'words': ['http', 'dns']
            }]
        }
        
    else:  # Generic template
        request = {
            'method': args.method,
            'path': [f"{{{{BaseURL}}}}{args.path}"],
            'matchers': [{
                'type': 'word',
                'words': args.match_words.split(',') if args.match_words else ['vulnerable']
            }]
        }
    
    requests.append(request)
    template['requests'] = requests
    
    # Output directory
    output_dir = Path.home() / '.local' / 'nuclei-templates' / 'custom' / args.program if args.program else Path.home() / '.local' / 'nuclei-templates' / 'custom'
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Output file
    output_file = output_dir / f"{template['id']}.yaml"
    
    # Write template
    with open(output_file, 'w') as f:
        yaml.dump(template, f, default_flow_style=False, sort_keys=False)
    
    print(f"✅ Template created: {output_file}")
    print(f"\n📋 Template ID: {template['id']}")
    print(f"🎯 Type: {args.type}")
    print(f"⚠️  Severity: {args.severity}")
    
    # Test command
    print(f"\n🧪 Test with:")
    print(f"nuclei -t {output_file} -u {args.test_url or 'https://target.com'}")
    
    # Add to Qdrant
    if args.store_qdrant:
        print("\n📦 Storing in Qdrant...")
        # This would integrate with MCP Qdrant server
        print(f"mcp__qdrant-bbhk__qdrant-store with template info")
    
    return output_file

def main():
    parser = argparse.ArgumentParser(
        description='Convert manual bug findings to Nuclei templates',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # XSS template
  %(prog)s --type xss --name "XSS in Search" --path "/search" --payload-param "q" --severity medium
  
  # SQLi template  
  %(prog)s --type sqli --name "SQL Injection" --path "/api/user" --severity high --method POST
  
  # IDOR template
  %(prog)s --type idor --name "User IDOR" --path "/api/user/{{id}}" --severity high
  
  # Custom template
  %(prog)s --type custom --name "Custom Vuln" --path "/vulnerable" --match-words "error,stack trace"
        """
    )
    
    parser.add_argument('--type', choices=['xss', 'sqli', 'idor', 'ssrf', 'custom'], 
                       required=True, help='Vulnerability type')
    parser.add_argument('--name', required=True, help='Template name')
    parser.add_argument('--path', required=True, help='URL path (e.g., /search, /api/user)')
    parser.add_argument('--method', default='GET', choices=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
                       help='HTTP method')
    parser.add_argument('--severity', default='medium', 
                       choices=['info', 'low', 'medium', 'high', 'critical'],
                       help='Severity level')
    parser.add_argument('--id', help='Custom template ID')
    parser.add_argument('--description', help='Vulnerability description')
    parser.add_argument('--program', help='Bug bounty program name')
    parser.add_argument('--payload-param', help='Parameter name for payload injection')
    parser.add_argument('--custom-payload', help='Custom payload to test')
    parser.add_argument('--match-words', help='Comma-separated words to match in response')
    parser.add_argument('--match-regex', help='Comma-separated regex patterns to match')
    parser.add_argument('--headers', help='Custom headers (format: key1:value1,key2:value2)')
    parser.add_argument('--auth-header', help='Authorization header value')
    parser.add_argument('--tags', help='Comma-separated tags')
    parser.add_argument('--reference', action='append', help='Reference URLs')
    parser.add_argument('--test-url', help='URL to test the template against')
    parser.add_argument('--store-qdrant', action='store_true', 
                       help='Store template info in Qdrant')
    
    args = parser.parse_args()
    
    try:
        template_file = create_template(args)
        print(f"\n✨ Success! Template ready for use in automated scanning.")
    except Exception as e:
        print(f"❌ Error creating template: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()