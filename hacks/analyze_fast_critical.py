#!/usr/bin/env python3
"""
Analyze HackerOne programs for Fast Payments + Critical Severity
Extract top targets for focused hunting
"""

import json
from datetime import datetime

def analyze_fast_critical():
    # Load the data
    with open('/home/kali/bbhk/hacks/HACKERONE_PROGRAMS_FOR_GROK4.json', 'r') as f:
        data = json.load(f)
    
    # Filter for fast payments + critical severity
    fast_critical = []
    for program in data['programs']:
        if (program.get('fast_payments') and 
            'critical' in program.get('scope_statistics', {}).get('max_severities', [])):
            fast_critical.append(program)
    
    # Sort by priority score
    fast_critical.sort(key=lambda x: x['priority_score'], reverse=True)
    
    print(f"Found {len(fast_critical)} programs with Fast Payments + Critical Severity\n")
    
    # Get top 5 for today's hunt
    top_5 = fast_critical[:5]
    
    print("=" * 60)
    print("TODAY'S HUNT - Fast Payment + Critical Severity Targets")
    print("=" * 60)
    print()
    
    targets = []
    for i, prog in enumerate(top_5, 1):
        print(f"{i}. {prog['name']} ({prog['handle']})")
        print(f"   Priority Score: {prog['priority_score']}")
        print(f"   Scope Size: {prog['scope_statistics'].get('total_in_scope', 0)} assets")
        print(f"   Response Time: {prog['response_stats'].get('average_time_to_first_program_response', 'N/A')} hours")
        print(f"   URL: {prog['url']}")
        
        # Extract domains for recon
        domains = []
        if 'in_scope_assets' in prog:
            for asset in prog['in_scope_assets'][:5]:  # First 5 assets
                if asset['asset_type'] == 'URL':
                    domain = asset['asset_identifier']
                    if domain.startswith('*.'):
                        domain = domain[2:]  # Remove wildcard
                    domains.append(domain)
        
        if domains:
            print(f"   Key Domains: {', '.join(domains[:3])}")
        
        targets.append({
            'name': prog['name'],
            'handle': prog['handle'],
            'domains': domains,
            'priority_score': prog['priority_score'],
            'scope_size': prog['scope_statistics'].get('total_in_scope', 0)
        })
        print()
    
    # Generate recon commands
    print("=" * 60)
    print("ONE-LINER RECON COMMANDS")
    print("=" * 60)
    print()
    
    for target in targets:
        if target['domains']:
            domain = target['domains'][0]
            print(f"# {target['name']} ({target['handle']})")
            print(f"subfinder -d {domain} -silent | httpx -silent | nuclei -t nuclei-templates/ -silent")
            print()
    
    # Export derived data
    output = {
        'generated': datetime.now().isoformat(),
        'focus': 'Fast Payments + Critical Severity',
        'total_matching': len(fast_critical),
        'todays_hunt': targets,
        'full_list': [{
            'name': p['name'],
            'handle': p['handle'],
            'priority_score': p['priority_score'],
            'scope_size': p['scope_statistics'].get('total_in_scope', 0),
            'response_time': p['response_stats'].get('average_time_to_first_program_response', None)
        } for p in fast_critical[:20]]  # Top 20 for reference
    }
    
    # Save to derived folder
    import os
    os.makedirs('/home/kali/bbhk/hacks/derived', exist_ok=True)
    
    with open('/home/kali/bbhk/hacks/derived/fast_critical_targets.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print("✅ Exported to hacks/derived/fast_critical_targets.json")
    
    return targets

if __name__ == "__main__":
    analyze_fast_critical()