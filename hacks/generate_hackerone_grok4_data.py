#!/usr/bin/env python3
"""
Generate comprehensive HackerOne programs data for Grok4 analysis
Merges data from multiple sources and creates enriched dataset
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_json_file(filepath: str) -> Any:
    """Load JSON file safely"""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading {filepath}: {e}")
        return None

def calculate_scope_statistics(targets: Dict) -> Dict:
    """Calculate statistics about program scope"""
    stats = {
        'total_in_scope': 0,
        'total_out_scope': 0,
        'asset_types': set(),
        'max_severities': set(),
        'eligible_for_bounty_count': 0,
        'by_asset_type': {}
    }
    
    if not targets:
        return stats
    
    # Process in-scope targets
    in_scope = targets.get('in_scope', [])
    if isinstance(in_scope, list):
        stats['total_in_scope'] = len(in_scope)
        for asset in in_scope:
            if isinstance(asset, dict):
                asset_type = asset.get('asset_type', 'Unknown')
                stats['asset_types'].add(asset_type)
                
                # Count by asset type
                if asset_type not in stats['by_asset_type']:
                    stats['by_asset_type'][asset_type] = 0
                stats['by_asset_type'][asset_type] += 1
                
                if asset.get('max_severity'):
                    stats['max_severities'].add(asset.get('max_severity'))
                    
                if asset.get('eligible_for_bounty'):
                    stats['eligible_for_bounty_count'] += 1
    
    # Process out-of-scope targets
    out_scope = targets.get('out_of_scope', [])
    if isinstance(out_scope, list):
        stats['total_out_scope'] = len(out_scope)
    
    # Convert sets to lists for JSON serialization
    stats['asset_types'] = list(stats['asset_types'])
    stats['max_severities'] = list(stats['max_severities'])
    
    return stats

def calculate_priority_score(program: Dict) -> float:
    """Calculate priority score for program selection"""
    score = 0.0
    
    # Base score for offering bounties
    if program.get('offers_bounties'):
        score += 10
    
    # Submission state
    if program.get('submission_state') == 'open':
        score += 5
    
    # Response efficiency
    efficiency = program.get('response_efficiency_percentage')
    if efficiency:
        try:
            score += float(efficiency) / 10  # Max 10 points for 100% efficiency
        except:
            pass
    
    # Fast payments bonus
    if program.get('fast_payments'):
        score += 3
    
    # Scope size bonus
    scope_stats = program.get('scope_statistics', {})
    total_scope = scope_stats.get('total_in_scope', 0)
    if total_scope > 0:
        score += min(total_scope / 2, 10)  # Max 10 points for large scope
    
    # Critical severity available
    if 'critical' in scope_stats.get('max_severities', []):
        score += 5
    
    # Managed program (usually higher quality)
    if program.get('managed_program'):
        score += 2
    
    # Open scope bonus
    if program.get('open_scope'):
        score += 3
    
    # Gold standard safe harbor
    if program.get('gold_standard_safe_harbor'):
        score += 2
    
    # Average response time (lower is better)
    avg_response = program.get('average_time_to_first_program_response')
    if avg_response:
        try:
            days = float(avg_response)
            if days < 1:
                score += 5
            elif days < 3:
                score += 3
            elif days < 7:
                score += 1
        except:
            pass
    
    return round(score, 2)

def merge_program_data(programs1: List[Dict], programs2: List[Dict]) -> Dict[str, Dict]:
    """Merge data from two sources using handle as key"""
    merged = {}
    
    # Process first dataset (with scope information)
    for prog in programs1:
        handle = prog.get('handle')
        if handle:
            merged[handle] = prog.copy()
            # Calculate scope statistics
            if 'targets' in prog:
                merged[handle]['scope_statistics'] = calculate_scope_statistics(prog['targets'])
    
    # Merge second dataset (with more detailed fields)
    for prog in programs2:
        handle = prog.get('handle')
        if handle:
            if handle in merged:
                # Merge fields, preferring non-null values from second dataset
                for key, value in prog.items():
                    if value is not None and (key not in merged[handle] or merged[handle][key] is None):
                        merged[handle][key] = value
            else:
                # New program not in first dataset
                merged[handle] = prog.copy()
                merged[handle]['scope_statistics'] = {}
    
    return merged

def create_grok4_dataset():
    """Main function to create the dataset for Grok4"""
    logger.info("Starting HackerOne data processing for Grok4...")
    
    # Load data files
    data1 = load_json_file('/home/kali/bbhk/data/bounty_targets/hackerone_data.json')
    data2 = load_json_file('/home/kali/bbhk/data/hacker_api_programs_20250817_193331.json')
    
    if not data1 or not data2:
        logger.error("Failed to load required data files")
        return
    
    logger.info(f"Loaded {len(data1)} programs from file 1")
    logger.info(f"Loaded {len(data2)} programs from file 2")
    
    # Merge data
    merged_programs = merge_program_data(data1, data2)
    logger.info(f"Merged into {len(merged_programs)} unique programs")
    
    # Filter for bounty programs and calculate priority scores
    bounty_programs = []
    for handle, program in merged_programs.items():
        if program.get('offers_bounties'):
            # Calculate priority score
            program['priority_score'] = calculate_priority_score(program)
            
            # Clean up program data for output
            cleaned_program = {
                'name': program.get('name', 'Unknown'),
                'handle': handle,
                'url': program.get('url', f'https://hackerone.com/{handle}'),
                'website': program.get('website'),
                'offers_bounties': True,
                'submission_state': program.get('submission_state', 'unknown'),
                'allows_bounty_splitting': program.get('allows_bounty_splitting', False),
                'managed_program': program.get('managed_program', False),
                'triage_active': program.get('triage_active', False),
                'open_scope': program.get('open_scope', False),
                'fast_payments': program.get('fast_payments', False),
                'gold_standard_safe_harbor': program.get('gold_standard_safe_harbor', False),
                'scope_statistics': program.get('scope_statistics', {}),
                'response_stats': {
                    'response_efficiency_percentage': program.get('response_efficiency_percentage'),
                    'average_time_to_first_program_response': program.get('average_time_to_first_program_response'),
                    'average_time_to_bounty_awarded': program.get('average_time_to_bounty_awarded'),
                    'average_time_to_report_resolved': program.get('average_time_to_report_resolved')
                },
                'user_stats': {
                    'number_of_reports_for_user': program.get('number_of_reports_for_user', 0),
                    'bounty_earned_for_user': program.get('bounty_earned_for_user', 0)
                },
                'priority_score': program['priority_score']
            }
            
            # Add in-scope assets if available
            if 'targets' in program and 'in_scope' in program['targets']:
                in_scope = program['targets']['in_scope']
                if isinstance(in_scope, list) and len(in_scope) > 0:
                    # Limit to first 20 assets to keep file size manageable
                    cleaned_program['in_scope_assets'] = in_scope[:20]
            
            bounty_programs.append(cleaned_program)
    
    # Sort by priority score
    bounty_programs.sort(key=lambda x: x['priority_score'], reverse=True)
    
    logger.info(f"Found {len(bounty_programs)} programs offering bounties")
    
    # Create output structure
    output = {
        'metadata': {
            'total_programs': len(bounty_programs),
            'generated_date': datetime.now().isoformat(),
            'data_sources': [
                'hackerone_data.json',
                'hacker_api_programs_20250817_193331.json'
            ],
            'description': 'Comprehensive HackerOne programs data for Grok4 target selection analysis'
        },
        'statistics': {
            'total_bounty_programs': len(bounty_programs),
            'open_submission': sum(1 for p in bounty_programs if p['submission_state'] == 'open'),
            'managed_programs': sum(1 for p in bounty_programs if p['managed_program']),
            'fast_payment_programs': sum(1 for p in bounty_programs if p['fast_payments']),
            'open_scope_programs': sum(1 for p in bounty_programs if p['open_scope']),
            'programs_with_scope_data': sum(1 for p in bounty_programs if p['scope_statistics'].get('total_in_scope', 0) > 0)
        },
        'programs': bounty_programs
    }
    
    # Write to JSON file
    output_file = '/home/kali/bbhk/hacks/HACKERONE_PROGRAMS_FOR_GROK4.json'
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    logger.info(f"✅ Created {output_file}")
    
    # Create summary markdown
    create_summary_markdown(bounty_programs, output['statistics'])
    
    return output

def create_summary_markdown(programs: List[Dict], stats: Dict):
    """Create a markdown summary of the data"""
    summary = []
    summary.append("# HackerOne Programs Summary for Grok4 Analysis\n")
    summary.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    summary.append(f"**Total Programs**: {len(programs)}\n")
    
    # Overall statistics
    summary.append("\n## Overall Statistics\n")
    for key, value in stats.items():
        summary.append(f"- **{key.replace('_', ' ').title()}**: {value}\n")
    
    # Top 20 by priority score
    summary.append("\n## Top 20 Programs by Priority Score\n")
    for i, prog in enumerate(programs[:20], 1):
        scope_count = prog['scope_statistics'].get('total_in_scope', 0)
        summary.append(f"{i}. **{prog['name']}** ({prog['handle']}) - Score: {prog['priority_score']}\n")
        summary.append(f"   - Scope: {scope_count} assets")
        if prog['fast_payments']:
            summary.append(" 💰")
        if prog['open_scope']:
            summary.append(" 🌐")
        summary.append("\n")
    
    # Programs with largest scope
    summary.append("\n## Top 20 Programs by Scope Size\n")
    sorted_by_scope = sorted(programs, 
                           key=lambda x: x['scope_statistics'].get('total_in_scope', 0), 
                           reverse=True)
    for i, prog in enumerate(sorted_by_scope[:20], 1):
        scope_count = prog['scope_statistics'].get('total_in_scope', 0)
        if scope_count > 0:
            summary.append(f"{i}. **{prog['name']}** - {scope_count} in-scope assets\n")
            asset_types = prog['scope_statistics'].get('asset_types', [])
            if asset_types:
                summary.append(f"   - Types: {', '.join(asset_types)}\n")
    
    # Fast payment programs
    summary.append("\n## Programs with Fast Payments\n")
    fast_payment = [p for p in programs if p['fast_payments']]
    for prog in fast_payment[:20]:
        summary.append(f"- **{prog['name']}** ({prog['handle']})\n")
    
    # Open scope programs
    summary.append("\n## Programs with Open Scope\n")
    open_scope = [p for p in programs if p['open_scope']]
    for prog in open_scope[:20]:
        summary.append(f"- **{prog['name']}** ({prog['handle']})\n")
    
    # Write summary file
    summary_file = '/home/kali/bbhk/hacks/HACKERONE_PROGRAMS_SUMMARY.md'
    with open(summary_file, 'w') as f:
        f.writelines(summary)
    
    logger.info(f"✅ Created {summary_file}")

if __name__ == "__main__":
    dataset = create_grok4_dataset()
    if dataset:
        print(f"\n✅ Successfully generated HackerOne data for Grok4 analysis")
        print(f"📊 Total programs: {dataset['metadata']['total_programs']}")
        print(f"📁 Files created:")
        print(f"   - HACKERONE_PROGRAMS_FOR_GROK4.json")
        print(f"   - HACKERONE_PROGRAMS_SUMMARY.md")