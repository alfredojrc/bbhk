#!/usr/bin/env python3
"""
Save all 570 HackerOne programs to database
"""

import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.database_persistence import DatabasePersistence
from src.correlation.customer_engine import CustomerCorrelationEngine

def main():
    """Load and save all 570 programs"""
    
    # Load the programs from JSON
    with open('reports/all_hackerone_programs.json', 'r') as f:
        data = json.load(f)
    
    programs = data['programs']
    print(f"Loading {len(programs)} programs into database...")
    
    db = DatabasePersistence()
    correlation = CustomerCorrelationEngine()
    
    saved = 0
    for prog in programs:
        try:
            # Prepare program data
            program_data = {
                'platform': 'hackerone',
                'name': prog.get('name', prog.get('handle', '')),
                'handle': prog.get('handle', ''),
                'url': prog.get('url', ''),
                'max_bounty': prog.get('top_bounty', 0),
                'offers_bounties': prog.get('offers_bounties', False),
                'submission_state': prog.get('submission_state', 'open'),
                'managed': prog.get('managed', False),
                'allows_private_disclosure': True,
                'response_efficiency_percentage': prog.get('response_efficiency_percentage', 0)
            }
            
            # Save to database
            program_id = db.upsert_program(program_data)
            saved += 1
            
            # Create basic scope for correlation
            scope = []
            handle = prog.get('handle', '')
            if handle:
                scope.append({'asset_type': 'domain', 'asset_identifier': f'{handle}.com'})
            
            # Correlate to customer
            customer_id = correlation.correlate_program(
                platform='hackerone',
                program_handle=handle,
                program_name=prog.get('name', ''),
                scope=scope,
                max_bounty=prog.get('top_bounty', 0)
            )
            
            if saved % 50 == 0:
                print(f"Progress: {saved}/{len(programs)}")
        
        except Exception as e:
            print(f"Error saving {prog.get('handle')}: {e}")
    
    print(f"\n✅ Successfully saved {saved} programs to database!")
    
    # Save customer correlations
    for customer in correlation.export_customer_map():
        db.store_customer_correlation(customer)
    
    print(f"✅ Saved {len(correlation.customers)} customer correlations")
    
    # Get statistics
    stats = db.get_statistics()
    print(f"\nDatabase Statistics:")
    print(f"  Total programs: {stats['total_programs']}")
    print(f"  Programs with bounties: {stats['programs_with_bounties']}")
    print(f"  Customer correlations: {stats['customer_correlations']}")

if __name__ == "__main__":
    main()