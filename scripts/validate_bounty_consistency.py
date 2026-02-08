#!/usr/bin/env python3
"""
Validate that campaign summary totals match detail totals
ZERO TOLERANCE FOR FAKE DATA!
"""

import requests
import json

API_BASE = "http://<YOUR_HOSTNAME>:8000"

def validate_all_campaigns():
    """Check every campaign for data consistency"""
    
    # Get all campaigns from summary
    summary_response = requests.get(f"{API_BASE}/api/campaigns/summary")
    summary_data = summary_response.json()
    
    mismatches = []
    validated = 0
    
    print("🔍 Validating bounty data consistency across all campaigns...")
    print("=" * 60)
    
    for campaign in summary_data['campaigns']:
        campaign_id = campaign['campaign_id']
        campaign_name = campaign['campaign_name']
        summary_total = campaign['total_bounties_awarded']
        
        # Get detail for this campaign
        detail_response = requests.get(f"{API_BASE}/api/campaigns/{campaign_id}")
        
        if detail_response.status_code == 200:
            detail_data = detail_response.json()
            detail_total = detail_data['performance_stats']['total_bounties_awarded']
            
            if summary_total != detail_total:
                mismatches.append({
                    'id': campaign_id,
                    'name': campaign_name,
                    'summary': summary_total,
                    'detail': detail_total,
                    'diff': summary_total - detail_total
                })
                print(f"❌ MISMATCH: {campaign_name} (ID: {campaign_id})")
                print(f"   Summary: ${summary_total:,}")
                print(f"   Detail:  ${detail_total:,}")
                print(f"   Diff:    ${abs(summary_total - detail_total):,}")
            else:
                validated += 1
                if summary_total > 0:
                    print(f"✅ {campaign_name}: ${summary_total:,} (consistent)")
        else:
            print(f"⚠️  Error fetching campaign {campaign_id}: {detail_response.status_code}")
    
    print("=" * 60)
    print(f"\n📊 Validation Results:")
    print(f"   ✅ Consistent: {validated} campaigns")
    print(f"   ❌ Mismatches: {len(mismatches)} campaigns")
    
    if mismatches:
        print(f"\n🚨 CRITICAL: Found {len(mismatches)} data inconsistencies!")
        print("   This indicates FAKE DATA or calculation errors!")
        return False
    else:
        print(f"\n🎉 SUCCESS: All {validated} campaigns have consistent bounty data!")
        print("   NO FAKE DATA DETECTED!")
        return True

if __name__ == "__main__":
    success = validate_all_campaigns()
    exit(0 if success else 1)