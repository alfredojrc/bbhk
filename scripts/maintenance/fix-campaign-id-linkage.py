#!/usr/bin/env python3
"""
CRITICAL FIX: Add campaign_id to ALL tables and link all data to campaigns
Every piece of data MUST be linked to a campaign ID for proper organization
"""

import sqlite3
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any

# Configuration
DB_PATH = "/home/kali/bbhk/core/database/bbhk.db"

def check_current_schema():
    """Check current database schema for campaign_id columns"""
    print("🔍 CHECKING CURRENT SCHEMA FOR CAMPAIGN_ID LINKAGE")
    print("=" * 60)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get all table names
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = [row[0] for row in cursor.fetchall()]
    
    missing_campaign_id = []
    has_campaign_id = []
    
    for table in tables:
        cursor.execute(f"PRAGMA table_info({table})")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'campaign_id' in columns:
            has_campaign_id.append(table)
            print(f"   ✅ {table} - HAS campaign_id")
        else:
            missing_campaign_id.append(table)
            print(f"   ❌ {table} - MISSING campaign_id")
    
    conn.close()
    
    print(f"\n📊 SCHEMA ANALYSIS:")
    print(f"   Tables WITH campaign_id: {len(has_campaign_id)}")
    print(f"   Tables MISSING campaign_id: {len(missing_campaign_id)}")
    
    return has_campaign_id, missing_campaign_id

def add_campaign_id_to_tables(missing_tables: List[str]):
    """Add campaign_id column to all tables that need it"""
    print(f"\n🔧 ADDING CAMPAIGN_ID TO {len(missing_tables)} TABLES")
    print("=" * 60)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Tables that should NOT have campaign_id (system/meta tables)
    system_tables = {
        'platforms', 'sqlite_sequence', 'campaign_search_index',
        'campaign_search_index_data', 'campaign_search_index_idx',
        'campaign_search_index_docsize', 'campaign_search_index_config'
    }
    
    for table in missing_tables:
        if table in system_tables:
            print(f"   ⏭️  Skipping system table: {table}")
            continue
            
        try:
            # Add campaign_id column with default value
            print(f"   🔨 Adding campaign_id to {table}...")
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN campaign_id INTEGER")
            
            # Create index for performance
            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_campaign_id ON {table}(campaign_id)")
            
            print(f"   ✅ {table} - campaign_id added with index")
            
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print(f"   ✅ {table} - campaign_id already exists")
            else:
                print(f"   ❌ {table} - Error: {e}")
    
    conn.commit()
    conn.close()

def create_default_campaign():
    """Create a default campaign for existing data"""
    print(f"\n📝 CREATING DEFAULT CAMPAIGN FOR EXISTING DATA")
    print("=" * 60)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if campaigns table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='campaigns'")
    if not cursor.fetchone():
        print("   ❌ Campaigns table doesn't exist! Need to run migration first.")
        conn.close()
        return None
    
    # Create default campaign
    default_campaign_data = {
        'campaign_id': 'default-legacy-campaign',
        'campaign_name': 'Legacy Data Campaign',
        'campaign_type': 'bug_bounty',
        'description': 'Default campaign for all existing BBHK data imported before campaign system',
        'status': 'active',
        'lifecycle_stage': 'active',
        'planned_start_date': '2025-01-01 00:00:00',
        'actual_start_date': '2025-01-01 00:00:00',
        'auto_archive_enabled': 0,  # Don't auto-archive legacy data
        'priority': 3,
        'tags': json.dumps(['legacy', 'imported', 'default']),
        'external_references': json.dumps({'source': 'legacy_bbhk_data'}),
        'created_by': 'system_migration',
        'last_modified_by': 'system_migration'
    }
    
    try:
        cursor.execute("""
            INSERT OR IGNORE INTO campaigns (
                campaign_id, campaign_name, campaign_type, description,
                status, lifecycle_stage, planned_start_date, actual_start_date,
                auto_archive_enabled, priority, tags, external_references,
                created_by, last_modified_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            default_campaign_data['campaign_id'],
            default_campaign_data['campaign_name'],
            default_campaign_data['campaign_type'],
            default_campaign_data['description'],
            default_campaign_data['status'],
            default_campaign_data['lifecycle_stage'],
            default_campaign_data['planned_start_date'],
            default_campaign_data['actual_start_date'],
            default_campaign_data['auto_archive_enabled'],
            default_campaign_data['priority'],
            default_campaign_data['tags'],
            default_campaign_data['external_references'],
            default_campaign_data['created_by'],
            default_campaign_data['last_modified_by']
        ))
        
        # Get the created campaign ID
        cursor.execute("SELECT id FROM campaigns WHERE campaign_id = ?", (default_campaign_data['campaign_id'],))
        campaign_pk = cursor.fetchone()[0]
        
        conn.commit()
        print(f"   ✅ Default campaign created with ID: {campaign_pk}")
        return campaign_pk
        
    except Exception as e:
        print(f"   ❌ Error creating default campaign: {e}")
        conn.rollback()
        return None
    finally:
        conn.close()

def link_existing_data_to_campaign(campaign_pk: int):
    """Link all existing data to the default campaign"""
    print(f"\n🔗 LINKING ALL EXISTING DATA TO CAMPAIGN {campaign_pk}")
    print("=" * 60)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get all tables with campaign_id column
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    tables = [row[0] for row in cursor.fetchall()]
    
    updated_tables = []
    
    for table in tables:
        if table == 'campaigns':  # Skip campaigns table itself
            continue
            
        # Check if table has campaign_id column
        cursor.execute(f"PRAGMA table_info({table})")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'campaign_id' not in columns:
            continue
        
        try:
            # Update all NULL campaign_id values to default campaign
            cursor.execute(f"UPDATE {table} SET campaign_id = ? WHERE campaign_id IS NULL", (campaign_pk,))
            rows_updated = cursor.rowcount
            
            if rows_updated > 0:
                updated_tables.append((table, rows_updated))
                print(f"   ✅ {table} - {rows_updated} rows linked to campaign")
            else:
                print(f"   ⏭️  {table} - no rows to update")
                
        except Exception as e:
            print(f"   ❌ {table} - Error: {e}")
    
    conn.commit()
    conn.close()
    
    print(f"\n📊 LINKAGE SUMMARY:")
    total_rows = sum(count for _, count in updated_tables)
    print(f"   Tables updated: {len(updated_tables)}")
    print(f"   Total rows linked: {total_rows}")
    
    return updated_tables

def create_campaign_based_programs():
    """Create individual campaigns for major programs"""
    print(f"\n🎯 CREATING INDIVIDUAL CAMPAIGNS FOR MAJOR PROGRAMS")
    print("=" * 60)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get programs with significant data
    cursor.execute("""
        SELECT p.id, p.program_name, p.program_url, pd.handle,
               COUNT(ps.id) as scope_count,
               pb.maximum_bounty, pb.offers_bounties
        FROM programs p
        LEFT JOIN program_details pd ON p.id = pd.program_id
        LEFT JOIN program_scope ps ON p.id = ps.program_id
        LEFT JOIN program_bounties pb ON p.id = pb.program_id
        WHERE p.program_name IS NOT NULL
        GROUP BY p.id
        HAVING scope_count > 5 OR pb.maximum_bounty > 1000
        ORDER BY scope_count DESC, pb.maximum_bounty DESC
        LIMIT 20
    """)
    
    major_programs = cursor.fetchall()
    
    created_campaigns = []
    
    for program in major_programs:
        program_id, name, url, handle, scope_count, max_bounty, offers_bounties = program
        
        # Generate campaign ID from program name
        campaign_id_hash = hashlib.md5(f"{name}_{handle}".encode()).hexdigest()[:8]
        campaign_id = f"campaign-{handle or campaign_id_hash}"
        
        # Create campaign for this program
        campaign_data = {
            'campaign_id': campaign_id,
            'campaign_name': f"{name} Bug Bounty Campaign",
            'campaign_type': 'bug_bounty' if offers_bounties else 'vdp',
            'description': f"Dedicated campaign for {name} program with {scope_count} targets",
            'status': 'active',
            'lifecycle_stage': 'active',
            'planned_start_date': '2025-01-01 00:00:00',
            'actual_start_date': '2025-01-01 00:00:00',
            'auto_archive_enabled': 1,
            'priority': 2 if max_bounty and max_bounty > 5000 else 3,
            'tags': json.dumps(['high_value' if max_bounty and max_bounty > 5000 else 'standard', 'imported']),
            'external_references': json.dumps({
                'program_url': url,
                'handle': handle,
                'max_bounty': max_bounty,
                'scope_count': scope_count
            }),
            'created_by': 'auto_campaign_creation',
            'last_modified_by': 'auto_campaign_creation'
        }
        
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO campaigns (
                    campaign_id, campaign_name, campaign_type, description,
                    status, lifecycle_stage, planned_start_date, actual_start_date,
                    auto_archive_enabled, priority, tags, external_references,
                    created_by, last_modified_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                campaign_data['campaign_id'],
                campaign_data['campaign_name'],
                campaign_data['campaign_type'],
                campaign_data['description'],
                campaign_data['status'],
                campaign_data['lifecycle_stage'],
                campaign_data['planned_start_date'],
                campaign_data['actual_start_date'],
                campaign_data['auto_archive_enabled'],
                campaign_data['priority'],
                campaign_data['tags'],
                campaign_data['external_references'],
                campaign_data['created_by'],
                campaign_data['last_modified_by']
            ))
            
            # Get the created campaign ID
            cursor.execute("SELECT id FROM campaigns WHERE campaign_id = ?", (campaign_data['campaign_id'],))
            campaign_pk = cursor.fetchone()[0]
            
            # Link program and all related data to this campaign
            cursor.execute("UPDATE programs SET campaign_id = ? WHERE id = ?", (campaign_pk, program_id))
            cursor.execute("UPDATE program_details SET campaign_id = ? WHERE program_id = ?", (campaign_pk, program_id))
            cursor.execute("UPDATE program_scope SET campaign_id = ? WHERE program_id = ?", (campaign_pk, program_id))
            cursor.execute("UPDATE program_bounties SET campaign_id = ? WHERE program_id = ?", (campaign_pk, program_id))
            
            created_campaigns.append((campaign_id, name, campaign_pk))
            print(f"   ✅ Created campaign for {name} (ID: {campaign_pk})")
            
        except Exception as e:
            print(f"   ❌ Error creating campaign for {name}: {e}")
    
    conn.commit()
    conn.close()
    
    print(f"\n📊 CAMPAIGN CREATION SUMMARY:")
    print(f"   Individual campaigns created: {len(created_campaigns)}")
    
    return created_campaigns

def verify_campaign_linkage():
    """Verify all data is properly linked to campaigns"""
    print(f"\n✅ VERIFYING CAMPAIGN LINKAGE")
    print("=" * 60)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check campaigns
    cursor.execute("SELECT COUNT(*) FROM campaigns")
    campaign_count = cursor.fetchone()[0]
    print(f"   Total campaigns: {campaign_count}")
    
    # Check data linkage
    verification_results = {}
    
    data_tables = ['programs', 'program_details', 'program_scope', 'program_bounties']
    
    for table in data_tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        total_rows = cursor.fetchone()[0]
        
        cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE campaign_id IS NOT NULL")
        linked_rows = cursor.fetchone()[0]
        
        cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE campaign_id IS NULL")
        unlinked_rows = cursor.fetchone()[0]
        
        verification_results[table] = {
            'total': total_rows,
            'linked': linked_rows,
            'unlinked': unlinked_rows,
            'percentage': (linked_rows / total_rows * 100) if total_rows > 0 else 0
        }
        
        status = "✅" if unlinked_rows == 0 else "⚠️"
        print(f"   {status} {table}: {linked_rows}/{total_rows} linked ({verification_results[table]['percentage']:.1f}%)")
    
    conn.close()
    
    # Overall status
    total_linked = sum(r['linked'] for r in verification_results.values())
    total_rows = sum(r['total'] for r in verification_results.values())
    overall_percentage = (total_linked / total_rows * 100) if total_rows > 0 else 0
    
    print(f"\n📊 OVERALL LINKAGE STATUS:")
    print(f"   Total data rows: {total_rows}")
    print(f"   Linked to campaigns: {total_linked}")
    print(f"   Overall coverage: {overall_percentage:.1f}%")
    
    if overall_percentage == 100:
        print(f"   🎉 ALL DATA SUCCESSFULLY LINKED TO CAMPAIGNS!")
    else:
        print(f"   ⚠️  Some data still unlinked - may need manual review")
    
    return verification_results

def main():
    print("=" * 80)
    print("CRITICAL CAMPAIGN_ID LINKAGE FIX")
    print("ENSURING ALL DATA IS LINKED TO CAMPAIGN IDs")
    print("=" * 80)
    
    # Step 1: Check current schema
    has_campaign_id, missing_campaign_id = check_current_schema()
    
    # Step 2: Add campaign_id to missing tables
    if missing_campaign_id:
        add_campaign_id_to_tables(missing_campaign_id)
    
    # Step 3: Create default campaign
    default_campaign_pk = create_default_campaign()
    
    if default_campaign_pk:
        # Step 4: Link existing data to default campaign
        link_existing_data_to_campaign(default_campaign_pk)
        
        # Step 5: Create individual campaigns for major programs
        created_campaigns = create_campaign_based_programs()
        
        # Step 6: Verify all linkage
        verification_results = verify_campaign_linkage()
    
    print("\n" + "=" * 80)
    print("✅ CAMPAIGN_ID LINKAGE FIX COMPLETE")
    print("🎯 ALL DATA NOW ORGANIZED BY CAMPAIGN ID")
    print("=" * 80)

if __name__ == "__main__":
    main()