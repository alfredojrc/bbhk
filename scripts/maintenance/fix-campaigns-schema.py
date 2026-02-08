#!/usr/bin/env python3
"""
Fix campaigns table schema and link all data to campaign_id
"""

import sqlite3
import json
from datetime import datetime

DB_PATH = "/home/kali/bbhk/core/database/bbhk.db"

def fix_campaigns_table():
    """Fix campaigns table schema to match expected structure"""
    print("🔧 FIXING CAMPAIGNS TABLE SCHEMA")
    print("=" * 50)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check current campaigns table structure
    cursor.execute("PRAGMA table_info(campaigns)")
    current_columns = {col[1]: col[2] for col in cursor.fetchall()}
    
    print(f"   Current columns: {list(current_columns.keys())}")
    
    # Required columns for proper campaign management
    required_columns = {
        'campaign_type': 'VARCHAR(50) DEFAULT "bug_bounty"',
        'description': 'TEXT',
        'status': 'VARCHAR(20) DEFAULT "active"',
        'lifecycle_stage': 'VARCHAR(50) DEFAULT "active"',
        'planned_start_date': 'TIMESTAMP',
        'actual_start_date': 'TIMESTAMP',
        'planned_end_date': 'TIMESTAMP',
        'actual_end_date': 'TIMESTAMP',
        'auto_archive_enabled': 'BOOLEAN DEFAULT 1',
        'archive_delay_days': 'INTEGER DEFAULT 30',
        'priority': 'INTEGER DEFAULT 3',
        'tags': 'TEXT',  # JSON as TEXT for SQLite
        'external_references': 'TEXT',  # JSON as TEXT
        'created_by': 'VARCHAR(100)',
        'last_modified_by': 'VARCHAR(100)'
    }
    
    # Add missing columns
    for col_name, col_type in required_columns.items():
        if col_name not in current_columns:
            try:
                cursor.execute(f"ALTER TABLE campaigns ADD COLUMN {col_name} {col_type}")
                print(f"   ✅ Added column: {col_name}")
            except sqlite3.OperationalError as e:
                print(f"   ⚠️  Column {col_name}: {e}")
    
    conn.commit()
    conn.close()
    print("   ✅ Campaigns table schema fixed")

def create_default_campaign():
    """Create default campaign with proper schema"""
    print("\n📝 CREATING DEFAULT CAMPAIGN")
    print("=" * 50)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create default campaign
    try:
        cursor.execute("""
            INSERT OR IGNORE INTO campaigns (
                campaign_name, campaign_type, description, status, lifecycle_stage,
                planned_start_date, actual_start_date, auto_archive_enabled,
                priority, tags, external_references, created_by, last_modified_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            'Legacy Data Campaign',
            'bug_bounty',
            'Default campaign for all existing BBHK data imported before campaign system',
            'active',
            'active',
            '2025-01-01 00:00:00',
            '2025-01-01 00:00:00',
            0,  # Don't auto-archive legacy data
            3,  # Medium priority
            json.dumps(['legacy', 'imported', 'default']),
            json.dumps({'source': 'legacy_bbhk_data'}),
            'system_migration',
            'system_migration'
        ))
        
        # Get the created campaign ID
        cursor.execute("SELECT id FROM campaigns WHERE campaign_name = ?", ('Legacy Data Campaign',))
        result = cursor.fetchone()
        
        if result:
            campaign_pk = result[0]
            conn.commit()
            print(f"   ✅ Default campaign created with ID: {campaign_pk}")
            return campaign_pk
        else:
            # If already exists, get existing ID
            cursor.execute("SELECT id FROM campaigns ORDER BY id LIMIT 1")
            result = cursor.fetchone()
            if result:
                campaign_pk = result[0]
                print(f"   ✅ Using existing campaign ID: {campaign_pk}")
                return campaign_pk
                
    except Exception as e:
        print(f"   ❌ Error: {e}")
        conn.rollback()
        return None
    finally:
        conn.close()

def link_all_data_to_campaign(campaign_pk):
    """Link ALL data to the default campaign"""
    print(f"\n🔗 LINKING ALL DATA TO CAMPAIGN {campaign_pk}")
    print("=" * 50)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Tables to update (all that have campaign_id column)
    tables_to_update = [
        'programs', 'program_details', 'program_scope', 'program_bounties',
        'targets', 'findings', 'reports', 'scans', 'sessions', 'metrics',
        'disclosed_reports', 'patterns', 'variants', 'researcher_queue',
        'researcher_findings', 'rules', 'agents', 'tools'
    ]
    
    total_updated = 0
    
    for table in tables_to_update:
        try:
            # Check if table exists and has campaign_id column
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [col[1] for col in cursor.fetchall()]
            
            if 'campaign_id' not in columns:
                print(f"   ⏭️  {table} - no campaign_id column")
                continue
            
            # Update all NULL campaign_id values
            cursor.execute(f"UPDATE {table} SET campaign_id = ? WHERE campaign_id IS NULL", (campaign_pk,))
            rows_updated = cursor.rowcount
            
            if rows_updated > 0:
                total_updated += rows_updated
                print(f"   ✅ {table} - {rows_updated} rows linked")
            else:
                print(f"   ⏭️  {table} - no rows to update")
                
        except Exception as e:
            print(f"   ❌ {table} - Error: {e}")
    
    conn.commit()
    conn.close()
    
    print(f"\n📊 TOTAL ROWS LINKED TO CAMPAIGN: {total_updated}")
    return total_updated

def create_individual_campaigns():
    """Create specific campaigns for major programs"""
    print(f"\n🎯 CREATING INDIVIDUAL CAMPAIGNS FOR MAJOR PROGRAMS")
    print("=" * 50)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get top programs with most scope/activity
    cursor.execute("""
        SELECT p.id, p.program_name, COUNT(ps.id) as scope_count,
               pb.maximum_bounty, pd.handle
        FROM programs p
        LEFT JOIN program_scope ps ON p.id = ps.program_id
        LEFT JOIN program_bounties pb ON p.id = pb.program_id
        LEFT JOIN program_details pd ON p.id = pd.program_id
        WHERE p.program_name IS NOT NULL AND p.program_name != ''
        GROUP BY p.id
        HAVING scope_count > 3 OR pb.maximum_bounty > 500
        ORDER BY scope_count DESC, pb.maximum_bounty DESC
        LIMIT 15
    """)
    
    major_programs = cursor.fetchall()
    created_campaigns = []
    
    for program_id, name, scope_count, max_bounty, handle in major_programs:
        # Create individual campaign
        campaign_name = f"{name} Campaign"
        
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO campaigns (
                    campaign_name, campaign_type, description, status, lifecycle_stage,
                    planned_start_date, actual_start_date, auto_archive_enabled,
                    priority, tags, external_references, created_by, last_modified_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                campaign_name,
                'bug_bounty' if max_bounty and max_bounty > 0 else 'vdp',
                f"Dedicated campaign for {name} with {scope_count} scope targets",
                'active',
                'active',
                '2025-01-01 00:00:00',
                '2025-01-01 00:00:00',
                1,  # Enable auto-archive
                2 if max_bounty and max_bounty > 2000 else 3,
                json.dumps(['individual', 'high_value' if max_bounty and max_bounty > 2000 else 'standard']),
                json.dumps({
                    'program_id': program_id,
                    'handle': handle,
                    'max_bounty': max_bounty,
                    'scope_count': scope_count
                }),
                'auto_campaign_creation',
                'auto_campaign_creation'
            ))
            
            # Get campaign ID
            cursor.execute("SELECT id FROM campaigns WHERE campaign_name = ?", (campaign_name,))
            result = cursor.fetchone()
            
            if result:
                campaign_pk = result[0]
                
                # Link program and related data to this campaign
                cursor.execute("UPDATE programs SET campaign_id = ? WHERE id = ?", (campaign_pk, program_id))
                cursor.execute("UPDATE program_details SET campaign_id = ? WHERE program_id = ?", (campaign_pk, program_id))
                cursor.execute("UPDATE program_scope SET campaign_id = ? WHERE program_id = ?", (campaign_pk, program_id))
                cursor.execute("UPDATE program_bounties SET campaign_id = ? WHERE program_id = ?", (campaign_pk, program_id))
                
                created_campaigns.append((campaign_name, campaign_pk, scope_count))
                print(f"   ✅ {name} -> Campaign ID {campaign_pk}")
                
        except Exception as e:
            print(f"   ❌ Error creating campaign for {name}: {e}")
    
    conn.commit()
    conn.close()
    
    print(f"   📊 Created {len(created_campaigns)} individual campaigns")
    return created_campaigns

def verify_linkage():
    """Verify all data is properly linked"""
    print(f"\n✅ VERIFYING CAMPAIGN LINKAGE")
    print("=" * 50)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check campaigns
    cursor.execute("SELECT COUNT(*) FROM campaigns")
    campaign_count = cursor.fetchone()[0]
    print(f"   Total campaigns: {campaign_count}")
    
    # Check key data tables
    key_tables = ['programs', 'program_scope', 'findings', 'reports']
    
    for table in key_tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            total = cursor.fetchone()[0]
            
            cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE campaign_id IS NOT NULL")
            linked = cursor.fetchone()[0]
            
            percentage = (linked / total * 100) if total > 0 else 0
            status = "✅" if linked == total else "⚠️"
            print(f"   {status} {table}: {linked}/{total} linked ({percentage:.1f}%)")
            
        except Exception as e:
            print(f"   ❌ {table}: Error checking - {e}")
    
    conn.close()

def main():
    print("=" * 70)
    print("CAMPAIGN_ID LINKAGE FIX - PROPER IMPLEMENTATION")
    print("=" * 70)
    
    # Step 1: Fix campaigns table schema
    fix_campaigns_table()
    
    # Step 2: Create default campaign
    default_campaign_pk = create_default_campaign()
    
    if default_campaign_pk:
        # Step 3: Link all existing data
        total_linked = link_all_data_to_campaign(default_campaign_pk)
        
        # Step 4: Create individual campaigns for major programs
        individual_campaigns = create_individual_campaigns()
        
        # Step 5: Verify linkage
        verify_linkage()
        
        print(f"\n🎉 SUCCESS!")
        print(f"   Default campaign ID: {default_campaign_pk}")
        print(f"   Total rows linked: {total_linked}")
        print(f"   Individual campaigns: {len(individual_campaigns)}")
    
    print("=" * 70)
    print("✅ ALL DATA NOW ORGANIZED BY CAMPAIGN_ID!")
    print("=" * 70)

if __name__ == "__main__":
    main()