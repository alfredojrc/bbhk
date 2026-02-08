#!/usr/bin/env python3
"""
Validate PostgreSQL data integrity after fetch
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
import json

DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'bbhk_db',
    'user': 'bbhk_user',
    'password': os.getenv('POSTGRES_PASSWORD', '')
}

def validate_data():
    """Validate PostgreSQL data"""
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    print("="*60)
    print("📊 PostgreSQL Data Validation")
    print("="*60)
    
    # Check programs
    cursor.execute("SELECT COUNT(*) as count FROM programs")
    programs_count = cursor.fetchone()['count']
    print(f"\n✅ Programs: {programs_count}")
    
    # Check scopes
    cursor.execute("SELECT COUNT(*) as count FROM structured_scopes")
    scopes_count = cursor.fetchone()['count']
    print(f"✅ Structured Scopes: {scopes_count}")
    
    # Top programs by scope count
    cursor.execute("""
        SELECT p.name, p.handle, COUNT(s.id) as scope_count
        FROM programs p
        LEFT JOIN structured_scopes s ON p.program_id = s.program_id
        GROUP BY p.name, p.handle
        ORDER BY scope_count DESC
        LIMIT 10
    """)
    
    print("\n📈 Top 10 Programs by Scope Count:")
    for row in cursor.fetchall():
        print(f"   {row['name']} (@{row['handle']}): {row['scope_count']} scopes")
    
    # Check bounty programs
    cursor.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN offers_bounties = true THEN 1 ELSE 0 END) as bounty_programs,
            SUM(CASE WHEN gold_standard_safe_harbor = true THEN 1 ELSE 0 END) as safe_harbor
        FROM programs
        WHERE submission_state = 'open'
    """)
    
    stats = cursor.fetchone()
    print(f"\n📊 Open Programs Stats:")
    print(f"   Total Open: {stats['total']}")
    print(f"   Offering Bounties: {stats['bounty_programs']}")
    print(f"   Gold Standard: {stats['safe_harbor']}")
    
    # Check critical assets
    cursor.execute("""
        SELECT COUNT(*) as count
        FROM structured_scopes
        WHERE max_severity = 'critical'
          AND eligible_for_bounty = true
    """)
    
    critical = cursor.fetchone()['count']
    print(f"\n🎯 Critical Assets: {critical}")
    
    conn.close()
    print("\n✅ Validation Complete!")

if __name__ == "__main__":
    validate_data()