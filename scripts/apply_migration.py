#!/usr/bin/env python3
"""
Apply database migration for new HackerOne tables
"""

import os
import psycopg2
import sys

# PostgreSQL Configuration
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'bbhk_db',
    'user': 'bbhk_user',
    'password': os.getenv('POSTGRES_PASSWORD', '')
}

def apply_migration():
    """Apply the migration SQL file"""
    try:
        # Connect to database
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        print("✅ Connected to PostgreSQL")
        
        # Read migration file
        with open('migration/add_reports_bounties_earnings_tables.sql', 'r') as f:
            migration_sql = f.read()
        
        print("📝 Applying migration...")
        
        # Execute migration
        cursor.execute(migration_sql)
        conn.commit()
        
        print("✅ Migration applied successfully!")
        
        # Show created tables
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN (
                'hacker_reports', 'bounties', 'earnings', 'hacktivity', 
                'invitations', 'payment_preferences', 'balance'
            )
            ORDER BY table_name;
        """)
        
        tables = cursor.fetchall()
        print(f"\n📊 Created {len(tables)} new tables:")
        for table in tables:
            print(f"   - {table[0]}")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    apply_migration()