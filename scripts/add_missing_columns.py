#!/usr/bin/env python3
"""Add missing columns to existing SQLite tables"""

import sqlite3

db_path = "/home/kali/bbhk/.swarm/memory.db"
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Add missing columns to programs table
missing_columns = [
    ("last_scanned", "DATE"),
    ("submission_state", "TEXT"),
    ("state", "TEXT"),
    ("started_accepting_at", "TEXT"),
    ("number_of_reports_for_user", "INTEGER DEFAULT 0"),
    ("last_invitation_sent_at", "TEXT"),
    ("bookmarked", "BOOLEAN DEFAULT 0"),
    ("allows_bounty_splitting", "BOOLEAN DEFAULT 0"),
    ("offers_bounties", "BOOLEAN DEFAULT 1")
]

for col_name, col_type in missing_columns:
    try:
        cursor.execute(f"ALTER TABLE programs ADD COLUMN {col_name} {col_type}")
        print(f"✅ Added column: {col_name}")
    except sqlite3.OperationalError as e:
        if "duplicate column" in str(e):
            print(f"ℹ️ Column exists: {col_name}")
        else:
            print(f"❌ Error adding {col_name}: {e}")

conn.commit()
conn.close()
print("✅ Column migration complete")