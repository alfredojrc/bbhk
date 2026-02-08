#!/usr/bin/env python3
"""
Consolidate BBHK memory into single SQLite database
Migrate from fragmented storage to unified system
"""

import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path
import shutil

class MemoryConsolidator:
    def __init__(self):
        self.main_db = "/home/kali/bbhk/.swarm/memory.db"
        self.backup_dir = "/home/kali/bbhk/memory_backup"
        
    def backup_existing(self):
        """Backup current memory database"""
        if os.path.exists(self.main_db):
            os.makedirs(self.backup_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{self.backup_dir}/memory_backup_{timestamp}.db"
            shutil.copy2(self.main_db, backup_path)
            print(f"✅ Backed up to: {backup_path}")
            
    def create_optimized_schema(self):
        """Create optimized tables for bug bounty data"""
        conn = sqlite3.connect(self.main_db)
        cursor = conn.cursor()
        
        # Programs table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS programs (
            handle TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT,
            max_bounty INTEGER,
            min_bounty INTEGER,
            response_time REAL,
            priority_score REAL,
            fast_payments BOOLEAN,
            open_scope BOOLEAN,
            last_tested DATE,
            data JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Vulnerabilities table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            severity TEXT,
            program_handle TEXT,
            pattern TEXT,
            payout_min INTEGER,
            payout_max INTEGER,
            effort_ratio TEXT,
            exploit_code TEXT,
            data JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (program_handle) REFERENCES programs(handle)
        )
        ''')
        
        # Policies table (key-value store)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS policies (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            namespace TEXT DEFAULT 'default',
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_programs_priority ON programs(priority_score DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_programs_bounty ON programs(max_bounty DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulnerabilities_type ON vulnerabilities(type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_policies_namespace ON policies(namespace)')
        
        conn.commit()
        conn.close()
        print("✅ Created optimized schema")
        
    def import_json_programs(self):
        """Import HackerOne programs from JSON"""
        json_file = "/home/kali/bbhk/hacks/HACKERONE_PROGRAMS_FOR_GROK4.json"
        
        if not os.path.exists(json_file):
            print("⚠️ JSON file not found")
            return
            
        with open(json_file, 'r') as f:
            data = json.load(f)
            
        conn = sqlite3.connect(self.main_db)
        cursor = conn.cursor()
        
        programs = data.get('programs', [])
        imported = 0
        
        for prog in programs:
            try:
                cursor.execute('''
                INSERT OR REPLACE INTO programs 
                (handle, name, url, max_bounty, min_bounty, response_time, 
                 priority_score, fast_payments, open_scope, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    prog.get('handle'),
                    prog.get('name'),
                    prog.get('url'),
                    None,  # max_bounty - need to extract from scope
                    None,  # min_bounty
                    prog.get('response_stats', {}).get('average_time_to_first_program_response'),
                    prog.get('priority_score'),
                    prog.get('fast_payments', False),
                    prog.get('open_scope', False),
                    json.dumps(prog)
                ))
                imported += 1
            except Exception as e:
                print(f"Error importing {prog.get('handle')}: {e}")
                
        conn.commit()
        conn.close()
        print(f"✅ Imported {imported} programs")
        
    def migrate_memory_entries(self):
        """Migrate existing memory_entries to policies table"""
        conn = sqlite3.connect(self.main_db)
        cursor = conn.cursor()
        
        # Check if memory_entries exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='memory_entries'")
        if not cursor.fetchone():
            print("ℹ️ No memory_entries table to migrate")
            conn.close()
            return
            
        # Migrate key entries to policies
        cursor.execute('''
        SELECT key, value, namespace 
        FROM memory_entries 
        WHERE namespace IN ('claude_md_optimization', 'tools', 'default')
        AND key IN ('vulnerability_economics', 'braze_inc_policy', 
                   'scope_verification_process', 'expert_consensus_details',
                   'mcp_server_examples', 'crapi_guide')
        ''')
        
        entries = cursor.fetchall()
        migrated = 0
        
        for key, value, namespace in entries:
            try:
                cursor.execute('''
                INSERT OR REPLACE INTO policies (key, value, namespace)
                VALUES (?, ?, ?)
                ''', (key, value, namespace))
                migrated += 1
            except Exception as e:
                print(f"Error migrating {key}: {e}")
                
        conn.commit()
        conn.close()
        print(f"✅ Migrated {migrated} memory entries to policies")
        
    def add_vulnerability_patterns(self):
        """Add common vulnerability patterns"""
        patterns = [
            {
                'type': 'BOLA/IDOR',
                'severity': 'HIGH',
                'pattern': 'Sequential ID enumeration in API endpoints',
                'payout_min': 500,
                'payout_max': 5000,
                'effort_ratio': '1:5'
            },
            {
                'type': 'Business Logic',
                'severity': 'CRITICAL',
                'pattern': 'Race condition in payment processing',
                'payout_min': 5000,
                'payout_max': 50000,
                'effort_ratio': '1:10'
            },
            {
                'type': 'Authentication Bypass',
                'severity': 'CRITICAL',
                'pattern': 'JWT none algorithm acceptance',
                'payout_min': 10000,
                'payout_max': 25000,
                'effort_ratio': '1:8'
            },
            {
                'type': 'SSRF',
                'severity': 'HIGH',
                'pattern': 'Cloud metadata access via URL parameters',
                'payout_min': 3000,
                'payout_max': 15000,
                'effort_ratio': '1:6'
            },
            {
                'type': 'Mass Assignment',
                'severity': 'HIGH',
                'pattern': 'User role/privilege escalation via API',
                'payout_min': 2000,
                'payout_max': 10000,
                'effort_ratio': '1:4'
            }
        ]
        
        conn = sqlite3.connect(self.main_db)
        cursor = conn.cursor()
        
        for pattern in patterns:
            cursor.execute('''
            INSERT OR IGNORE INTO vulnerabilities 
            (type, severity, pattern, payout_min, payout_max, effort_ratio, data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                pattern['type'],
                pattern['severity'],
                pattern['pattern'],
                pattern['payout_min'],
                pattern['payout_max'],
                pattern['effort_ratio'],
                json.dumps(pattern)
            ))
            
        conn.commit()
        conn.close()
        print(f"✅ Added {len(patterns)} vulnerability patterns")
        
    def create_helper_views(self):
        """Create useful views for quick queries"""
        conn = sqlite3.connect(self.main_db)
        cursor = conn.cursor()
        
        # High-value programs view
        cursor.execute('''
        CREATE VIEW IF NOT EXISTS high_value_programs AS
        SELECT handle, name, priority_score, fast_payments, open_scope
        FROM programs
        WHERE priority_score > 40
        ORDER BY priority_score DESC
        ''')
        
        # Critical vulnerabilities view
        cursor.execute('''
        CREATE VIEW IF NOT EXISTS critical_vulnerabilities AS
        SELECT * FROM vulnerabilities
        WHERE severity = 'CRITICAL'
        ORDER BY payout_max DESC
        ''')
        
        # Recent policies view
        cursor.execute('''
        CREATE VIEW IF NOT EXISTS recent_policies AS
        SELECT key, namespace, updated_at
        FROM policies
        ORDER BY updated_at DESC
        LIMIT 20
        ''')
        
        conn.commit()
        conn.close()
        print("✅ Created helper views")
        
    def generate_report(self):
        """Generate consolidation report"""
        conn = sqlite3.connect(self.main_db)
        cursor = conn.cursor()
        
        # Get counts
        cursor.execute("SELECT COUNT(*) FROM programs")
        program_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        vuln_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM policies")
        policy_count = cursor.fetchone()[0]
        
        # Get database size
        cursor.execute("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()")
        db_size = cursor.fetchone()[0]
        
        conn.close()
        
        report = f"""
========================================
MEMORY CONSOLIDATION REPORT
========================================
Database: {self.main_db}
Size: {db_size / 1024 / 1024:.2f} MB

Content Summary:
- Programs: {program_count}
- Vulnerabilities: {vuln_count}
- Policies: {policy_count}

Quick Access Commands:
- sqlite3 {self.main_db}
- SELECT * FROM high_value_programs;
- SELECT * FROM critical_vulnerabilities;
- SELECT value FROM policies WHERE key='vulnerability_economics';

Memory is now consolidated and optimized!
========================================
        """
        
        print(report)
        
        # Save report
        with open("/home/kali/bbhk/MEMORY_CONSOLIDATION_REPORT.txt", "w") as f:
            f.write(report)
            
    def run(self):
        """Execute full consolidation"""
        print("🚀 Starting Memory Consolidation...")
        
        self.backup_existing()
        self.create_optimized_schema()
        self.import_json_programs()
        self.migrate_memory_entries()
        self.add_vulnerability_patterns()
        self.create_helper_views()
        self.generate_report()
        
        print("\n✅ Memory consolidation complete!")
        print("📁 Database: /home/kali/bbhk/.swarm/memory.db")
        print("📊 Use 'sqlite3' to query your consolidated data")


if __name__ == "__main__":
    consolidator = MemoryConsolidator()
    consolidator.run()