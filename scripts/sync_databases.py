#!/usr/bin/env python3
"""
Database Synchronization for Hybrid SQLite-Qdrant Architecture
Ensures data consistency between both storage systems
"""

import sqlite3
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import hashlib
import numpy as np
from pathlib import Path

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams, PointStruct
    from sentence_transformers import SentenceTransformer
    QDRANT_AVAILABLE = True
except ImportError:
    QDRANT_AVAILABLE = False
    print("⚠️ Qdrant client not available. Install with: pip install qdrant-client sentence-transformers")

class DatabaseSynchronizer:
    def __init__(self):
        self.sqlite_path = "/home/kali/bbhk/.swarm/memory.db"
        self.qdrant_host = "localhost"
        self.qdrant_port = 6333
        
        # Initialize connections
        self.sqlite_conn = sqlite3.connect(self.sqlite_path)
        self.sqlite_conn.row_factory = sqlite3.Row
        
        if QDRANT_AVAILABLE:
            self.qdrant = QdrantClient(host=self.qdrant_host, port=self.qdrant_port)
            self.encoder = SentenceTransformer('all-MiniLM-L6-v2')
        else:
            self.qdrant = None
            self.encoder = None
            
        # Sync tracking table
        self._create_sync_table()
        
    def _create_sync_table(self):
        """Create table to track synchronization state"""
        cursor = self.sqlite_conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sync_state (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            sqlite_hash TEXT,
            qdrant_hash TEXT,
            last_synced TIMESTAMP,
            sync_status TEXT,
            UNIQUE(entity_type, entity_id)
        )
        ''')
        self.sqlite_conn.commit()
        
    def _calculate_hash(self, data: Dict) -> str:
        """Calculate hash of data for change detection"""
        # Remove timestamps and IDs for consistent hashing
        clean_data = {k: v for k, v in data.items() 
                     if k not in ['created_at', 'updated_at', 'id']}
        data_str = json.dumps(clean_data, sort_keys=True)
        return hashlib.md5(data_str.encode()).hexdigest()
        
    def _generate_embedding(self, text: str) -> List[float]:
        """Generate embedding for text using sentence transformer"""
        if not self.encoder:
            return []
        embedding = self.encoder.encode(text)
        return embedding.tolist()
        
    async def sync_vulnerabilities_to_qdrant(self, force: bool = False):
        """Sync vulnerability patterns from SQLite to Qdrant for semantic search"""
        if not QDRANT_AVAILABLE:
            print("❌ Qdrant not available for synchronization")
            return
            
        print("🔄 Syncing vulnerabilities to Qdrant...")
        
        # Ensure collection exists
        collections = self.qdrant.get_collections().collections
        if not any(c.name == "vulnerability_patterns" for c in collections):
            self.qdrant.create_collection(
                collection_name="vulnerability_patterns",
                vectors_config=VectorParams(size=384, distance=Distance.COSINE)
            )
            
        cursor = self.sqlite_conn.cursor()
        cursor.execute('''
        SELECT id, type, severity, pattern, payout_min, payout_max, 
               effort_ratio, exploit_code, data
        FROM vulnerabilities
        ''')
        
        vulnerabilities = cursor.fetchall()
        points_to_upsert = []
        synced = 0
        
        for vuln in vulnerabilities:
            vuln_dict = dict(vuln)
            vuln_hash = self._calculate_hash(vuln_dict)
            
            # Check if needs sync
            cursor.execute('''
            SELECT sqlite_hash, qdrant_hash FROM sync_state
            WHERE entity_type = 'vulnerability' AND entity_id = ?
            ''', (str(vuln['id']),))
            
            sync_record = cursor.fetchone()
            
            if not force and sync_record and sync_record['qdrant_hash'] == vuln_hash:
                continue  # Already synced and unchanged
                
            # Generate embedding from pattern and type
            text_for_embedding = f"{vuln['type']} {vuln['pattern']} severity:{vuln['severity']}"
            embedding = self._generate_embedding(text_for_embedding)
            
            if embedding:
                point = PointStruct(
                    id=vuln['id'],
                    vector=embedding,
                    payload={
                        "type": vuln['type'],
                        "severity": vuln['severity'],
                        "pattern": vuln['pattern'],
                        "payout_min": vuln['payout_min'],
                        "payout_max": vuln['payout_max'],
                        "effort_ratio": vuln['effort_ratio'],
                        "exploit_code": vuln['exploit_code'],
                        "data": vuln['data'] if vuln['data'] else None
                    }
                )
                points_to_upsert.append(point)
                
                # Update sync state
                cursor.execute('''
                INSERT OR REPLACE INTO sync_state 
                (entity_type, entity_id, sqlite_hash, qdrant_hash, last_synced, sync_status)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', ('vulnerability', str(vuln['id']), vuln_hash, vuln_hash, 
                      datetime.now(), 'synced'))
                synced += 1
                
        if points_to_upsert:
            self.qdrant.upsert(
                collection_name="vulnerability_patterns",
                points=points_to_upsert
            )
            
        self.sqlite_conn.commit()
        print(f"✅ Synced {synced} vulnerabilities to Qdrant")
        
    async def sync_high_value_programs(self, threshold: float = 40.0):
        """Sync only high-value programs to Qdrant for semantic search"""
        if not QDRANT_AVAILABLE:
            print("❌ Qdrant not available for synchronization")
            return
            
        print(f"🔄 Syncing programs with priority > {threshold} to Qdrant...")
        
        # Ensure collection exists
        collections = self.qdrant.get_collections().collections
        if not any(c.name == "high_value_programs" for c in collections):
            self.qdrant.create_collection(
                collection_name="high_value_programs",
                vectors_config=VectorParams(size=384, distance=Distance.COSINE)
            )
            
        cursor = self.sqlite_conn.cursor()
        cursor.execute('''
        SELECT handle, name, url, max_bounty, min_bounty, response_time,
               priority_score, fast_payments, open_scope, data
        FROM programs
        WHERE priority_score > ?
        ''', (threshold,))
        
        programs = cursor.fetchall()
        points_to_upsert = []
        synced = 0
        
        for prog in programs:
            prog_dict = dict(prog)
            prog_hash = self._calculate_hash(prog_dict)
            
            # Generate embedding from name and data
            prog_data = json.loads(prog['data']) if prog['data'] else {}
            policy = prog_data.get('policy', '')
            text_for_embedding = f"{prog['name']} {policy}"
            embedding = self._generate_embedding(text_for_embedding)
            
            if embedding:
                point = PointStruct(
                    id=abs(hash(prog['handle'])) % (10 ** 8),  # Convert handle to numeric ID
                    vector=embedding,
                    payload={
                        "handle": prog['handle'],
                        "name": prog['name'],
                        "url": prog['url'],
                        "max_bounty": prog['max_bounty'],
                        "priority_score": prog['priority_score'],
                        "fast_payments": prog['fast_payments'],
                        "open_scope": prog['open_scope']
                    }
                )
                points_to_upsert.append(point)
                synced += 1
                
        if points_to_upsert:
            self.qdrant.upsert(
                collection_name="high_value_programs",
                points=points_to_upsert
            )
            
        print(f"✅ Synced {synced} high-value programs to Qdrant")
        
    async def check_sync_health(self) -> Dict[str, Any]:
        """Check synchronization health and report issues"""
        cursor = self.sqlite_conn.cursor()
        
        # Count entities in SQLite
        cursor.execute("SELECT COUNT(*) as count FROM programs")
        sqlite_programs = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM vulnerabilities")
        sqlite_vulns = cursor.fetchone()['count']
        
        # Count entities in Qdrant
        qdrant_vulns = 0
        qdrant_programs = 0
        
        if QDRANT_AVAILABLE and self.qdrant:
            try:
                vuln_info = self.qdrant.get_collection("vulnerability_patterns")
                qdrant_vulns = vuln_info.points_count
            except:
                pass
                
            try:
                prog_info = self.qdrant.get_collection("high_value_programs")
                qdrant_programs = prog_info.points_count
            except:
                pass
                
        # Check sync state
        cursor.execute('''
        SELECT 
            COUNT(CASE WHEN sync_status = 'synced' THEN 1 END) as synced,
            COUNT(CASE WHEN sync_status = 'pending' THEN 1 END) as pending,
            COUNT(CASE WHEN sync_status = 'error' THEN 1 END) as errors,
            MIN(last_synced) as oldest_sync
        FROM sync_state
        ''')
        
        sync_stats = cursor.fetchone()
        
        # Check for stale syncs (older than 24 hours)
        stale_threshold = datetime.now() - timedelta(hours=24)
        cursor.execute('''
        SELECT COUNT(*) as count FROM sync_state
        WHERE last_synced < ?
        ''', (stale_threshold,))
        stale_count = cursor.fetchone()['count']
        
        health_report = {
            "sqlite": {
                "programs": sqlite_programs,
                "vulnerabilities": sqlite_vulns
            },
            "qdrant": {
                "vulnerability_patterns": qdrant_vulns,
                "high_value_programs": qdrant_programs,
                "available": QDRANT_AVAILABLE
            },
            "sync_state": {
                "synced": sync_stats['synced'] if sync_stats else 0,
                "pending": sync_stats['pending'] if sync_stats else 0,
                "errors": sync_stats['errors'] if sync_stats else 0,
                "oldest_sync": sync_stats['oldest_sync'] if sync_stats else None,
                "stale_syncs": stale_count
            },
            "health_status": "healthy" if stale_count == 0 else "needs_sync"
        }
        
        return health_report
        
    async def incremental_sync(self):
        """Perform incremental sync based on changes"""
        print("🔄 Starting incremental synchronization...")
        
        # Sync vulnerabilities
        await self.sync_vulnerabilities_to_qdrant()
        
        # Sync high-value programs
        await self.sync_high_value_programs()
        
        # Check health
        health = await self.check_sync_health()
        
        print("\n📊 Synchronization Report:")
        print(f"SQLite Programs: {health['sqlite']['programs']}")
        print(f"SQLite Vulnerabilities: {health['sqlite']['vulnerabilities']}")
        print(f"Qdrant Vulnerability Patterns: {health['qdrant']['vulnerability_patterns']}")
        print(f"Qdrant High-Value Programs: {health['qdrant']['high_value_programs']}")
        print(f"Sync Status: {health['health_status']}")
        
        if health['sync_state']['stale_syncs'] > 0:
            print(f"⚠️ {health['sync_state']['stale_syncs']} stale syncs detected")
            
        return health
        
    async def force_full_sync(self):
        """Force complete resynchronization"""
        print("🔄 Starting FULL synchronization...")
        
        # Clear sync state
        cursor = self.sqlite_conn.cursor()
        cursor.execute("DELETE FROM sync_state")
        self.sqlite_conn.commit()
        
        # Force sync all data
        await self.sync_vulnerabilities_to_qdrant(force=True)
        await self.sync_high_value_programs(threshold=0)  # Sync all programs
        
        health = await self.check_sync_health()
        print("\n✅ Full synchronization complete!")
        return health
        
    def cleanup(self):
        """Clean up old sync records"""
        cursor = self.sqlite_conn.cursor()
        
        # Remove sync records for deleted entities
        cursor.execute('''
        DELETE FROM sync_state
        WHERE entity_type = 'vulnerability' 
        AND entity_id NOT IN (SELECT CAST(id AS TEXT) FROM vulnerabilities)
        ''')
        
        cursor.execute('''
        DELETE FROM sync_state  
        WHERE entity_type = 'program'
        AND entity_id NOT IN (SELECT handle FROM programs)
        ''')
        
        removed = cursor.rowcount
        self.sqlite_conn.commit()
        
        if removed > 0:
            print(f"🧹 Cleaned up {removed} orphaned sync records")
            
    def close(self):
        """Close database connections"""
        self.sqlite_conn.close()
        

async def main():
    """Main synchronization routine"""
    print("=" * 60)
    print("DATABASE SYNCHRONIZATION SERVICE")
    print("=" * 60)
    
    syncer = DatabaseSynchronizer()
    
    # Check if Qdrant is available
    if not QDRANT_AVAILABLE:
        print("\n❌ Qdrant is not available. Synchronization disabled.")
        print("To enable, install: pip install qdrant-client sentence-transformers")
        syncer.close()
        return
        
    # Perform incremental sync
    await syncer.incremental_sync()
    
    # Cleanup orphaned records
    syncer.cleanup()
    
    # Close connections
    syncer.close()
    
    print("\n✅ Synchronization complete!")
    

if __name__ == "__main__":
    asyncio.run(main())