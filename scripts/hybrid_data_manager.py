#!/usr/bin/env python3
"""
Hybrid Data Manager for BBHK
Unified interface for SQLite (structured) and Qdrant (vector) databases
Implements mandatory data placement rules from CLAUDE.md
"""

import sqlite3
import json
import re
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime
from pathlib import Path
from enum import Enum

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams, PointStruct
    QDRANT_AVAILABLE = True
except ImportError:
    QDRANT_AVAILABLE = False
    print("⚠️ Qdrant not installed. Vector search disabled. Install with: pip install qdrant-client")

try:
    from sentence_transformers import SentenceTransformer
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False
    print("⚠️ SentenceTransformers not installed. Embeddings disabled. Install with: pip install sentence-transformers")


class QueryType(Enum):
    """Query routing destinations"""
    SQLITE = "sqlite"
    QDRANT = "qdrant"
    HYBRID = "hybrid"
    QDRANT_WITH_SQL = "qdrant_with_sql_enrichment"


class HybridDB:
    """
    Unified interface for hybrid SQLite + Qdrant operations
    Implements mandatory data placement rules
    """
    
    def __init__(self, 
                 sqlite_path: str = "/home/kali/bbhk/.swarm/memory.db",
                 qdrant_host: str = "localhost",
                 qdrant_port: int = 6333):
        """Initialize connections to both databases"""
        
        # SQLite connection (always available)
        self.sqlite_path = sqlite_path
        self.sqlite_conn = sqlite3.connect(sqlite_path)
        self.sqlite_conn.row_factory = sqlite3.Row
        
        # Qdrant connection (optional)
        self.qdrant_client = None
        if QDRANT_AVAILABLE:
            try:
                self.qdrant_client = QdrantClient(host=qdrant_host, port=qdrant_port)
                self._ensure_qdrant_collections()
            except Exception as e:
                print(f"⚠️ Qdrant connection failed: {e}")
                print("Falling back to SQLite-only mode")
        
        # Embedding model (optional)
        self.embedder = None
        if EMBEDDINGS_AVAILABLE:
            try:
                self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
            except Exception as e:
                print(f"⚠️ Embedding model load failed: {e}")
    
    def _ensure_qdrant_collections(self):
        """Ensure required Qdrant collections exist"""
        if not self.qdrant_client:
            return
        
        collections = {
            "vulnerability_patterns": 384,  # MiniLM embedding size
            "program_descriptions": 384,
            "poc_code": 384,
            "report_texts": 384
        }
        
        existing = [c.name for c in self.qdrant_client.get_collections().collections]
        
        for name, vector_size in collections.items():
            if name not in existing:
                self.qdrant_client.create_collection(
                    collection_name=name,
                    vectors_config=VectorParams(size=vector_size, distance=Distance.COSINE)
                )
                print(f"✅ Created Qdrant collection: {name}")
    
    def route_query(self, query: str) -> QueryType:
        """
        Determine where to route the query based on mandatory rules
        """
        query_lower = query.lower()
        
        # Rule 1: Exact matches go to SQLite
        if any(op in query_lower for op in ['where', 'select', '=', 'from']):
            if not any(word in query_lower for word in ['similar', 'like this', 'resembles']):
                return QueryType.SQLITE
        
        # Rule 2: Aggregations go to SQLite
        if any(agg in query_lower for agg in ['count', 'sum', 'avg', 'group by', 'max(', 'min(']):
            return QueryType.SQLITE
        
        # Rule 3: Semantic similarity goes to Qdrant
        if any(sim in query_lower for sim in ['similar', 'like this', 'find patterns', 'resembles', 'related to']):
            return QueryType.QDRANT
        
        # Rule 4: Natural language goes to Qdrant with SQL enrichment
        if not query_lower.startswith('select') and len(query.split()) > 3:
            if not any(sql in query_lower for sql in ['insert', 'update', 'delete', 'create']):
                return QueryType.QDRANT_WITH_SQL
        
        # Rule 5: Mixed intent uses hybrid
        if 'and' in query_lower and any(word in query_lower for word in ['similar', 'high', 'low', 'bounty']):
            return QueryType.HYBRID
        
        # Default: SQLite for structured queries
        return QueryType.SQLITE
    
    def search(self, query: str, **kwargs) -> Dict[str, Any]:
        """
        Unified search interface with automatic routing
        Returns consistent dictionary format with data and metadata
        """
        import time
        start_time = time.time()
        
        query_type = self.route_query(query)
        
        # Execute appropriate search
        if query_type == QueryType.SQLITE:
            data = self.sql_search(query, **kwargs)
        elif query_type == QueryType.QDRANT:
            data = self.vector_search(query, **kwargs)
        elif query_type == QueryType.HYBRID:
            data = self.hybrid_search(query, **kwargs)
        elif query_type == QueryType.QDRANT_WITH_SQL:
            data = self.vector_search_with_enrichment(query, **kwargs)
        else:
            data = self.sql_search(query, **kwargs)
        
        # Calculate execution time
        execution_time = (time.time() - start_time) * 1000
        
        # Return consistent format
        return {
            "data": data,
            "metadata": {
                "query_type": query_type.value,
                "execution_time_ms": round(execution_time, 2),
                "result_count": len(data) if data else 0,
                "source": "hybrid_manager"
            }
        }
    
    def sql_search(self, query: str, params: Optional[Tuple] = None) -> List[Dict[str, Any]]:
        """Execute SQL query on SQLite"""
        cursor = self.sqlite_conn.cursor()
        
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            columns = [description[0] for description in cursor.description] if cursor.description else []
            results = []
            
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))
            
            return results
        except Exception as e:
            print(f"❌ SQL error: {e}")
            return []
    
    def vector_search(self, query: str, collection: str = "vulnerability_patterns", 
                     limit: int = 10, **kwargs) -> List[Dict[str, Any]]:
        """Execute vector similarity search on Qdrant"""
        if not self.qdrant_client or not self.embedder:
            print("⚠️ Vector search unavailable, falling back to SQL")
            return self.sql_fallback_search(query, limit)
        
        try:
            # Generate embedding
            embedding = self.embedder.encode(query).tolist()
            
            # Search in Qdrant
            results = self.qdrant_client.search(
                collection_name=collection,
                query_vector=embedding,
                limit=limit,
                **kwargs
            )
            
            # Format results
            formatted = []
            for hit in results:
                result = {
                    "id": hit.id,
                    "score": hit.score,
                    "payload": hit.payload or {}
                }
                formatted.append(result)
            
            return formatted
        except Exception as e:
            print(f"❌ Vector search error: {e}")
            return []
    
    def hybrid_search(self, query: str, alpha: float = 0.7, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Execute hybrid search combining SQLite and Qdrant
        alpha: weight for vector search (0.0 = pure SQL, 1.0 = pure vector)
        """
        # Extract SQL-friendly parts
        sql_query = self._extract_sql_components(query)
        
        # Get SQL results
        sql_results = []
        if sql_query and alpha < 1.0:
            sql_results = self.sql_search(sql_query)
        
        # Get vector results
        vector_results = []
        if self.qdrant_client and alpha > 0.0:
            vector_results = self.vector_search(query, limit=limit * 2)
        
        # Combine results using Reciprocal Rank Fusion (RRF)
        return self._reciprocal_rank_fusion(sql_results, vector_results, alpha, limit)
    
    def vector_search_with_enrichment(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Vector search with SQL metadata enrichment
        """
        # First, get vector results
        vector_results = self.vector_search(query, limit=limit)
        
        if not vector_results:
            return []
        
        # Extract IDs from vector results
        ids = []
        for result in vector_results:
            if 'program_handle' in result.get('payload', {}):
                ids.append(result['payload']['program_handle'])
            elif 'id' in result.get('payload', {}):
                ids.append(result['payload']['id'])
        
        if not ids:
            return vector_results
        
        # Enrich with SQL data
        placeholders = ','.join('?' * len(ids))
        sql_query = f"""
        SELECT * FROM programs 
        WHERE handle IN ({placeholders})
        """
        
        sql_data = self.sql_search(sql_query, tuple(ids))
        sql_dict = {row['handle']: row for row in sql_data}
        
        # Merge results
        for result in vector_results:
            handle = result.get('payload', {}).get('program_handle')
            if handle and handle in sql_dict:
                result['metadata'] = sql_dict[handle]
        
        return vector_results
    
    def store_program(self, program: Dict[str, Any]) -> bool:
        """
        Store program data according to placement rules
        SQLite: structured data
        Qdrant: description embeddings
        """
        # Store in SQLite (primary)
        try:
            cursor = self.sqlite_conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO programs 
            (handle, name, url, max_bounty, min_bounty, priority_score, data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                program['handle'],
                program['name'],
                program.get('url'),
                program.get('max_bounty'),
                program.get('min_bounty'),
                program.get('priority_score', 0),
                json.dumps(program)
            ))
            self.sqlite_conn.commit()
            
            # Store in Qdrant if available
            if self.qdrant_client and self.embedder and program.get('description'):
                embedding = self.embedder.encode(program['description']).tolist()
                
                self.qdrant_client.upsert(
                    collection_name="program_descriptions",
                    points=[
                        PointStruct(
                            id=hash(program['handle']) % 2**32,
                            vector=embedding,
                            payload={
                                "program_handle": program['handle'],
                                "name": program['name'],
                                "description": program['description'],
                                "max_bounty": program.get('max_bounty')
                            }
                        )
                    ]
                )
            
            return True
        except Exception as e:
            print(f"❌ Store error: {e}")
            return False
    
    def store_memory(self, key: str, value: str, namespace: str = "default") -> bool:
        """
        Store a memory entry in SQLite (following MCP pattern)
        Compatible with claude-flow memory storage
        """
        try:
            cursor = self.sqlite_conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO memory_entries 
                (key, value, namespace, created_at, updated_at, accessed_at)
                VALUES (?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'), strftime('%s', 'now'))
            """, (key, value, namespace))
            self.sqlite_conn.commit()
            return True
        except Exception as e:
            print(f"❌ Failed to store memory: {e}")
            return False
    
    def retrieve_memory(self, key: str, namespace: str = "default") -> Optional[str]:
        """
        Retrieve a memory entry from SQLite
        Compatible with claude-flow memory retrieval
        """
        try:
            cursor = self.sqlite_conn.cursor()
            cursor.execute("""
                SELECT value FROM memory_entries 
                WHERE key = ? AND namespace = ?
            """, (key, namespace))
            result = cursor.fetchone()
            return result[0] if result else None
        except Exception as e:
            print(f"❌ Failed to retrieve memory: {e}")
            return None
    
    def store_vulnerability(self, vuln: Dict[str, Any]) -> bool:
        """
        Store vulnerability according to placement rules
        SQLite: structured pattern data
        Qdrant: pattern embeddings for similarity
        """
        try:
            # Store in SQLite
            cursor = self.sqlite_conn.cursor()
            cursor.execute("""
            INSERT INTO vulnerabilities 
            (type, severity, pattern, payout_min, payout_max, data)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                vuln['type'],
                vuln.get('severity'),
                vuln.get('pattern'),
                vuln.get('payout_min'),
                vuln.get('payout_max'),
                json.dumps(vuln)
            ))
            vuln_id = cursor.lastrowid
            self.sqlite_conn.commit()
            
            # Store in Qdrant
            if self.qdrant_client and self.embedder and vuln.get('pattern'):
                embedding = self.embedder.encode(vuln['pattern']).tolist()
                
                self.qdrant_client.upsert(
                    collection_name="vulnerability_patterns",
                    points=[
                        PointStruct(
                            id=vuln_id,
                            vector=embedding,
                            payload={
                                "vuln_id": vuln_id,
                                "type": vuln['type'],
                                "severity": vuln.get('severity'),
                                "pattern": vuln['pattern']
                            }
                        )
                    ]
                )
            
            return True
        except Exception as e:
            print(f"❌ Store vulnerability error: {e}")
            return False
    
    def _extract_sql_components(self, query: str) -> Optional[str]:
        """Extract SQL-friendly components from natural language query"""
        # Look for specific patterns
        patterns = {
            r"bounty[>\s]+(\d+)": "max_bounty > {}",
            r"priority[>\s]+(\d+)": "priority_score > {}",
            r"(high|critical)\s+severity": "severity IN ('HIGH', 'CRITICAL')",
            r"program\s+(\w+)": "handle LIKE '%{}%'"
        }
        
        conditions = []
        for pattern, sql_template in patterns.items():
            match = re.search(pattern, query, re.IGNORECASE)
            if match:
                if '{}' in sql_template:
                    conditions.append(sql_template.format(match.group(1)))
                else:
                    conditions.append(sql_template)
        
        if conditions:
            return f"SELECT * FROM programs WHERE {' AND '.join(conditions)} LIMIT 20"
        return None
    
    def _reciprocal_rank_fusion(self, sql_results: List[Dict], vector_results: List[Dict],
                                alpha: float, limit: int) -> List[Dict[str, Any]]:
        """
        Combine results using Reciprocal Rank Fusion (RRF)
        """
        k = 60  # RRF constant
        scores = {}
        
        # Score SQL results
        for rank, result in enumerate(sql_results):
            key = result.get('handle') or result.get('id') or str(result)
            scores[key] = scores.get(key, 0) + (1 - alpha) / (k + rank + 1)
            if key not in scores:
                scores[key] = {"data": result, "score": 0}
            scores[key]["score"] += (1 - alpha) / (k + rank + 1)
        
        # Score vector results
        for rank, result in enumerate(vector_results):
            key = result.get('payload', {}).get('program_handle') or result.get('id') or str(result)
            if key not in scores:
                scores[key] = {"data": result, "score": 0}
            scores[key]["score"] += alpha / (k + rank + 1)
        
        # Sort by combined score
        sorted_results = sorted(scores.values(), key=lambda x: x["score"], reverse=True)
        
        # Return top results
        return [r["data"] for r in sorted_results[:limit]]
    
    def sql_fallback_search(self, query: str, limit: int) -> List[Dict[str, Any]]:
        """Fallback to SQL when vector search unavailable"""
        # Simple keyword search in SQLite
        keywords = query.lower().split()
        conditions = []
        params = []
        
        for keyword in keywords[:3]:  # Limit to first 3 keywords
            conditions.append("(name LIKE ? OR data LIKE ?)")
            params.extend([f"%{keyword}%", f"%{keyword}%"])
        
        if conditions:
            sql = f"""
            SELECT * FROM programs 
            WHERE {' OR '.join(conditions)}
            LIMIT ?
            """
            params.append(limit)
            return self.sql_search(sql, tuple(params))
        
        return []
    
    def close(self):
        """Close all connections"""
        if self.sqlite_conn:
            self.sqlite_conn.close()
        if self.qdrant_client:
            # Qdrant client doesn't need explicit close
            pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# Convenience functions
def get_hybrid_db() -> HybridDB:
    """Get configured HybridDB instance"""
    return HybridDB()


def quick_search(query: str) -> List[Dict[str, Any]]:
    """Quick search with automatic routing"""
    with HybridDB() as db:
        return db.search(query)


if __name__ == "__main__":
    # Test the hybrid database
    print("🚀 Testing Hybrid Database Manager")
    print("=" * 60)
    
    db = HybridDB()
    
    # Test query routing
    test_queries = [
        "SELECT * FROM programs WHERE handle = 'uber'",  # → SQLite
        "Find vulnerabilities similar to XSS",            # → Qdrant
        "High-bounty programs similar to Netflix",        # → Hybrid
        "What are the top paying bug bounty programs",    # → Qdrant+SQL
        "SELECT COUNT(*) FROM vulnerabilities",           # → SQLite
    ]
    
    for query in test_queries:
        route = db.route_query(query)
        print(f"Query: {query[:50]}...")
        print(f"  → Routed to: {route.value}")
        print()
    
    # Test actual search
    print("Testing SQL search:")
    results = db.sql_search("SELECT COUNT(*) as count FROM programs")
    if results:
        print(f"  Programs in database: {results[0]['count']}")
    
    print("\nTesting hybrid search:")
    results = db.search("high priority programs")
    print(f"  Found {len(results)} results")
    
    db.close()
    print("\n✅ Hybrid Database Manager ready!")