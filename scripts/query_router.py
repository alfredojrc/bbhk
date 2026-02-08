#!/usr/bin/env python3
"""
Intelligent Query Router for Hybrid SQLite-Qdrant Architecture
Routes queries to the optimal database based on query pattern and intent
"""

import re
import sqlite3
import json
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import time

try:
    from qdrant_client import QdrantClient
    from sentence_transformers import SentenceTransformer
    QDRANT_AVAILABLE = True
except ImportError:
    QDRANT_AVAILABLE = False

class QueryIntent(Enum):
    """Types of query intents"""
    EXACT_MATCH = "exact"           # SELECT WHERE field = value
    RANGE_QUERY = "range"           # WHERE value > X
    AGGREGATION = "aggregation"     # COUNT, SUM, AVG
    SEMANTIC = "semantic"           # Find similar
    HYBRID = "hybrid"              # Combination
    FULL_TEXT = "fulltext"         # Text search
    
class DataSource(Enum):
    """Available data sources"""
    SQLITE = "sqlite"
    QDRANT = "qdrant"
    BOTH = "both"

@dataclass
class QueryPlan:
    """Execution plan for a query"""
    intent: QueryIntent
    source: DataSource
    sql_query: Optional[str] = None
    vector_query: Optional[Dict] = None
    fusion_strategy: Optional[str] = None
    estimated_time_ms: float = 0
    confidence: float = 1.0

class IntelligentQueryRouter:
    def __init__(self):
        self.sqlite_path = "/home/kali/bbhk/.swarm/memory.db"
        self.sqlite_conn = sqlite3.connect(self.sqlite_path)
        self.sqlite_conn.row_factory = sqlite3.Row
        
        if QDRANT_AVAILABLE:
            self.qdrant = QdrantClient(host="localhost", port=6333)
            self.encoder = SentenceTransformer('all-MiniLM-L6-v2')
        else:
            self.qdrant = None
            self.encoder = None
            
        # Query patterns for intent detection
        self.patterns = {
            QueryIntent.EXACT_MATCH: [
                r"WHERE\s+\w+\s*=\s*",
                r"SELECT.*FROM.*WHERE.*=",
                r"find\s+program\s+(\w+)",
                r"get\s+(\w+)\s+by\s+handle"
            ],
            QueryIntent.RANGE_QUERY: [
                r"WHERE.*[<>]=?",
                r"bounty\s*>\s*\d+",
                r"priority.*greater",
                r"last.*days"
            ],
            QueryIntent.AGGREGATION: [
                r"COUNT\s*\(",
                r"SUM\s*\(",
                r"AVG\s*\(",
                r"GROUP\s+BY",
                r"how\s+many",
                r"total\s+bounty"
            ],
            QueryIntent.SEMANTIC: [
                r"similar\s+to",
                r"like\s+this",
                r"find\s+patterns",
                r"related\s+vulnerabilities",
                r"semantic\s+search"
            ],
            QueryIntent.FULL_TEXT: [
                r"contains",
                r"search\s+for",
                r"mentions",
                r"includes\s+text"
            ]
        }
        
    def detect_intent(self, query: str) -> QueryIntent:
        """Detect the intent of a query"""
        query_lower = query.lower()
        
        # Check each pattern type
        for intent, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, query_lower):
                    return intent
                    
        # Default to exact match for simple queries
        return QueryIntent.EXACT_MATCH
        
    def analyze_query(self, query: str) -> QueryPlan:
        """Analyze query and create execution plan"""
        intent = self.detect_intent(query)
        
        # Determine optimal data source
        if intent == QueryIntent.SEMANTIC:
            if not QDRANT_AVAILABLE:
                # Fallback to SQLite with LIKE
                return QueryPlan(
                    intent=QueryIntent.FULL_TEXT,
                    source=DataSource.SQLITE,
                    sql_query=self._convert_to_sql_like(query),
                    estimated_time_ms=5,
                    confidence=0.6
                )
            return QueryPlan(
                intent=intent,
                source=DataSource.QDRANT,
                vector_query=self._prepare_vector_query(query),
                estimated_time_ms=30,
                confidence=0.9
            )
            
        elif intent in [QueryIntent.EXACT_MATCH, QueryIntent.RANGE_QUERY, QueryIntent.AGGREGATION]:
            return QueryPlan(
                intent=intent,
                source=DataSource.SQLITE,
                sql_query=self._optimize_sql_query(query),
                estimated_time_ms=2,
                confidence=0.95
            )
            
        elif intent == QueryIntent.FULL_TEXT:
            # Check if we need semantic enhancement
            if self._needs_semantic_enhancement(query):
                return QueryPlan(
                    intent=QueryIntent.HYBRID,
                    source=DataSource.BOTH,
                    sql_query=self._prepare_sql_component(query),
                    vector_query=self._prepare_vector_query(query),
                    fusion_strategy="reciprocal_rank",
                    estimated_time_ms=35,
                    confidence=0.85
                )
            else:
                return QueryPlan(
                    intent=intent,
                    source=DataSource.SQLITE,
                    sql_query=self._convert_to_sql_like(query),
                    estimated_time_ms=5,
                    confidence=0.8
                )
                
        # Default hybrid for complex queries
        return QueryPlan(
            intent=QueryIntent.HYBRID,
            source=DataSource.BOTH,
            sql_query=self._prepare_sql_component(query),
            vector_query=self._prepare_vector_query(query) if QDRANT_AVAILABLE else None,
            fusion_strategy="weighted",
            estimated_time_ms=40,
            confidence=0.75
        )
        
    def _optimize_sql_query(self, query: str) -> str:
        """Optimize SQL query for performance"""
        # Add index hints if beneficial
        if "programs" in query and "priority_score" in query:
            query = query.replace("FROM programs", 
                                "FROM programs INDEXED BY idx_programs_priority")
                                
        # Limit results if not specified
        if "LIMIT" not in query.upper():
            query += " LIMIT 100"
            
        return query
        
    def _convert_to_sql_like(self, query: str) -> str:
        """Convert natural language to SQL LIKE query"""
        # Extract search terms
        terms = re.findall(r'\b\w+\b', query.lower())
        
        # Remove common words
        stop_words = {'find', 'get', 'show', 'list', 'the', 'with', 'for', 'and', 'or'}
        terms = [t for t in terms if t not in stop_words]
        
        # Build LIKE query
        conditions = []
        for term in terms[:3]:  # Limit to 3 terms
            conditions.append(f"(name LIKE '%{term}%' OR data LIKE '%{term}%')")
            
        if conditions:
            where_clause = " OR ".join(conditions)
            return f"SELECT * FROM programs WHERE {where_clause} LIMIT 20"
        else:
            return "SELECT * FROM programs LIMIT 20"
            
    def _prepare_vector_query(self, query: str) -> Dict:
        """Prepare vector search query"""
        if not self.encoder:
            return {}
            
        # Generate embedding
        embedding = self.encoder.encode(query).tolist()
        
        return {
            "vector": embedding,
            "limit": 10,
            "with_payload": True,
            "score_threshold": 0.7
        }
        
    def _prepare_sql_component(self, query: str) -> str:
        """Prepare SQL component for hybrid search"""
        # Simple keyword extraction
        keywords = re.findall(r'\b\w{4,}\b', query.lower())
        
        conditions = []
        for keyword in keywords[:2]:
            conditions.append(f"name LIKE '%{keyword}%'")
            
        if conditions:
            return f"SELECT handle, name, priority_score FROM programs WHERE {' OR '.join(conditions)}"
        return "SELECT handle, name, priority_score FROM programs LIMIT 10"
        
    def _needs_semantic_enhancement(self, query: str) -> bool:
        """Determine if query would benefit from semantic search"""
        semantic_indicators = [
            'similar', 'related', 'like', 'pattern',
            'vulnerability', 'exploit', 'technique'
        ]
        
        query_lower = query.lower()
        return any(indicator in query_lower for indicator in semantic_indicators)
        
    def execute_plan(self, plan: QueryPlan) -> Dict[str, Any]:
        """Execute the query plan and return results"""
        start_time = time.time()
        results = {"source": plan.source.value, "data": [], "metadata": {}}
        
        try:
            if plan.source == DataSource.SQLITE:
                results["data"] = self._execute_sqlite(plan.sql_query)
                
            elif plan.source == DataSource.QDRANT:
                results["data"] = self._execute_qdrant(plan.vector_query)
                
            elif plan.source == DataSource.BOTH:
                sql_results = self._execute_sqlite(plan.sql_query)
                vector_results = self._execute_qdrant(plan.vector_query) if QDRANT_AVAILABLE else []
                results["data"] = self._fuse_results(sql_results, vector_results, plan.fusion_strategy)
                results["metadata"]["fusion_strategy"] = plan.fusion_strategy
                
        except Exception as e:
            results["error"] = str(e)
            
        # Add execution metadata
        execution_time = (time.time() - start_time) * 1000
        results["metadata"].update({
            "intent": plan.intent.value,
            "execution_time_ms": round(execution_time, 2),
            "estimated_time_ms": plan.estimated_time_ms,
            "confidence": plan.confidence
        })
        
        return results
        
    def _execute_sqlite(self, query: str) -> List[Dict]:
        """Execute SQLite query"""
        if not query:
            return []
            
        cursor = self.sqlite_conn.cursor()
        cursor.execute(query)
        
        results = []
        for row in cursor.fetchall():
            results.append(dict(row))
            
        return results
        
    def _execute_qdrant(self, query_params: Dict) -> List[Dict]:
        """Execute Qdrant vector search"""
        if not QDRANT_AVAILABLE or not self.qdrant or not query_params:
            return []
            
        # Try vulnerability patterns first
        results = []
        try:
            search_result = self.qdrant.search(
                collection_name="vulnerability_patterns",
                query_vector=query_params["vector"],
                limit=query_params.get("limit", 10)
            )
            
            for hit in search_result:
                result = hit.payload.copy()
                result["_score"] = hit.score
                result["_source"] = "vulnerability_patterns"
                results.append(result)
        except:
            pass
            
        # Try high-value programs
        try:
            search_result = self.qdrant.search(
                collection_name="high_value_programs",
                query_vector=query_params["vector"],
                limit=query_params.get("limit", 10)
            )
            
            for hit in search_result:
                result = hit.payload.copy()
                result["_score"] = hit.score
                result["_source"] = "high_value_programs"
                results.append(result)
        except:
            pass
            
        return results
        
    def _fuse_results(self, sql_results: List[Dict], vector_results: List[Dict], 
                      strategy: str) -> List[Dict]:
        """Fuse results from multiple sources"""
        if strategy == "reciprocal_rank":
            return self._reciprocal_rank_fusion(sql_results, vector_results)
        elif strategy == "weighted":
            return self._weighted_fusion(sql_results, vector_results, sql_weight=0.6)
        else:
            # Simple concatenation with deduplication
            seen = set()
            fused = []
            
            for result in sql_results + vector_results:
                key = result.get('handle') or result.get('id') or str(result)
                if key not in seen:
                    seen.add(key)
                    fused.append(result)
                    
            return fused
            
    def _reciprocal_rank_fusion(self, sql_results: List[Dict], 
                                vector_results: List[Dict], k: int = 60) -> List[Dict]:
        """Reciprocal Rank Fusion for combining results"""
        scores = {}
        
        # Score SQL results
        for rank, result in enumerate(sql_results):
            key = result.get('handle') or result.get('id', f"sql_{rank}")
            scores[key] = scores.get(key, 0) + 1 / (k + rank + 1)
            
        # Score vector results
        for rank, result in enumerate(vector_results):
            key = result.get('handle') or result.get('id', f"vector_{rank}")
            scores[key] = scores.get(key, 0) + 1 / (k + rank + 1)
            
        # Combine results
        all_results = {r.get('handle', f"r_{i}"): r 
                      for i, r in enumerate(sql_results + vector_results)}
        
        # Sort by fused score
        sorted_keys = sorted(scores.keys(), key=lambda x: scores[x], reverse=True)
        
        fused = []
        for key in sorted_keys[:20]:  # Top 20 results
            if key in all_results:
                result = all_results[key].copy()
                result['_fusion_score'] = scores[key]
                fused.append(result)
                
        return fused
        
    def _weighted_fusion(self, sql_results: List[Dict], vector_results: List[Dict],
                        sql_weight: float = 0.6) -> List[Dict]:
        """Weighted fusion of results"""
        vector_weight = 1 - sql_weight
        
        # Normalize and weight SQL results
        for i, result in enumerate(sql_results):
            result['_weighted_score'] = sql_weight * (1 - i / max(len(sql_results), 1))
            
        # Normalize and weight vector results
        for i, result in enumerate(vector_results):
            base_score = result.get('_score', 1 - i / max(len(vector_results), 1))
            result['_weighted_score'] = vector_weight * base_score
            
        # Combine and sort
        all_results = sql_results + vector_results
        all_results.sort(key=lambda x: x.get('_weighted_score', 0), reverse=True)
        
        return all_results[:20]
        
    def suggest_query(self, natural_language: str) -> List[Dict]:
        """Suggest optimized queries for natural language input"""
        suggestions = []
        
        # Analyze the query
        plan = self.analyze_query(natural_language)
        
        # Primary suggestion based on intent
        suggestions.append({
            "type": "optimized",
            "query": plan.sql_query or "Semantic search recommended",
            "source": plan.source.value,
            "confidence": plan.confidence,
            "estimated_ms": plan.estimated_time_ms
        })
        
        # Alternative suggestions
        if "program" in natural_language.lower():
            suggestions.append({
                "type": "alternative",
                "query": "SELECT * FROM programs WHERE priority_score > 40 ORDER BY priority_score DESC LIMIT 10",
                "source": "sqlite",
                "description": "Top high-value programs"
            })
            
        if "vulnerability" in natural_language.lower() or "vuln" in natural_language.lower():
            suggestions.append({
                "type": "alternative", 
                "query": "SELECT * FROM vulnerabilities WHERE severity = 'CRITICAL' ORDER BY payout_max DESC",
                "source": "sqlite",
                "description": "Critical vulnerabilities by payout"
            })
            
        if any(word in natural_language.lower() for word in ['similar', 'like', 'pattern']):
            suggestions.append({
                "type": "alternative",
                "query": "Use semantic search in Qdrant",
                "source": "qdrant",
                "description": "Find similar patterns using vector similarity"
            })
            
        return suggestions
        

def benchmark_routing():
    """Benchmark query routing decisions"""
    router = IntelligentQueryRouter()
    
    test_queries = [
        "SELECT * FROM programs WHERE handle = 'security'",
        "Find programs with bounty > 50000",
        "Show me similar vulnerabilities to XSS",
        "How many programs have fast payments",
        "Search for programs mentioning blockchain",
        "Get vulnerability patterns like SSRF",
        "List all critical severity issues"
    ]
    
    print("=" * 60)
    print("QUERY ROUTING BENCHMARK")
    print("=" * 60)
    
    for query in test_queries:
        print(f"\nQuery: {query}")
        print("-" * 40)
        
        plan = router.analyze_query(query)
        print(f"Intent: {plan.intent.value}")
        print(f"Source: {plan.source.value}")
        print(f"Confidence: {plan.confidence:.0%}")
        print(f"Estimated time: {plan.estimated_time_ms}ms")
        
        if plan.sql_query:
            print(f"SQL: {plan.sql_query[:100]}...")
        if plan.vector_query:
            print(f"Vector search: Yes")
        if plan.fusion_strategy:
            print(f"Fusion: {plan.fusion_strategy}")
            

if __name__ == "__main__":
    # Run benchmark
    benchmark_routing()
    
    # Interactive mode
    print("\n" + "=" * 60)
    print("INTERACTIVE QUERY ROUTER")
    print("=" * 60)
    print("Enter queries to see routing decisions (type 'exit' to quit)")
    
    router = IntelligentQueryRouter()
    
    while True:
        query = input("\nQuery> ").strip()
        if query.lower() == 'exit':
            break
            
        if not query:
            continue
            
        # Analyze query
        plan = router.analyze_query(query)
        
        print(f"\n📊 Query Analysis:")
        print(f"  Intent: {plan.intent.value}")
        print(f"  Source: {plan.source.value}")
        print(f"  Confidence: {plan.confidence:.0%}")
        print(f"  Est. Time: {plan.estimated_time_ms}ms")
        
        # Get suggestions
        suggestions = router.suggest_query(query)
        if suggestions:
            print(f"\n💡 Suggestions:")
            for i, suggestion in enumerate(suggestions, 1):
                print(f"  {i}. [{suggestion['type']}] {suggestion.get('description', suggestion['query'][:50])}")
                
        # Execute if requested
        execute = input("\nExecute query? (y/n): ").strip().lower()
        if execute == 'y':
            results = router.execute_plan(plan)
            print(f"\n📋 Results from {results['source']}:")
            print(f"  Found: {len(results['data'])} items")
            print(f"  Time: {results['metadata']['execution_time_ms']}ms")
            
            if results['data'][:3]:
                print("\n  First 3 results:")
                for item in results['data'][:3]:
                    print(f"    - {item}")