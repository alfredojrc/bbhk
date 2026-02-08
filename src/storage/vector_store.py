"""
Qdrant Vector Store Integration
Handles semantic search and similarity matching for bug bounty programs
"""

import asyncio
import hashlib
import json
import os
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging
logger = logging.getLogger(__name__)

import aiohttp
import hashlib


@dataclass 
class VectorDocument:
    """Represents a document to be stored in vector database"""
    id: str
    text: str
    metadata: Dict[str, Any]
    vector: Optional[List[float]] = None
    
    def to_qdrant_point(self) -> Dict[str, Any]:
        """Convert to Qdrant point format"""
        return {
            "id": self.id,
            "vector": self.vector,
            "payload": {
                **self.metadata,
                "text": self.text,
                "indexed_at": datetime.utcnow().isoformat()
            }
        }


class QdrantVectorStore:
    """Qdrant vector database integration for semantic search"""
    
    def __init__(self, host: str = None, port: int = None,
                 collection_name: str = None):
        self.host = host or os.environ.get("QDRANT_HOST", "localhost")
        self.port = port or int(os.environ.get("QDRANT_PORT", "6333"))
        self.base_url = f"http://{self.host}:{self.port}"
        self.collection_name = collection_name or os.environ.get("QDRANT_COLLECTION", "bbhk-programs")
        self.vector_size = 384  # Standard dimension for text embeddings
        
        # We'll use a simple text-to-vector approach for now
        logger.info("Initializing vector store...")
        
        self.session = None
        
    async def initialize(self):
        """Initialize connection and create collection if needed"""
        self.session = aiohttp.ClientSession()
        
        # Check if collection exists
        try:
            async with self.session.get(f"{self.base_url}/collections/{self.collection_name}") as resp:
                if resp.status == 404:
                    await self.create_collection()
                else:
                    logger.info(f"Collection '{self.collection_name}' already exists")
        except Exception as e:
            logger.error(f"Error checking collection: {e}")
            raise
    
    async def cleanup(self):
        """Close connections"""
        if self.session:
            await self.session.close()
    
    async def create_collection(self):
        """Create Qdrant collection for programs"""
        config = {
            "vectors": {
                "size": self.vector_size,
                "distance": "Cosine"
            },
            "optimizers_config": {
                "default_segment_number": 2
            },
            "replication_factor": 1
        }
        
        try:
            async with self.session.put(
                f"{self.base_url}/collections/{self.collection_name}",
                json=config
            ) as resp:
                if resp.status in [200, 201]:
                    logger.info(f"Created collection '{self.collection_name}'")
                else:
                    error = await resp.text()
                    raise Exception(f"Failed to create collection: {error}")
        except Exception as e:
            logger.error(f"Error creating collection: {e}")
            raise
    
    def generate_embedding(self, text: str) -> List[float]:
        """Generate embedding vector for text using simple hash-based approach"""
        # Simple deterministic text-to-vector conversion
        # In production, use proper embedding models
        import random
        
        # Use hash as seed for deterministic random vectors
        seed = int(hashlib.md5(text.encode()).hexdigest()[:8], 16)
        random.seed(seed)
        
        # Generate pseudo-random vector
        vector = [random.gauss(0, 1) for _ in range(self.vector_size)]
        
        # Normalize vector
        norm = sum(x**2 for x in vector) ** 0.5
        if norm > 0:
            vector = [x / norm for x in vector]
        
        return vector
    
    def create_program_text(self, program: Dict[str, Any]) -> str:
        """Create searchable text from program data"""
        parts = []
        
        # Add program name and handle
        parts.append(f"Program: {program.get('name', '')} ({program.get('handle', '')})")
        
        # Add platform
        parts.append(f"Platform: {program.get('platform', '')}")
        
        # Add bounty information
        if program.get('max_bounty'):
            parts.append(f"Max Bounty: ${program['max_bounty']}")
        
        # Add scope information
        if program.get('scope'):
            domains = []
            for asset in program['scope']:
                if asset.get('asset_type') in ['domain', 'url']:
                    domains.append(asset.get('asset_identifier', ''))
            if domains:
                parts.append(f"Domains: {', '.join(domains[:10])}")  # Limit to first 10
        
        # Add policy snippet if available
        if program.get('policy'):
            policy_snippet = program['policy'][:500] if len(program['policy']) > 500 else program['policy']
            parts.append(f"Policy: {policy_snippet}")
        
        # Add vulnerability preferences if known
        if program.get('priority_vulnerabilities'):
            parts.append(f"Focus Areas: {', '.join(program['priority_vulnerabilities'])}")
        
        return ' | '.join(parts)
    
    async def index_program(self, program: Dict[str, Any]) -> bool:
        """
        Index a bug bounty program in Qdrant
        
        Args:
            program: Program data dictionary
            
        Returns:
            Success status
        """
        try:
            # Generate unique ID (Qdrant requires integer or UUID)
            program_id = f"{program.get('platform', 'unknown')}_{program.get('handle', 'unknown')}"
            # Convert to integer ID using hash
            doc_id = abs(hash(program_id)) % (10 ** 12)  # 12-digit integer
            
            # Create searchable text
            text = self.create_program_text(program)
            
            # Generate embedding
            vector = self.generate_embedding(text)
            
            # Create document
            doc = VectorDocument(
                id=doc_id,
                text=text,
                metadata={
                    'platform': program.get('platform', ''),
                    'handle': program.get('handle', ''),
                    'name': program.get('name', ''),
                    'max_bounty': program.get('max_bounty', 0),
                    'managed': program.get('managed', False),
                    'customer_id': program.get('customer_id', ''),
                    'scope_count': len(program.get('scope', [])),
                    'response_efficiency': program.get('response_efficiency_percentage', 0)
                },
                vector=vector
            )
            
            # Upload to Qdrant
            points = [doc.to_qdrant_point()]
            
            async with self.session.put(
                f"{self.base_url}/collections/{self.collection_name}/points",
                json={"points": points}
            ) as resp:
                if resp.status in [200, 201]:
                    logger.debug(f"Indexed program: {program.get('handle')}")
                    return True
                else:
                    error = await resp.text()
                    logger.error(f"Failed to index program: {error}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error indexing program {program.get('handle')}: {e}")
            return False
    
    async def batch_index_programs(self, programs: List[Dict[str, Any]], batch_size: int = 100) -> int:
        """
        Batch index multiple programs
        
        Args:
            programs: List of program dictionaries
            batch_size: Number of programs per batch
            
        Returns:
            Number of successfully indexed programs
        """
        total_indexed = 0
        
        for i in range(0, len(programs), batch_size):
            batch = programs[i:i + batch_size]
            points = []
            
            for program in batch:
                try:
                    # Generate unique ID
                    program_id = f"{program.get('platform', 'unknown')}_{program.get('handle', 'unknown')}"
                    doc_id = hashlib.sha256(program_id.encode()).hexdigest()[:16]
                    
                    # Create searchable text
                    text = self.create_program_text(program)
                    
                    # Generate embedding
                    vector = self.generate_embedding(text)
                    
                    # Create point
                    point = {
                        "id": doc_id,
                        "vector": vector,
                        "payload": {
                            'text': text,
                            'platform': program.get('platform', ''),
                            'handle': program.get('handle', ''),
                            'name': program.get('name', ''),
                            'max_bounty': program.get('max_bounty', 0),
                            'managed': program.get('managed', False),
                            'customer_id': program.get('customer_id', ''),
                            'scope_count': len(program.get('scope', [])),
                            'indexed_at': datetime.utcnow().isoformat()
                        }
                    }
                    points.append(point)
                    
                except Exception as e:
                    logger.warning(f"Error preparing program for indexing: {e}")
                    continue
            
            # Upload batch to Qdrant
            if points:
                try:
                    async with self.session.put(
                        f"{self.base_url}/collections/{self.collection_name}/points",
                        json={"points": points}
                    ) as resp:
                        if resp.status in [200, 201]:
                            total_indexed += len(points)
                            logger.info(f"Indexed batch of {len(points)} programs")
                        else:
                            error = await resp.text()
                            logger.error(f"Failed to index batch: {error}")
                except Exception as e:
                    logger.error(f"Error uploading batch: {e}")
        
        return total_indexed
    
    async def search_similar_programs(self, query: str, limit: int = 10, 
                                     filters: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """
        Search for similar programs using semantic search
        
        Args:
            query: Search query text
            limit: Maximum number of results
            filters: Optional filters (e.g., {'platform': 'hackerone'})
            
        Returns:
            List of similar programs with scores
        """
        try:
            # Generate query embedding
            query_vector = self.generate_embedding(query)

            # Get collection info to check for named vectors
            collection_info = await self.get_collection_info()
            vectors_config = collection_info.get('result', {}).get('config', {}).get('params', {}).get('vectors', {})

            search_request = {
                "limit": limit,
                "with_payload": True,
                "with_vector": False
            }

            # Check if vectors_config is a dictionary (named vectors) or not
            if isinstance(vectors_config, dict) and vectors_config.get('fast-all-minilm-l6-v2'):
                search_request["vector"] = {
                    "name": "fast-all-minilm-l6-v2",
                    "vector": query_vector
                }
            else:
                search_request["vector"] = query_vector
            
            # Add filters if provided
            if filters:
                search_request["filter"] = {
                    "must": [
                        {"key": k, "match": {"value": v}}
                        for k, v in filters.items()
                    ]
                }
            
            # Execute search
            async with self.session.post(
                f"{self.base_url}/collections/{self.collection_name}/points/search",
                json=search_request
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results = []
                    
                    for point in data.get('result', []):
                        results.append({
                            'score': point['score'],
                            'platform': point['payload'].get('platform'),
                            'handle': point['payload'].get('handle'),
                            'name': point['payload'].get('name'),
                            'max_bounty': point['payload'].get('max_bounty'),
                            'customer_id': point['payload'].get('customer_id'),
                            'text_snippet': point['payload'].get('text', '')[:200]
                        })
                    
                    logger.debug(f"Found {len(results)} similar programs for query: {query[:50]}")
                    return results
                else:
                    error = await resp.text()
                    logger.error(f"Search failed: {error}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error searching programs: {e}")
            return []
    
    async def find_duplicate_programs(self, program: Dict[str, Any], threshold: float = 0.85) -> List[Dict[str, Any]]:
        """
        Find potential duplicate programs
        
        Args:
            program: Program to check for duplicates
            threshold: Similarity threshold (0-1)
            
        Returns:
            List of potential duplicate programs
        """
        # Create search text from program
        search_text = self.create_program_text(program)
        
        # Search for similar programs
        results = await self.search_similar_programs(search_text, limit=5)
        
        # Filter by threshold
        duplicates = [r for r in results if r['score'] >= threshold]
        
        return duplicates
    
    async def get_collection_info(self) -> Dict[str, Any]:
        """Get information about the collection"""
        try:
            async with self.session.get(
                f"{self.base_url}/collections/{self.collection_name}"
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    return {}
        except Exception as e:
            logger.error(f"Error getting collection info: {e}")
            return {}