#!/usr/bin/env python3
"""
Fix Qdrant MCP Server Configuration
This script fixes the vector embedding configuration issues in Qdrant collections
"""

import requests
import json
import sys
from typing import Dict, Any

QDRANT_URL = "http://localhost:6333"
COLLECTIONS = ["bbhk_vulnerabilities", "bbhk-project", "bbhk_programs"]

def check_collection(collection_name: str) -> Dict[str, Any]:
    """Check if collection exists and get its configuration"""
    try:
        response = requests.get(f"{QDRANT_URL}/collections/{collection_name}")
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error checking collection {collection_name}: {e}")
        return None

def delete_collection(collection_name: str) -> bool:
    """Delete a collection"""
    try:
        response = requests.delete(f"{QDRANT_URL}/collections/{collection_name}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error deleting collection {collection_name}: {e}")
        return False

def create_collection(collection_name: str) -> bool:
    """Create a collection with proper vector configuration"""
    config = {
        "vectors": {
            "size": 384,
            "distance": "Cosine",
            "on_disk": False
        },
        "shard_number": 1,
        "replication_factor": 1,
        "write_consistency_factor": 1,
        "on_disk_payload": True,
        "hnsw_config": {
            "m": 16,
            "ef_construct": 100,
            "full_scan_threshold": 10000,
            "max_indexing_threads": 0,
            "on_disk": False
        },
        "optimizer_config": {
            "deleted_threshold": 0.2,
            "vacuum_min_vector_number": 1000,
            "default_segment_number": 0,
            "indexing_threshold": 10000,
            "flush_interval_sec": 5
        },
        "wal_config": {
            "wal_capacity_mb": 32,
            "wal_segments_ahead": 0
        }
    }
    
    try:
        response = requests.put(
            f"{QDRANT_URL}/collections/{collection_name}",
            json=config
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Error creating collection {collection_name}: {e}")
        return False

def insert_test_data(collection_name: str) -> bool:
    """Insert test data to verify the collection works"""
    test_point = {
        "points": [
            {
                "id": 1,
                "vector": [0.1] * 384,  # Test vector with 384 dimensions
                "payload": {
                    "type": "test",
                    "description": "Test vulnerability for MCP validation",
                    "severity": "info",
                    "timestamp": "2025-08-17T13:00:00Z"
                }
            }
        ]
    }
    
    try:
        response = requests.put(
            f"{QDRANT_URL}/collections/{collection_name}/points",
            json=test_point
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Error inserting test data: {e}")
        return False

def main():
    print("🔧 Fixing Qdrant MCP Configuration")
    print("=" * 50)
    
    # Check Qdrant health
    try:
        health = requests.get(f"{QDRANT_URL}/")
        if health.status_code != 200:
            print("❌ Qdrant is not healthy!")
            sys.exit(1)
        print("✅ Qdrant is healthy")
    except Exception as e:
        print(f"❌ Cannot connect to Qdrant: {e}")
        sys.exit(1)
    
    # Fix each collection
    for collection in COLLECTIONS:
        print(f"\n📦 Processing collection: {collection}")
        
        # Check existing configuration
        existing = check_collection(collection)
        
        if existing:
            print(f"  ⚠️  Collection exists, checking configuration...")
            result = existing.get("result", {})
            config = result.get("config", {})
            params = config.get("params", {})
            vectors = params.get("vectors", {})
            
            # Check if configuration is correct
            if vectors.get("size") == 384 and vectors.get("distance") == "Cosine":
                print(f"  ✅ Collection configuration is correct")
            else:
                print(f"  ❌ Wrong configuration detected")
                print(f"     Current: size={vectors.get('size')}, distance={vectors.get('distance')}")
                print(f"  🔄 Recreating collection...")
                
                # Delete and recreate
                if delete_collection(collection):
                    print(f"  ✅ Deleted old collection")
                    if create_collection(collection):
                        print(f"  ✅ Created new collection with correct config")
                        if insert_test_data(collection):
                            print(f"  ✅ Test data inserted successfully")
                    else:
                        print(f"  ❌ Failed to create collection")
                else:
                    print(f"  ❌ Failed to delete collection")
        else:
            print(f"  📝 Collection doesn't exist, creating...")
            if create_collection(collection):
                print(f"  ✅ Created collection")
                if insert_test_data(collection):
                    print(f"  ✅ Test data inserted successfully")
            else:
                print(f"  ❌ Failed to create collection")
    
    # Test search on main collection
    print("\n🔍 Testing search on bbhk_vulnerabilities...")
    test_search = {
        "vector": [0.1] * 384,
        "limit": 5,
        "with_payload": True
    }
    
    try:
        response = requests.post(
            f"{QDRANT_URL}/collections/bbhk_vulnerabilities/points/search",
            json=test_search
        )
        if response.status_code == 200:
            print("  ✅ Search test successful")
            results = response.json()
            print(f"  📊 Found {len(results.get('result', []))} results")
        else:
            print(f"  ❌ Search test failed: {response.status_code}")
    except Exception as e:
        print(f"  ❌ Search test error: {e}")
    
    print("\n✅ Qdrant MCP configuration fixed!")
    print("\n📋 Next steps:")
    print("  1. Restart MCP servers if running")
    print("  2. Test with: mcp__qdrant-bbhk__qdrant-store")
    print("  3. Monitor for any vector mismatch errors")

if __name__ == "__main__":
    main()