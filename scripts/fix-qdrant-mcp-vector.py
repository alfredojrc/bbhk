#!/usr/bin/env python3
"""
Fix Qdrant MCP Vector Configuration
Recreates collection with proper named vector configuration
"""

import requests
import json

QDRANT_URL = "http://localhost:6333"
COLLECTION_NAME = "bbhk_knowledge"

def recreate_collection_with_named_vectors():
    """Recreate collection with named vector support for MCP"""
    
    # Delete existing collection if it exists
    print(f"Checking if collection '{COLLECTION_NAME}' exists...")
    collections_response = requests.get(f"{QDRANT_URL}/collections")
    collections = collections_response.json()
    
    existing_collections = [c['name'] for c in collections['result']['collections']]
    
    if COLLECTION_NAME in existing_collections:
        print(f"Deleting existing collection '{COLLECTION_NAME}'...")
        requests.delete(f"{QDRANT_URL}/collections/{COLLECTION_NAME}")
    
    # Create new collection with named vector configuration
    print(f"Creating collection '{COLLECTION_NAME}' with named vectors...")
    
    config = {
        "vectors": {
            "fast-all-minilm-l6-v2": {
                "size": 384,
                "distance": "Cosine"
            }
        }
    }
    
    response = requests.put(
        f"{QDRANT_URL}/collections/{COLLECTION_NAME}",
        json=config
    )
    
    if response.status_code == 200:
        print(f"✅ Collection '{COLLECTION_NAME}' created successfully with named vector support")
        print("   Vector name: fast-all-minilm-l6-v2")
        print("   Dimensions: 384")
        print("   Distance: Cosine")
        
        # Test by adding a sample point
        test_point = {
            "points": [{
                "id": 1,
                "vector": {
                    "fast-all-minilm-l6-v2": [0.1] * 384  # 384-dimensional test vector
                },
                "payload": {
                    "text": "Test HackerOne API documentation",
                    "source": "test"
                }
            }]
        }
        
        test_response = requests.put(
            f"{QDRANT_URL}/collections/{COLLECTION_NAME}/points",
            json=test_point
        )
        
        if test_response.status_code == 200:
            print("✅ Test point inserted successfully")
        else:
            print(f"⚠️ Test point insertion failed: {test_response.json()}")
            
        return True
    else:
        print(f"❌ Failed to create collection: {response.json()}")
        return False

def list_all_collections():
    """List all collections and their configurations"""
    print("\n📊 Current Qdrant Collections:")
    print("-" * 50)
    
    collections_response = requests.get(f"{QDRANT_URL}/collections")
    collections = collections_response.json()
    
    for collection in collections['result']['collections']:
        name = collection['name']
        print(f"\n• {name}")
        
        # Get detailed config
        config_response = requests.get(f"{QDRANT_URL}/collections/{name}")
        config = config_response.json()
        
        if 'result' in config and 'config' in config['result']:
            vectors = config['result']['config']['params'].get('vectors', {})
            
            if isinstance(vectors, dict):
                # Named vectors
                for vector_name, vector_config in vectors.items():
                    if isinstance(vector_config, dict):
                        print(f"  - Named vector: {vector_name}")
                        print(f"    Size: {vector_config.get('size', 'unknown')}")
                        print(f"    Distance: {vector_config.get('distance', 'unknown')}")
            else:
                # Unnamed vector
                print(f"  - Unnamed vector")
                print(f"    Size: {vectors.get('size', 'unknown')}")
                print(f"    Distance: {vectors.get('distance', 'unknown')}")

if __name__ == "__main__":
    print("🔧 Qdrant MCP Vector Configuration Fix")
    print("=" * 50)
    
    # Create the properly configured collection
    if recreate_collection_with_named_vectors():
        # List all collections to verify
        list_all_collections()
        
        print("\n✅ Qdrant is now configured for MCP usage!")
        print("The MCP can now use the 'bbhk_knowledge' collection with 'fast-all-minilm-l6-v2' vector name")
    else:
        print("\n❌ Failed to configure Qdrant for MCP")