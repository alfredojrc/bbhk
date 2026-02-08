#!/usr/bin/env python3
"""
Fix Qdrant vector configuration for all-MiniLM-L6-v2 model
Creates proper collection with FastEmbed configuration
"""

import os
import sys
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from fastembed import TextEmbedding
import json

def fix_qdrant_configuration():
    """Configure Qdrant with proper vector model"""
    
    # Initialize Qdrant client
    client = QdrantClient(host="localhost", port=6333)
    
    # Initialize FastEmbed with all-MiniLM-L6-v2
    print("🔧 Initializing FastEmbed with all-MiniLM-L6-v2 model...")
    embedding_model = TextEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2")
    
    # Get model dimensions
    test_embedding = list(embedding_model.embed(["test"]))[0]
    vector_size = len(test_embedding)
    print(f"✅ Model initialized with vector size: {vector_size}")
    
    # Create properly configured collection
    collection_name = "bbhk_vulnerabilities"
    
    try:
        # Delete if exists
        client.delete_collection(collection_name)
        print(f"🗑️ Deleted existing collection: {collection_name}")
    except:
        pass
    
    # Create new collection with proper configuration
    print(f"📦 Creating collection: {collection_name}")
    client.create_collection(
        collection_name=collection_name,
        vectors_config=VectorParams(
            size=vector_size,
            distance=Distance.COSINE,
            on_disk=False
        )
    )
    
    # Add test data
    test_points = [
        {
            "id": 1,
            "text": "XSS vulnerability in input validation",
            "metadata": {"type": "XSS", "severity": "high"}
        },
        {
            "id": 2,
            "text": "SQL injection in user authentication",
            "metadata": {"type": "SQLi", "severity": "critical"}
        },
        {
            "id": 3,
            "text": "CSRF token missing in form submission",
            "metadata": {"type": "CSRF", "severity": "medium"}
        }
    ]
    
    print("📝 Adding test vulnerability data...")
    points = []
    for point_data in test_points:
        embedding = list(embedding_model.embed([point_data["text"]]))[0]
        points.append(
            PointStruct(
                id=point_data["id"],
                vector=embedding.tolist(),
                payload={
                    "text": point_data["text"],
                    **point_data["metadata"]
                }
            )
        )
    
    client.upsert(collection_name=collection_name, points=points)
    
    # Test search
    print("\n🔍 Testing search functionality...")
    query_text = "XSS attack"
    query_embedding = list(embedding_model.embed([query_text]))[0]
    
    search_result = client.search(
        collection_name=collection_name,
        query_vector=query_embedding.tolist(),
        limit=3
    )
    
    print(f"✅ Search for '{query_text}' results:")
    for result in search_result:
        print(f"  - Score: {result.score:.4f}, Text: {result.payload['text']}")
    
    # Create configuration for MCP server
    config = {
        "collection_name": collection_name,
        "model_name": "sentence-transformers/all-MiniLM-L6-v2",
        "vector_size": vector_size,
        "distance": "cosine"
    }
    
    config_path = "/home/kali/bbhk/config/qdrant_mcp_config.json"
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    
    print(f"\n✅ Configuration saved to: {config_path}")
    print("🎉 Qdrant successfully configured with all-MiniLM-L6-v2!")
    
    return True

if __name__ == "__main__":
    try:
        fix_qdrant_configuration()
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)