#!/usr/bin/env python3
"""
Search the knowledge base for a given query.
"""

import asyncio
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage.vector_store import QdrantVectorStore

async def main():
    """
    Main function to search the knowledge base.
    """
    query = "HubSpot security testing"
    collections = ["bbhk_vulnerabilities", "bbhk-project", "bbhk_programs"]

    for collection in collections:
        print(f"Searching collection: {collection}")
        vector_store = QdrantVectorStore(collection_name=collection)
        await vector_store.initialize()
        results = await vector_store.search_similar_programs(query)
        await vector_store.cleanup()

        if results:
            for result in results:
                print(f"  Score: {result['score']:.4f}")
                print(f"  Name: {result.get('name')}")
                print(f"  Handle: {result.get('handle')}")
                print(f"  Platform: {result.get('platform')}")
                print(f"  Snippet: {result.get('text_snippet')}")
                print("-" * 20)
        else:
            print("  No results found.")
        print()

if __name__ == "__main__":
    asyncio.run(main())