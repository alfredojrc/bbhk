# Qdrant Integration Documentation

## Current Status ✅
- **Container**: bbhk-qdrant (running)
- **Port**: 6333
- **Collections**: 4 (bbhk-project, bbhk_programs, bbhk_vulnerabilities, hubspot)
- **Data Points**: 183 in bbhk-project
- **Volume**: qdrant_storage (persistent data)

## Quick Commands

### Check Status
```bash
# Verify Qdrant is running
docker ps | grep qdrant

# Check collections
curl -s http://localhost:6333/collections | jq '.result.collections[].name'

# Count points in bbhk-project
curl -s http://localhost:6333/collections/bbhk-project | jq '.result.points_count'
```

### Fix Issues
```bash
# Run fix script if MCP integration fails
python3 /home/kali/bbhk/scripts/fix_qdrant_mcp.py

# Restart container if needed
docker restart bbhk-qdrant
```

## Using Qdrant Data

### Via Python
```python
from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchValue

client = QdrantClient(url="http://localhost:6333")

# Search for vulnerability patterns
results = client.search(
    collection_name="bbhk-project",
    query_vector=[0.1] * 384,  # Your query vector
    limit=5
)
```

### Via Memory Storage
Since MCP Qdrant integration is not available in this session, use claude-flow memory:

```javascript
// Store information
mcp__claude-flow__memory_usage({
  action: "store",
  key: "pattern_name",
  namespace: "bug_bounty",
  value: "pattern description"
})

// Retrieve information  
mcp__claude-flow__memory_usage({
  action: "retrieve",
  key: "pattern_name",
  namespace: "bug_bounty"
})
```

## Collections Overview

### bbhk-project (Main Collection)
- **Points**: 183
- **Purpose**: Bug bounty patterns and vulnerabilities
- **Vector Config**: fast-all-minilm-l6-v2 (384 dimensions)

### bbhk_programs
- **Purpose**: HackerOne program data
- **Content**: Program details, scope, bounties

### bbhk_vulnerabilities
- **Purpose**: Vulnerability patterns and exploits
- **Content**: CVEs, techniques, PoCs

### hubspot
- **Purpose**: HubSpot-specific research
- **Content**: API patterns, vulnerabilities found

## Maintenance

### Backup Data
```bash
# Export collection
curl -X POST "http://localhost:6333/collections/bbhk-project/snapshots"

# List snapshots
curl -X GET "http://localhost:6333/collections/bbhk-project/snapshots"
```

### Clean Up Old Containers
```bash
# Remove stopped containers
docker container prune

# Keep only bbhk-qdrant running
```

## Important Notes

1. **Never delete qdrant_storage volume** - Contains all our data
2. **Use bbhk-qdrant container** - This is the correct one with our data
3. **MCP integration** requires Claude Code restart after configuration changes
4. **Alternative storage** available via claude-flow memory if Qdrant unavailable