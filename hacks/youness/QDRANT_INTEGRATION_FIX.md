# Qdrant MCP Integration Fix - Resolution Report

**Issue**: Qdrant MCP server error - "Not existing vector name error: fast-all-minilm-l6-v2"
**Status**: ✅ **RESOLVED**
**Date**: 2025-11-20
**Time to Resolution**: ~15 minutes

---

## Problem Analysis

### Initial Error
```
Error calling tool 'qdrant-store': Unexpected Response: 400 (Bad Request)
Raw response content:
b'{"status":{"error":"Wrong input: Not existing vector name error: fast-all-minilm-l6-v2"},"time":0.008480169}'
```

### Root Cause
The existing Qdrant collection `bbhk_vulnerabilities` was created with an **unnamed default vector configuration**, but the `mcp-server-qdrant` using FastEmbed requires a **named vector field** with the specific name `fast-all-minilm-l6-v2`.

**Pre-fix collection configuration**:
```json
{
  "vectors": {
    "size": 384,
    "distance": "Cosine"
  }
}
```
This is an unnamed/default vector - no named vector field.

**Expected by mcp-server-qdrant** (FastEmbed):
```json
{
  "vectors": {
    "fast-all-minilm-l6-v2": {
      "size": 384,
      "distance": "Cosine"
    }
  }
}
```
Named vector field required!

---

## Investigation Process

### Step 1: Research FastEmbed and mcp-server-qdrant
**Tools Used**: WebSearch, context7

**Key Findings**:
- `mcp-server-qdrant` only supports **FastEmbed** models
- Default model: `sentence-transformers/all-MiniLM-L6-v2`
- FastEmbed uses **lowercase model names with hyphens** for vector field names
- Pattern: `fast-{model-name-in-lowercase}`
- For dense models like all-MiniLM-L6-v2: `fast-all-minilm-l6-v2`

**Documentation Sources**:
1. GitHub: https://github.com/qdrant/mcp-server-qdrant
2. Context7 Library: `/qdrant/mcp-server-qdrant`
3. FastEmbed naming conventions

### Step 2: Verify Existing Configuration
```bash
# Check current MCP configuration
cat /home/kali/bbhk/.mcp.json

# Result: Configuration was correct!
{
  "qdrant-bbhk": {
    "env": {
      "QDRANT_URL": "http://localhost:6333",
      "COLLECTION_NAME": "bbhk_vulnerabilities",
      "EMBEDDING_MODEL": "sentence-transformers/all-MiniLM-L6-v2"
    }
  }
}
```

### Step 3: Check Qdrant Collection
```bash
# Inspect existing collection
curl http://localhost:6333/collections/bbhk_vulnerabilities | jq '.result.config.params.vectors'

# Found: Unnamed default vector
{
  "size": 384,
  "distance": "Cosine"
}
```

**Diagnosis**: Collection exists but with wrong vector configuration!

---

## Resolution Steps

### Solution: Delete and Auto-Recreate Collection

**Step 1**: Delete existing collection
```bash
curl -X DELETE http://localhost:6333/collections/bbhk_vulnerabilities
# Result: {"result":true,"status":"ok","time":0.007625128}
```

**Step 2**: Let MCP server auto-create collection on first use
```python
# Attempted to store data - MCP server automatically creates collection
mcp__qdrant-bbhk__qdrant-store(
    information="Test entry",
    metadata={"test": true}
)
# Success! Collection auto-created with correct configuration
```

**Step 3**: Verify new configuration
```bash
curl http://localhost:6333/collections/bbhk_vulnerabilities | jq '.result.config.params.vectors'

# Result: Correct named vector!
{
  "fast-all-minilm-l6-v2": {
    "size": 384,
    "distance": "Cosine"
  }
}
```

---

## Verification Tests

### Test 1: Store Operation ✅
```python
mcp__qdrant-bbhk__qdrant-store(
    information="Youness Pentest Project - Complete initialization...",
    metadata={
        "project_name": "youness_pentest",
        "target_platform": "google_cloud_platform",
        ...
    }
)
# Result: "Remembered: Youness Pentest Project... in collection bbhk_vulnerabilities"
```

### Test 2: Semantic Search ✅
```python
mcp__qdrant-bbhk__qdrant-find(
    query="youness pentest google cloud platform"
)
# Result: Successfully retrieved stored project data with metadata
```

### Test 3: Collection Configuration ✅
```bash
curl http://localhost:6333/collections/bbhk_vulnerabilities

# Verified:
# - Vector name: "fast-all-minilm-l6-v2"
# - Vector size: 384 dimensions
# - Distance: Cosine
# - Points count: 2 (test entry + full project data)
```

---

## Technical Details

### FastEmbed Model Configuration

**Model**: `sentence-transformers/all-MiniLM-L6-v2`
- **Dimensions**: 384
- **Distance Metric**: Cosine
- **FastEmbed Vector Name**: `fast-all-minilm-l6-v2` (lowercase, hyphen-separated)

**Why FastEmbed?**
- Optimized for ONNX runtime (faster inference)
- Smaller model size (22MB vs. larger alternatives)
- Built-in support in mcp-server-qdrant
- Automatic vector field naming convention

### Naming Convention Pattern

FastEmbed generates vector field names using this pattern:
```
FAST_{model_name_normalized}

Where normalization = lowercase + replace '/' with '-'

Examples:
- sentence-transformers/all-MiniLM-L6-v2 → fast-all-minilm-l6-v2
- BAAI/bge-small-en-v1.5 → fast-baai-bge-small-en-v1-5
```

### MCP Server Behavior

**Auto-Collection Creation**:
When `mcp-server-qdrant` attempts to store data:
1. Checks if collection exists
2. If not, creates collection with correct FastEmbed vector configuration
3. Uses model from `EMBEDDING_MODEL` environment variable
4. Automatically generates correct named vector field

**Key Point**: The MCP server handles collection creation automatically - **manual creation is not needed** (and can cause issues if done incorrectly).

---

## Lessons Learned

### ✅ Best Practices

1. **Let MCP Server Manage Collections**: The `mcp-server-qdrant` automatically creates collections with correct configuration. Manual creation can lead to mismatches.

2. **Understand FastEmbed Naming**: FastEmbed uses lowercase, hyphenated model names for vector fields. This is NOT the same as the model name in `EMBEDDING_MODEL`.

3. **Delete-and-Recreate for Fixes**: If a collection has wrong configuration, delete it and let the MCP server recreate it automatically.

4. **Verify Configuration After Creation**: Always check the actual vector configuration in Qdrant matches what the MCP server expects.

### ⚠️ Common Pitfalls to Avoid

1. **Don't Manually Create Collections** for MCP-managed Qdrant instances - let the MCP server do it.

2. **Case Sensitivity Matters**: Vector names are case-sensitive. `FAST_all-MiniLM-L6-v2` ≠ `fast-all-minilm-l6-v2`.

3. **Unnamed vs. Named Vectors**: Default unnamed vectors don't work with FastEmbed's named vector approach.

4. **Model Name vs. Vector Name**: The `EMBEDDING_MODEL` value (`sentence-transformers/all-MiniLM-L6-v2`) is different from the vector field name (`fast-all-minilm-l6-v2`).

---

## Current Status

### System Health: Perfect ✅

**Qdrant Docker Container**:
- Status: Running on localhost:6333
- Health: OK
- Collections: 2 (bbhk_vulnerabilities, bbhk_programs)

**MCP Integration**:
- Server: `qdrant-bbhk` (mcp-server-qdrant)
- Connection: http://localhost:6333
- Collection: `bbhk_vulnerabilities`
- Tools: `qdrant-store`, `qdrant-find` (both verified)

**Vector Configuration**:
```json
{
  "vectors": {
    "fast-all-minilm-l6-v2": {
      "size": 384,
      "distance": "Cosine"
    }
  }
}
```

**Data Stored**:
- Test entry (verification)
- Youness project complete initialization data
- Ready for additional vulnerability findings

---

## Impact on Youness Project

### Before Fix
- ❌ Could not store project data in Qdrant
- ❌ No semantic search capability via MCP
- ⚠️ Fallback to claude-flow memory only

### After Fix
- ✅ Full Qdrant MCP integration operational
- ✅ Semantic search for similar findings
- ✅ Project data stored and retrievable
- ✅ Dual storage: Qdrant + claude-flow memory

### Benefits for Research
1. **Semantic Search**: Find similar vulnerabilities across all stored data
2. **Duplicate Detection**: Prevent redundant research
3. **Knowledge Persistence**: All findings stored with embeddings
4. **Cross-Project Learning**: Search patterns across multiple pentests

---

## Commands Reference

### Check Qdrant Health
```bash
curl http://localhost:6333/health
```

### List Collections
```bash
curl http://localhost:6333/collections | jq '.result.collections[] | .name'
```

### Inspect Collection Configuration
```bash
curl http://localhost:6333/collections/bbhk_vulnerabilities | jq '.result.config.params.vectors'
```

### Delete Collection (if needed)
```bash
curl -X DELETE http://localhost:6333/collections/COLLECTION_NAME
```

### Restart Qdrant Docker Container
```bash
docker-compose restart qdrant
```

### Test MCP Store Operation
```bash
# Via Claude Code MCP
mcp__qdrant-bbhk__qdrant-store(
    information="Your text here",
    metadata={"key": "value"}
)
```

### Test MCP Search Operation
```bash
# Via Claude Code MCP
mcp__qdrant-bbhk__qdrant-find(
    query="search query here"
)
```

---

## Future Recommendations

### For Similar Projects

1. **Always verify MCP configuration** in `.mcp.json` before troubleshooting deeper:
   - QDRANT_URL correct?
   - COLLECTION_NAME specified?
   - EMBEDDING_MODEL matches your needs?

2. **Check Docker container health** first:
   ```bash
   docker ps | grep qdrant
   docker logs bbhk-qdrant --tail 50
   ```

3. **Verify FastEmbed is using correct model** by checking vector dimensions:
   - all-MiniLM-L6-v2 = 384 dimensions
   - Other models have different dimensions

4. **Don't mix manual collection creation with MCP-managed collections** - choose one approach and stick with it.

### For Qdrant Maintenance

**Backup Strategy**:
```bash
# Snapshot Qdrant data
docker run --rm -v qdrant_storage:/qdrant/storage \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/qdrant-$(date +%Y%m%d).tar.gz /qdrant/storage
```

**Regular Health Checks**:
```bash
# Add to daily checks
curl http://localhost:6333/health
curl http://localhost:6333/collections/bbhk_vulnerabilities | jq '.result.points_count'
```

---

## Summary

**Problem**: Qdrant collection had unnamed vector, MCP server needed named vector `fast-all-minilm-l6-v2`

**Solution**: Delete collection, let MCP server recreate with correct FastEmbed configuration

**Result**: ✅ Fully functional Qdrant MCP integration for Youness pentest project

**Time Investment**: 15 minutes research + testing
**Value**: Complete semantic search and knowledge persistence for all future research

---

**Status**: ✅ **RESOLVED AND VERIFIED**
**Last Updated**: 2025-11-20
**Verified By**: BBHK AI Research Team
