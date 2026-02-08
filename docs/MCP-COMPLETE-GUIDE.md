# MCP Server Complete Guide
**Last Updated:** 2025-08-17  
**Status:** Production Ready with Minor Issues

## Quick Start

All MCP servers are integrated and ready for use in this project. Use this guide to understand capabilities and workarounds for known issues.

## Available MCP Servers

### 1. claude-flow (✅ FULLY OPERATIONAL)
AI coordination and swarm management server.

**Key Functions:**
- `swarm_init` - Initialize swarm with topology
- `agent_spawn` - Create specialized agents  
- `task_orchestrate` - Coordinate complex workflows
- `memory_usage` - Persistent memory operations
- `neural_train` - Train neural patterns
- `health_check` - System health monitoring

**Example Usage:**
```javascript
mcp__claude-flow__swarm_init({ 
  topology: "mesh", 
  maxAgents: 5 
})
```

### 2. ruv-swarm (⚠️ OPERATIONAL WITH WORKAROUNDS)
High-performance swarm orchestration with WASM/SIMD optimization.

**Status:** Core functions work, monitoring has issues  
**Workaround:** Use initialization script before monitoring

**Key Functions:**
- `swarm_init` - Initialize swarm
- `agent_spawn` - Create agents
- `features_detect` - Detect runtime capabilities
- `swarm_monitor` - Real-time monitoring (has issues)

**Fix Applied:** Global metrics initialization via `/home/kali/bbhk/scripts/mcp-server-init.js`

### 3. context7 (✅ FULLY OPERATIONAL)
Documentation and library reference retrieval.

**Key Functions:**
- `resolve-library-id` - Find library IDs
- `get-library-docs` - Retrieve documentation

**Example:**
```javascript
mcp__context7__resolve-library-id({ 
  libraryName: "react" 
})
```

### 4. magic (✅ FULLY OPERATIONAL)
UI component generation and logo search.

**Key Functions:**
- `21st_magic_component_builder` - Create UI components
- `logo_search` - Find company logos
- `21st_magic_component_refiner` - Improve UI

### 5. playwright (✅ FULLY OPERATIONAL)
Browser automation and testing.

**Key Functions:**
- `playwright_navigate` - Navigate to URL
- `playwright_screenshot` - Take screenshots
- `playwright_click` - Click elements
- `playwright_fill` - Fill forms

### 6. fetch (✅ FULLY OPERATIONAL)
Web content fetching and simplification.

**Key Functions:**
- `fetch` - Retrieve web content as markdown

**Note:** May show HTML simplification warnings (non-critical)

### 7. qdrant-bbhk (⚠️ CONFIGURATION ISSUES)
Bug bounty data storage with vector search.

**Issue:** Vector name mismatch in MCP server  
**Workaround:** Use HTTP API directly or Python client

**Fix Applied:** Collections recreated with correct vector configuration via `/home/kali/bbhk/scripts/fix-qdrant-mcp.py`

## Troubleshooting Guide

### Issue: ruv-swarm "Cannot read properties of null"
**Solution:** Run initialization script
```bash
node /home/kali/bbhk/scripts/mcp-server-init.js
```

### Issue: qdrant-bbhk "Vector not configured"
**Solution:** Use direct API calls
```python
import requests
# Use HTTP API directly
response = requests.post(
    "http://localhost:6333/collections/bbhk_vulnerabilities/points/search",
    json={"vector": [0.1]*384, "limit": 5}
)
```

### Issue: MCP server not appearing in Claude
**Solution:** Check `.claude/settings.json` for:
```json
"enabledMcpjsonServers": ["claude-flow", "ruv-swarm"]
```

## Performance Optimization

### Batch Operations
Always use parallel operations for better performance:
```javascript
// Good - parallel execution
[
  mcp__claude-flow__agent_spawn({type: "researcher"}),
  mcp__claude-flow__agent_spawn({type: "coder"}),
  mcp__claude-flow__agent_spawn({type: "tester"})
]

// Bad - sequential execution
await mcp__claude-flow__agent_spawn({type: "researcher"})
await mcp__claude-flow__agent_spawn({type: "coder"})
await mcp__claude-flow__agent_spawn({type: "tester"})
```

### Memory Management
- Use namespaces in memory operations
- Set TTL for temporary data
- Clean up after large operations

## Integration Patterns

### 1. Bug Bounty Research Flow
```javascript
// 1. Initialize swarm
mcp__claude-flow__swarm_init({topology: "hierarchical"})

// 2. Spawn research agents
mcp__claude-flow__agent_spawn({type: "researcher"})

// 3. Search for vulnerabilities
mcp__fetch__fetch({url: "https://hackerone.com/reports"})

// 4. Store findings (use direct API for now)
// Direct Qdrant API call recommended
```

### 2. Documentation Search Flow
```javascript
// 1. Resolve library
const lib = mcp__context7__resolve-library-id({
  libraryName: "express"
})

// 2. Get documentation
mcp__context7__get-library-docs({
  context7CompatibleLibraryID: lib.id,
  topic: "routing"
})
```

### 3. UI Component Generation Flow
```javascript
// 1. Generate component
mcp__magic__21st_magic_component_builder({
  searchQuery: "dashboard",
  message: "Create admin dashboard"
})

// 2. Refine if needed
mcp__magic__21st_magic_component_refiner({
  context: "improve responsiveness"
})
```

## Best Practices

1. **Always Initialize First**
   - Run swarm_init before agent operations
   - Check health before critical operations

2. **Handle Errors Gracefully**
   - Implement fallbacks for known issues
   - Log errors for debugging

3. **Monitor Resource Usage**
   - Track memory with memory_usage
   - Use performance metrics

4. **Clean Up Resources**
   - Close browsers after playwright operations
   - Clear temporary memory data

## Scripts and Tools

### Available Fix Scripts
- `/home/kali/bbhk/scripts/fix-qdrant-mcp.py` - Fix Qdrant collections
- `/home/kali/bbhk/scripts/mcp-server-init.js` - Initialize MCP servers
- `/home/kali/bbhk/config/mcp-wrapper-config.json` - Wrapper configurations

### Health Check Commands
```bash
# Check Qdrant
curl http://localhost:6333/

# List collections
curl http://localhost:6333/collections

# Check Docker containers
docker ps | grep -E "qdrant|mcp"
```

## Known Limitations

1. **Qdrant MCP**: Hardcoded vector name causes store/find failures
2. **ruv-swarm monitor**: Map function error in event processing
3. **WebFetch**: HTML simplification may fail on complex pages

## Future Improvements

- [ ] Create custom Qdrant MCP wrapper
- [ ] Fix ruv-swarm monitoring events
- [ ] Add retry logic for transient failures
- [ ] Implement health check dashboard
- [ ] Add automated testing suite

## Support

For issues or questions:
1. Check this guide first
2. Run diagnostic scripts
3. Review error logs in `/home/kali/bbhk/logs/`
4. Use fallback methods documented above