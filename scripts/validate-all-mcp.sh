#!/bin/bash
# Simple MCP Validation Script - KISS Principle
# Tests all MCP servers are working correctly

echo "🔍 MCP Server Validation - $(date '+%Y-%m-%d %H:%M')"
echo "================================================="

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results counter
PASSED=0
FAILED=0

# Test function
test_mcp() {
    local name=$1
    local test_cmd=$2
    local description=$3
    
    echo -n "Testing $name: $description... "
    
    if eval "$test_cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        ((FAILED++))
        return 1
    fi
}

# 1. Test Qdrant
test_mcp "Qdrant" "curl -s http://localhost:6333/ | grep -q 'qdrant'" "Vector database health"

# 2. Test Docker containers
test_mcp "Docker" "docker ps | grep -q qdrant" "Qdrant container running"

# 3. Test Claude CLI
test_mcp "Claude CLI" "claude mcp list > /dev/null 2>&1" "MCP servers registered"

# 4. Test file access
test_mcp "File Access" "test -f /home/kali/bbhk/docs/MCP-COMPLETE-GUIDE.md" "Documentation exists"

# 5. Test Python environment
test_mcp "Python" "python3 -c 'import requests; import json' 2>/dev/null" "Required modules"

# 6. Test Node.js
test_mcp "Node.js" "node --version > /dev/null 2>&1" "Node runtime available"

# 7. Test Qdrant collections
test_mcp "Collections" "curl -s http://localhost:6333/collections | grep -q bbhk" "Qdrant collections exist"

# 8. Test scripts exist
test_mcp "Fix Scripts" "test -f /home/kali/bbhk/scripts/fix-qdrant-mcp.py" "Fix scripts available"

echo "================================================="
echo "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All MCP servers validated successfully!${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠️  Some tests failed. Run fix scripts:${NC}"
    echo "  python3 /home/kali/bbhk/scripts/fix-qdrant-mcp.py"
    echo "  node /home/kali/bbhk/scripts/mcp-server-init.js"
    exit 1
fi