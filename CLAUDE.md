# CLAUDE.md - Bug Bounty Hunter Kit (BBHK) v3.0
## 🎯 AI-Augmented Bug Bounty Platform

IMPORTANT! DON'T BE LAZY!! IF YOU FIND AN ISSUE, FIX IT!! 
FIND WORKARROUNDS IF IT MAKES SENSE, BUT THE FIRST THOUGHT SHOULD BE: FIX IT!!! 
USE WEB SEARCH, CONTEXT7, SERENA, QDRANT, ALL OUR MCP'S!!

## 🗄️ **VULNERABILITY STORAGE** - PRIMARY INTERFACE

**CRITICAL FOR CLAUDE CODE**: Use these commands for ALL vulnerability management!

```bash
# STORE NEW FINDINGS
./vuln store-quick                    # Interactive vulnerability entry
./vuln store vulnerability.json       # Import from JSON file

# SEARCH & ANALYZE
./vuln search chainlink              # Program-specific search
./vuln find "oracle manipulation"   # Semantic similarity search  
./vuln active                        # Active vulnerabilities (18 total)
./vuln critical                      # Critical severity only
./vuln portfolio                     # Portfolio analysis ($2.65M-$7.02M)

# AI-POWERED TOOL RECOMMENDATIONS (NEW)
./vuln tools <vuln_id>               # Get optimal tools for specific vulnerability
./vuln research <vuln_id>            # Create automated research workflow  
./vuln next <vuln_id>                # Get next guided research action

# UPDATE & MANAGE
./vuln update 5 status submitted     # Update specific fields
./vuln sync                          # Sync all systems (SQLite→Qdrant→Claude-flow)
./vuln validate                      # Check data consistency
./vuln backup                        # Export CSV backup
```

### **MANDATORY Workflow for New Findings**:
```bash
# 1. ALWAYS verify technology first (prevents false positives)
./verify-tech.sh

# 2. Store vulnerability with validation  
./vuln store-quick

# 3. Sync across all systems
./vuln sync
```

**Current Portfolio**: 39 vulnerabilities, 18 active, **$7.02M max potential value**

---

## 🛠️ **KALI TOOLS INTELLIGENCE** - AI-DRIVEN TOOL SELECTION

**NEW CAPABILITIES**: Smart tool recommendations based on vulnerability patterns and AI agent coordination!

### **Tool Management Commands**:
```bash
# VULNERABILITY-SPECIFIC RECOMMENDATIONS  
./vuln tools <vuln_id>               # Get optimal tools for specific vulnerability
./vuln research <vuln_id>            # Create automated research workflow
./vuln next <vuln_id>                # Get next research action with guidance

# STANDALONE TOOL MANAGEMENT
./tools-cli-venv search <query>      # Search for tools by capability
./tools-cli-venv list                # List all registered tools with metrics
./tools-cli-venv recommend           # Get tool recommendations for current context

# RESEARCH SESSIONS
./tools-cli-venv session create      # Start new research session
./tools-cli-venv session update      # Track progress and findings
```

### **Current Tool Registry**: 
- **10 tools registered** with effectiveness metrics
- **$445k total bounty potential** across all tools  
- **<200ms hybrid queries** with multi-tier matching
- **Smart recommendations**: Exact → Fuzzy → Semantic → Fallback

### **Agent-Tool Integration**:
```bash
# AI agents get optimal tool selections automatically
mcp__claude-flow__agent_spawn type:"business-logic-breaker"  # → burpsuite, slither, semgrep
mcp__claude-flow__agent_spawn type:"scout-recon"            # → subfinder, httpx, nuclei
mcp__claude-flow__agent_spawn type:"chaos-monkey"          # → ffuf, echidna, nuclei
```

**Performance**: Methodology v2.0 with **75% search acceleration** and **95% false positive prevention**

---

## ⚠️ **CRITICAL RULES**

### 🔍 **T.K.V.F. Framework** (Technology Knowledge Verification)
**MANDATORY BEFORE any vulnerability research**:

1. **STOP** - Don't assume anything about the technology
2. **VERIFY** - Run: `./verify-tech.sh` (25-minute verification process)  
3. **DOCUMENT** - Update knowledge base with findings

**Why Critical**: Prevented 3 false positives, saved 75+ hours of wasted research
- ❌ **Ondo Finance T+2**: False positive (tokens burned immediately)
- ❌ **Chainlink External Adapters**: Deprecated, not in production  
- ❌ **Keystone Network**: No mainnet deployment

**Access**: `/home/kali/bbhk/TECHNOLOGY_VERIFICATION_QUICKSTART.md`
**Memory**: `mcp__claude-flow__memory_usage action:"retrieve" key:"technology_knowledge_verification_framework"`
**Enhanced**: Now integrated in Methodology Framework v2.0 with tool automation and agent coordination

### 🎯 **Confirmed Active Vulnerabilities** (4 Tier 1)
1. **Chainlink Functions Oracle Data Poisoning** ($50k-$200k) - Ready for submission
2. **Keystone Network Infrastructure Shutdown** ($500k-$1M) - Nuclear priority  
3. **ACE Policy Manager Bypass** ($200k-$500k) - Novel attack vector
4. **Migration Coordinator Hijacking** ($200k-$500k) - Confirmed novel

**Details**: `mcp__claude-flow__memory_usage action:"retrieve" key:"chainlink_ace_attack_analysis_2025"`

### 🎯 **Attack Pattern Intelligence** (OWASP 2024 Mapped)
**Framework**: Classification system mapping verified vectors to optimal tools and agents

**Tier 1 Critical** ($50k-$2M) - Zero Competition:
- **A01 Broken Access Control** → ACE Policy Bypass, Migration Hijacking
- **A03 Injection** → Oracle Data Poisoning  
- **A04 Insecure Design** → Keystone Shutdown, Cross-Chain TOCTOU

**Tool-Attack Mapping**:
- **Business Logic** (burp, slither) → Payment/Policy flaws
- **Injection** (sqlmap, custom-fuzzers) → Data poisoning attacks
- **Design Flaws** (threat-modeling, race-detectors) → TOCTOU vulnerabilities

**Memory Access**: `mcp__claude-flow__memory_usage action:"retrieve" key:"attack_pattern_classification_owasp_2024"`

---

## 🏗️ **SYSTEM ARCHITECTURE**

### **Hybrid Data Storage**:
- **SQLite** (.swarm/memory.db): Primary storage, 39 vulnerabilities + tool registry, source of truth
- **Qdrant** (localhost:6333): Semantic search, 10 optimized collections (cleaned 47%), **MCP-enabled**
- **Kali Tools DB**: Tool registry, research sessions, agent-tool mappings
- **Claude-flow Memory**: Research patterns, T.K.V.F./D.I.E. frameworks, methodology v2.0
- **CSV Export**: Backup with 25 fields (vulnerability_data_structured.csv)

#### **Qdrant Vector Database** (Docker Container with MCP Integration):
**Status**: ✅ Production-ready with FastEmbed MCP server (Updated 2025-11-20, Fixed)

**Container Details**:
- **Image**: `qdrant/qdrant:v1.12.5` (pinned for stability)
- **Container Name**: `bbhk-qdrant`
- **Ports**: 6333 (HTTP API), 6334 (gRPC)
- **Volume**: `qdrant_storage` (persistent named volume)
- **Network**: `bbhk-network` (bridge mode)
- **Memory**: 512MB reserved, 2GB limit

**MCP Integration** (`qdrant-bbhk`):
```json
// Configuration in .mcp.json
{
  "qdrant-bbhk": {
    "type": "stdio",
    "command": "uvx",
    "args": ["mcp-server-qdrant"],
    "env": {
      "QDRANT_URL": "http://localhost:6333",
      "COLLECTION_NAME": "bbhk_vulnerabilities",
      "EMBEDDING_MODEL": "sentence-transformers/all-MiniLM-L6-v2"
    }
  }
}
```

**IMPORTANT - MCP Tools Only**:
⚠️ **ALWAYS use MCP tools for Qdrant operations in Claude Code. NEVER use curl or direct API calls!**

**Correct Usage** (via MCP tools):
```python
# ✅ Store data (CORRECT - use MCP tool)
mcp__qdrant-bbhk__qdrant-store(
    information="Your natural language description of the data",
    metadata={"key": "value", "project": "name", ...}
)

# ✅ Search data (CORRECT - use MCP tool)
mcp__qdrant-bbhk__qdrant-find(
    query="natural language search query"
)

# ❌ NEVER do this in Claude Code:
# curl http://localhost:6333/... (manual API calls break MCP workflow)
```

**Why MCP Tools Only?**
1. **Auto-Collection Management**: MCP server creates collections with correct FastEmbed vector configuration
2. **Automatic Embeddings**: Text is automatically embedded using FastEmbed
3. **Proper Error Handling**: MCP server handles FastEmbed-specific requirements
4. **Session Consistency**: MCP maintains proper context across operations

**Docker Management** (these curl commands are OK for debugging/health checks):
```bash
# Start Qdrant container
docker-compose up -d qdrant

# Check health (diagnostic only - not for data operations)
docker ps | grep bbhk-qdrant
docker logs bbhk-qdrant --tail 50
curl http://localhost:6333/health  # Health check OK

# Restart after config changes
docker-compose restart qdrant

# Access Qdrant dashboard (read-only browsing)
open http://localhost:6333/dashboard
```

**Collections** (10 optimized):
1. **bbhk_vulnerabilities** - Main vulnerability storage (384-dim vectors)
2. **tools_registry** - Kali tool intelligence
3. **attack_patterns** - OWASP 2024 mapped vectors
4. **research_sessions** - Historical research data
5. **program_intelligence** - Target program analysis
6. **poc_library** - Proof-of-concept code snippets
7. **agent_memories** - AI agent learning patterns
8. **methodology_kb** - T.K.V.F. + D.I.E. frameworks
9. **false_positives** - Lessons learned database
10. **code_analysis** - Smart contract vulnerability patterns

**Semantic Search via MCP**:
```bash
# Claude Code automatically uses qdrant-bbhk MCP for:
# - Vulnerability similarity search
# - Tool recommendation queries
# - Research pattern matching
# - Duplicate detection

# Example: Claude Code can now ask:
# "Find vulnerabilities similar to oracle manipulation"
# → Automatically queries Qdrant via MCP
```

**Performance Metrics**:
- **Search Speed**: <200ms for hybrid queries
- **Embeddings**: 384-dimensional sentence-transformers
- **Accuracy**: 95% false positive prevention (post-optimization)
- **Storage**: ~500MB for 39 vulnerabilities + metadata

**Health Check**:
```bash
# API health endpoint
curl http://localhost:6333/health

# List all collections
curl http://localhost:6333/collections | jq

# Check collection info
curl http://localhost:6333/collections/bbhk_vulnerabilities | jq
```

**Production Security** (Optional):
```yaml
# Enable in docker-compose.yml or .env
QDRANT__SERVICE__API_KEY=your_secret_key_here

# Then update MCP config in .mcp.json:
"env": {
  "QDRANT_URL": "http://localhost:6333",
  "QDRANT_API_KEY": "${QDRANT_API_KEY}"
}
```

**Backup & Restore**:
```bash
# Snapshot current data
docker run --rm -v qdrant_storage:/qdrant/storage \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/qdrant-$(date +%Y%m%d).tar.gz /qdrant/storage

# Restore from backup
docker run --rm -v qdrant_storage:/qdrant/storage \
  -v $(pwd)/backups:/backup \
  alpine tar xzf /backup/qdrant-20251120.tar.gz -C /
```

### **CRITICAL: Qdrant MCP Troubleshooting**
**Updated 2025-11-20 - Resolution for "vector name error" issues**

#### Common Error: "Not existing vector name error: fast-all-minilm-l6-v2"

**Symptom**:
```
Error calling tool 'qdrant-store': Unexpected Response: 400 (Bad Request)
Raw response content: "Not existing vector name error: fast-all-minilm-l6-v2"
```

**Root Cause**: Qdrant collection was created manually or by another process with wrong vector configuration (unnamed vector instead of named FastEmbed vector)

**Solution - Delete and Auto-Recreate**:
```python
# Step 1: Delete problematic collection (use curl for this diagnostic step)
# Run in terminal:
curl -X DELETE http://localhost:6333/collections/bbhk_vulnerabilities

# Step 2: Let MCP server auto-create collection with correct config
# Use MCP tool - it will automatically create the collection:
mcp__qdrant-bbhk__qdrant-store(
    information="Test initialization",
    metadata={"test": true}
)
# ✅ Collection auto-created with correct FastEmbed vector: "fast-all-minilm-l6-v2"
```

**Why This Works**:
1. `mcp-server-qdrant` uses **FastEmbed** which requires **named vectors**
2. FastEmbed generates vector name: `fast-{model-name-normalized}`
   - `sentence-transformers/all-MiniLM-L6-v2` → `fast-all-minilm-l6-v2` (lowercase, hyphens)
3. MCP server auto-creates collection with correct configuration on first store operation
4. Manual collection creation can cause mismatches - **always let MCP manage it**

**Correct Vector Configuration** (auto-created by MCP):
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

**Verification** (diagnostic curl OK):
```bash
# Check collection has correct vector configuration
curl http://localhost:6333/collections/bbhk_vulnerabilities | \
  jq '.result.config.params.vectors'

# Should see:
# {
#   "fast-all-minilm-l6-v2": {
#     "size": 384,
#     "distance": "Cosine"
#   }
# }
```

#### Best Practices for Qdrant MCP:

1. **✅ DO**: Use MCP tools exclusively for data operations
   ```python
   mcp__qdrant-bbhk__qdrant-store(information="...", metadata={...})
   mcp__qdrant-bbhk__qdrant-find(query="...")
   ```

2. **✅ DO**: Let MCP server manage collection creation
   - First `qdrant-store` call auto-creates collection
   - No manual setup needed

3. **✅ DO**: Use curl only for diagnostics/health checks
   ```bash
   curl http://localhost:6333/health
   curl http://localhost:6333/collections  # List collections
   ```

4. **❌ DON'T**: Create collections manually via curl/API
   - Leads to configuration mismatches
   - MCP server expects specific FastEmbed vector names

5. **❌ DON'T**: Use curl for data operations (insert/search/update)
   - Breaks MCP workflow
   - MCP handles embeddings automatically

**Detailed Fix Documentation**: See `/home/kali/bbhk/hacks/youness/QDRANT_INTEGRATION_FIX.md`

### **Data Flow**:
```
New Finding → T.K.V.F. → ./vuln store-quick → SQLite → Tool Recommendations → Research Workflows → Embeddings → Qdrant → Claude-flow
```

**Technical Details**: See `/home/kali/bbhk/VULNERABILITY_DATA_ARCHITECTURE_SECTION.md`

### **Essential Database Commands**:
```bash
# Quick queries
./query_memory.sh vulns             # Show all vulnerabilities
./query_memory.sh programs          # Show programs  

# Direct SQLite access  
sqlite3 .swarm/memory.db "SELECT * FROM vulnerabilities WHERE severity = 'CRITICAL'"

# Memory access
mcp__claude-flow__memory_usage action:"retrieve" key:"ai_agent_specialization_data"
```

---

## 🤖 **AI TOOLS INTEGRATION**

### **Groky v2** - Context-Aware Security Research
**Location**: `/home/kali/.npm-global/bin/groky-v2`

```bash
# Interactive vulnerability research with memory
groky -s chainlink "Analyze ACE policy bypass vulnerabilities"

# Quick PoC validation  
groky "Review this XSS payload: <script>alert(1)</script>"

# Research with context
groky -s research "What are common oracle manipulation techniques?"
```

### **Methodology Framework v2.0** - Integrated T.K.V.F. + AI Agents
**Location**: Claude-flow memory  
**Access**: `mcp__claude-flow__memory_usage action:"retrieve" key:"comprehensive_research_methodology_framework_v2"`

**6-Phase AI-Driven Pipeline**:
1. **Target Assessment** (2-4h) - scout-recon + prior-art-researcher  
2. **T.K.V.F. Verification** (25min) - MANDATORY technology validation
3. **Attack Classification** (3-6h) - AI-driven vector identification + OWASP 2024 mapping
4. **Agent Coordination** (1-2h) - Swarm orchestration with tool optimization  
5. **D.I.E. Validation** (2-4h) - Quality assurance with critical-validator
6. **Continuous Learning** (ongoing) - Methodology improvement and pattern recognition

**Performance**: 75% search acceleration, 95% false positive prevention, <5s tool recommendations

### **Bug Bounty Agent Swarm** (10 Specialized Hunters)
**Location**: `/home/kali/bbhk/.claude/agents/bug-bounty/`
**Critical Agents** (with optimized tool mappings):
1. **Business Logic Breaker** 🤑 → burpsuite, semgrep, slither, sqlmap
2. **Prior Art Researcher** 🔍 → vulnerability-databases, shodan, search-apis
3. **Critical Validator** 🔴 → foundry, hardhat, automated-testers, impact-calculators
4. **Scout** 🗺️ → subfinder, httpx, nuclei, masscan, nmap
5. **Mastermind** 🧠 → threat-modeling, exploit-chaining, strategic-analyzers

**Specialized Hunters**:
6. **Chaos Monkey** 🐒 → nuclei, ffuf, echidna, fuzzing-frameworks
7. **Code Archaeologist** 📜 → semgrep, git-analysis, gobuster, static-analyzers
8. **Lateral Thinker** 📎 → mythril, custom-fuzzers, novel-analyzers
9. **Code Whisperer** 💻 → bandit, crypto-analyzers, race-detectors
10. **Anarchist** 💥 → boundary-testers, chaos-frameworks, assumption-breakers

```bash
# Deploy specialized agents using MCP commands
mcp__claude-flow__agent_spawn type:"business-logic-breaker" name:"payment-hunter"
mcp__claude-flow__agent_spawn type:"prior-art-researcher" name:"duplicate-checker"
mcp__claude-flow__agent_spawn type:"critical-validator" name:"gemini-validator"
mcp__claude-flow__agent_spawn type:"scout-recon" name:"surface-mapper"

# Full swarm initialization
mcp__claude-flow__swarm_init topology:"mesh" maxAgents:10 strategy:"adaptive"
```

### **MCP Servers** (9 Active - Updated 2025-11-20):
**Project MCPs** (.mcp.json):
- **claude-flow** (v2.0.0-alpha.25): Swarm orchestration & memory management (87 tools)
- **ruv-swarm** (v1.0.20): Distributed swarm intelligence & neural networks
- **context7** (@upstash/context7-mcp@latest): Up-to-date documentation retrieval
- **serena** (uvx from GitHub): Semantic code understanding & intelligent editing
- **qdrant-bbhk** (mcp-server-qdrant): Vector database semantic search (10 collections)
- **playwright** (@executeautomation/playwright-mcp-server): Browser automation
- **magic** (@21st-dev/magic@latest): AI-powered UI component generation

**Additional MCPs** (.roo/mcp.json):
- **supabase** (@supabase/mcp-server-supabase): Database operations
- **hackerone-graphql** (Docker v1.0.6): HackerOne GraphQL API integration
- **mem0** (Composio): Memory management
- **perplexityai** (Composio): AI search integration

**Note**: Removed `fetch` MCP (redundant with Claude Code's built-in WebSearch tool)

---

## 🧠 **QUALITY STANDARDS**

### **D.I.E. Framework** (Mandatory for submissions):
- **Demonstrable**: Working PoC required
- **Impactful**: Clear security impact  
- **Evidentiary**: Complete evidence package

### **Validation Tools**:
```bash
# Expert validation using Critical Validator agent
gemini -y -p "Review this vulnerability using D.I.E. framework"

# Alternative validation using Groky
groky "Analyze this finding for technical accuracy and impact"

# Automated validation workflow
mcp__claude-flow__agent_spawn type:"critical-validator" name:"validator"
```

---

## 🎯 **STRATEGIC FOCUS**

### **Primary Mission**: 
- **Target**: $150k Year 1 through quality over quantity
- **Method**: 10-15 high-value programs, 3-7 day deep dives
- **Priority**: Business Logic > AI/LLM > Cloud Infrastructure

### **Current Success Metrics**:
- **Portfolio Value**: $2.65M-$7.02M (39 documented vulnerabilities)
- **Active Research**: 18 vulnerabilities ready for development/submission
- **False Positive Rate**: <5% (down from 49% before T.K.V.F.)
- **Success Stories**: 4 confirmed Tier 1 vulnerabilities with zero competition
- **System Optimization**: 47% Qdrant collection reduction (19→10), 75% search acceleration
- **Tool Integration**: 10 tools with AI-driven recommendations, $445k bounty potential

### **Avoid These Categories** (Low ROI):
- Reflected XSS, info disclosures, basic rate limiting issues

---

## 🔐 **ACCOUNTS & CREDENTIALS**

All credentials are configured via environment variables. See `.env.example` for the template.

```bash
# Copy the example and fill in your credentials
cp .env.example .env

# Required variables:
# HACKERONE_API_USERNAME - Your HackerOne username
# HACKERONE_API_TOKEN    - Your HackerOne API token
# POSTGRES_PASSWORD      - Database password
# DATABASE_URL           - Full database connection string
```

---

## 📋 **ESSENTIAL WORKFLOWS**

### **Phase 1: Target Selection**
```bash
./query_memory.sh programs          # Get high-value programs
groky "What vulnerabilities are common in [technology stack]?"
mcp__claude-flow__agent_spawn type:"scout-recon" name:"target-mapper"
```

### **Phase 2: Research** (Enhanced with Tool Intelligence)
```bash
./verify-tech.sh                    # MANDATORY: Run T.K.V.F. first
./vuln tools <id>                   # Get optimal tool selection for this vulnerability
./vuln research <id>                # Create automated workflow with agent coordination
mcp__claude-flow__agent_spawn type:"prior-art-researcher" name:"duplicate-checker"
./vuln find "similar vulnerability pattern"  # Check for duplicates
```

### **Phase 3: Development & Submission**
```bash
./vuln next <id>                    # Get next guided research action
./vuln store-quick                   # Store with complete metadata
./vuln sync                          # Update all systems
groky "Review this PoC for accuracy" # Expert validation
mcp__claude-flow__agent_spawn type:"critical-validator" name:"final-check"  # Automated validation
./vuln update <id> status submitted  # Mark as submitted
```

---

## 🔧 **TROUBLESHOOTING**

### **Common Issues & Fixes**:
```bash
# Qdrant connectivity issues
docker-compose restart qdrant        # Restart Qdrant container
docker logs bbhk-qdrant              # Check logs
curl http://localhost:6333/health    # Test API

# Database sync issues
./vuln validate                      # Check consistency
./vuln sync                          # Full synchronization

# MCP server issues
claude mcp list                      # Verify active servers
# Check .mcp.json and .claude/settings.local.json

# Missing dependencies
./scripts/install_focused_tools_kali.sh
pip install mcp-server-qdrant        # For Qdrant MCP
```

### **Docker Compose Quick Reference**:
```bash
# Start all services
docker-compose up -d

# Start specific service
docker-compose up -d qdrant          # Qdrant only
docker-compose up -d backend         # Backend API only

# View logs
docker-compose logs -f qdrant        # Follow Qdrant logs
docker-compose logs --tail 100       # Last 100 lines all services

# Stop services
docker-compose stop                  # Stop all
docker-compose stop qdrant           # Stop Qdrant only

# Restart services
docker-compose restart qdrant        # After config changes

# Check status
docker-compose ps                    # All services
docker-compose top                   # Process info

# Remove containers (keeps data)
docker-compose down

# Remove everything including volumes (⚠️ DATA LOSS)
docker-compose down -v

# Update images
docker-compose pull                  # Pull latest images
docker-compose up -d --build         # Rebuild and restart
```

---

## 📁 **TARGET ORGANIZATION**

**MANDATORY Structure**: Every target in `/hacks/TARGET_NAME/`
- `README.md` (summary)
- `*_findings_*.md` (technical details)  
- `*.html/*.txt` (evidence files)
- `poc_*.py` (exploit code)

---

## 🏆 **SUCCESS METRICS & GOALS**

### **Current Status**:
- **Total Vulnerabilities**: 39 documented patterns
- **Portfolio Value**: $2.65M minimum, $7.02M maximum potential
- **Active Pipeline**: 18 vulnerabilities ready for research/submission
- **Quality Improvement**: 95% false positive prevention through T.K.V.F.

### **Year 1 Target**: $150k through systematic, high-quality submissions

**Remember**: Quality > Quantity. One real vulnerability > 1000 false positives.

---

## 📚 **ADDITIONAL RESOURCES**

### **Technical Documentation**:
- **Data Architecture**: `/home/kali/bbhk/DATA_ARCHITECTURE_COMPLETE.md`
- **System Status**: `/home/kali/bbhk/SYSTEM_STATUS_CONSOLIDATED.md`
- **Attack Vectors**: `/home/kali/bbhk/ATTACK_VECTORS_COMPREHENSIVE_2025.md`
- **AI Expert Reviews**: `/home/kali/bbhk/AI_EXPERT_REVIEWS_CONSOLIDATED.md`
- **T.K.V.F. Quick Start**: `/home/kali/bbhk/TECHNOLOGY_VERIFICATION_QUICKSTART.md`
- **Complete Schemas**: `/home/kali/bbhk/VULNERABILITY_DATA_ARCHITECTURE_SECTION.md`

### **Memory Access Examples**:
```bash
# Comprehensive Methodology Framework v2.0
mcp__claude-flow__memory_usage action:"retrieve" key:"comprehensive_research_methodology_framework_v2" namespace:"bug_bounty_methodology"

# Kali Tools Integration & Mappings
mcp__claude-flow__memory_usage action:"retrieve" key:"kali_tools_methodology_integration" namespace:"bbhk_optimization"

# Attack Pattern Classification (OWASP 2024)
mcp__claude-flow__memory_usage action:"retrieve" key:"attack_pattern_classification_owasp_2024" namespace:"bug_bounty_methodology"

# Hive Mind Collective Intelligence Success
mcp__claude-flow__memory_usage action:"retrieve" key:"hive_mind_collective_intelligence_success_2025" namespace:"hive_achievements"

# AI agent specializations  
mcp__claude-flow__memory_usage action:"retrieve" key:"ai_agent_specialization_data" namespace:"bug_bounty_methodology"
```

**OPTIMIZED FOR CLAUDE CODE EFFICIENCY** - All essential commands front and center, technical details moved to referenced files, redundancy eliminated while preserving full functionality.