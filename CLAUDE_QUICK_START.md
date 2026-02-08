# 🤖 Claude/Claude-Flow Quick Start Guide

## For New Claude Sessions: Start Here!

### 🎯 Vulnerability Research (Priority #1)
```bash
# Templates & Guides Location
/home/kali/bbhk/VULNERABILITY_RESEARCH_TEMPLATE.md    # Step-by-step methodology
/home/kali/bbhk/HACKERONE_API_GUIDE.md               # API submission
/home/kali/bbhk/LESSONS_LEARNED_FIREBLOCKS.md        # Case study

# Latest Success
/home/kali/bbhk/docs/bb-sites/hackerone/programs/fireblocks_mpc/
└── Report #3303358 (Critical, $50k-$150k estimated)
```

### 🚀 Quick Commands
```bash
# Find vulnerability patterns
rg -i "rounds|iterations|security.*=.*[0-9]" --type c

# Submit to HackerOne
python3 submit_report_api.py

# Start new research
cp /home/kali/bbhk/VULNERABILITY_RESEARCH_TEMPLATE.md ./
```

### 📁 Key Paths
```
/home/kali/bbhk/                       # Root directory
├── VULNERABILITY_RESEARCH_TEMPLATE.md # Use this for new targets
├── HACKERONE_API_GUIDE.md            # API submission reference
├── LESSONS_LEARNED_FIREBLOCKS.md     # What worked
├── docs/INDEX.md                      # All documentation
└── docs/bb-sites/hackerone/programs/ # Program analyses
```

### 🎯 High-Value Targets
- Cryptographic libraries (reduced parameters)
- MPC/ZKP implementations
- Consensus protocols
- Key management systems

### 💰 Bounty Estimates
- CRITICAL crypto bugs: $50k-$250k
- HIGH severity: $10k-$50k
- API submission: 5 minutes

### 🔧 MCP Tools Available
```javascript
mcp__claude-flow__swarm_init        // AI coordination
mcp__context7__get-library-docs     // Documentation
mcp__qdrant-bbhk__qdrant-store     // Store findings
mcp__playwright__*                  // Browser automation
```

### ✅ Success Formula
1. Clone target repo
2. Search for reduced security parameters
3. AI-analyze suspicious code
4. Develop PoC
5. Submit via API
6. $$$

---

**Last Success**: Report #3303358 - Fireblocks MPC  
**Methodology**: AI-assisted analysis + automated submission  
**Time to Bounty**: ~8 hours → $50k-$150k

## Ready to find the next critical bug! 🚀