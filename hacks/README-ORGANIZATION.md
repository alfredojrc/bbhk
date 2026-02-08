# 📂 Bug Bounty Hacks Organization Guide (REORGANIZED)

**Purpose**: Define where all bug bounty program research goes  
**Date**: August 20, 2025 (Completely Reorganized)  
**Principle**: Active Research in `/hacks/` - Documentation in `/docs/`

## 🗺️ NEW UNIFIED STRUCTURE

```
hacks/                          # ALL ACTIVE BUG BOUNTY RESEARCH
├── README-ORGANIZATION.md      # This file - explains new structure
├── _scan_programs/            # Program intelligence & scanning tools
│   ├── program_scanner_v2.py
│   ├── TOP_PROGRAMS.yaml
│   └── REAL_API_OPEN_SOURCE_RANKING.md
├── hubspot/                   # HubSpot - ACTIVE (Report #3306949)
│   ├── CRITICAL_HUBSPOT_INTEL.md
│   ├── deliverables/
│   └── evidence_*/
├── chainlink/                 # Chainlink program (2.9GB research)
│   ├── repositories/
│   ├── findings/
│   └── deliverables/
├── fireblocks_mpc/           # Fireblocks MPC research
├── coinbase/                 # Coinbase program
├── grammarly/                # Grammarly program
├── metamask/                 # MetaMask program
├── nordsecurity/             # NordSecurity program
├── watson_group/             # Watson Group program
└── 8x8-bounty/              # 8x8 program
```

## 🎯 REORGANIZATION COMPLETE

### What Changed (August 20, 2025)
- **MOVED**: All programs from `/docs/bb-sites/hackerone/programs/` → `/hacks/`
- **UNIFIED**: Single location for all active research
- **CLEANED**: Removed 2.9GB of scattered documentation
- **RESULT**: `/hacks/` is now the command center (3.0GB of research)

## 📍 Where Things Go NOW

### Active Bug Bounty Research
**Location**: `/hacks/{program_name}/`

Each program folder contains:
- Research documentation (*.md files)
- Evidence collection (`evidence_*/`)
- Deliverables for submission (`deliverables/`)
- Scripts and tools specific to that target
- Claude Flow configurations (`.claude-flow/`)
- Swarm data (`.swarm/`)

### Program Intelligence Tools
**Location**: `/hacks/_scan_programs/`

Central tools for:
- Program scanning and analysis
- ROI calculations
- Attack vector identification
- Target prioritization

### Documentation (Static)
**Location**: `/docs/`
- API guides
- Methodology documentation
- Reference materials

## 🔄 Workflow for New Programs

1. **Create Program Directory**
   ```bash
   cd /home/kali/bbhk/hacks/
   mkdir new_program_name
   cd new_program_name
   ```

2. **Initialize Research**
   ```bash
   # Copy successful patterns from HubSpot
   cp ../hubspot/IDOR_PATTERN_PLAYBOOK.md ./
   # Start with program analysis
   python3 ../_scan_programs/program_scanner_v2.py
   ```

3. **Structure Your Research**
   ```
   new_program_name/
   ├── PROGRAM_INTEL.md           # Initial reconnaissance
   ├── findings/                  # Discovered vulnerabilities
   ├── evidence_YYYYMMDD_HHMMSS/ # Screenshots, logs, proof
   ├── deliverables/             # Files for HackerOne submission
   └── scripts/                  # Program-specific tools
   ```

## 📊 Current Program Status

### ✅ SUBMITTED
- **HubSpot** - Report #3306949 (Monitoring response)

### 🔄 ACTIVE RESEARCH
- **Chainlink** - 2.9GB of analysis
- **Fireblocks MPC** - Cryptographic analysis

### 📋 READY TO ANALYZE
- **Coinbase** - Initial recon complete
- **Grammarly** - Scope documented
- **MetaMask** - Web3 focus
- **NordSecurity** - VPN infrastructure
- **Watson Group** - AI/ML systems
- **8x8-bounty** - Communication platform

## 🚀 Benefits of New Structure

### Unified Workspace
- All programs in `/hacks/`
- No more searching multiple directories
- Consistent structure across all targets

### Better Organization
- Active research separated from static docs
- Each program self-contained
- Evidence and deliverables organized

### Efficient Workflow
```bash
# Quick program switch
cd /home/kali/bbhk/hacks/[tab-complete]

# See all targets
ls /home/kali/bbhk/hacks/

# Apply successful patterns
cp hubspot/IDOR_PATTERN_PLAYBOOK.md new_target/
```

## 🎯 Priority System

### Selection Criteria (Based on Scanner V2.1)
1. **🔴 High Priority** ($2,500+ per finding)
   - Ruby on Rails (open source, $50K max)
   - Django (open source, $25K max)
   - WordPress (open source, $25K max)

2. **🟡 Medium Priority** ($1,000-2,500 per finding)
   - Programs with IDOR patterns
   - Travel/booking platforms
   - Financial services

3. **🟢 Opportunistic** (<$1,000 per finding)
   - Quick wins
   - User enumeration
   - Information disclosure

## ⚡ Quick Commands

### Find Large Files
```bash
find /home/kali/bbhk/hacks -size +10M -type f | head -10
```

### Search Across All Programs
```bash
grep -r "IDOR" /home/kali/bbhk/hacks/ --include="*.md"
```

### Check Program Sizes
```bash
du -sh /home/kali/bbhk/hacks/* | sort -hr
```

### Latest Evidence
```bash
find /home/kali/bbhk/hacks -name "evidence_*" -type d | sort -r | head -5
```

## 📈 Success Metrics

### Current Stats
- **Total Programs**: 10
- **Active Research**: 3.0GB
- **Submitted Reports**: 1 (HubSpot #3306949)
- **Potential Value**: $120,800/month (Scanner V2.1)

### Goals
- **Week 1**: Submit findings for 2-3 programs
- **Month 1**: $25,000 in bounties
- **Month 6**: $100,000+ cumulative

## 🔗 Key Resources

### Tools
- [Program Scanner V2.1](/hacks/_scan_programs/program_scanner_v2.py)
- [HackerOne API Scripts](/scripts/)

### Successful Patterns
- [IDOR Pattern Playbook](/hacks/hubspot/IDOR_PATTERN_PLAYBOOK.md)
- [Open Source Ranking](/hacks/_scan_programs/REAL_API_OPEN_SOURCE_RANKING.md)

### References
- [CLAUDE.md](/home/kali/bbhk/CLAUDE.md) - Project guidance
- [Qdrant Patterns](mcp__qdrant-bbhk__qdrant-find) - Stored knowledge

---

**Remember**: `/hacks/` is your command center. Every program, every finding, every piece of evidence lives here. This is where money is made! 🎯