# 🎯 HackerOne Bug Bounty Documentation

**Purpose**: Comprehensive documentation of HackerOne bug bounty programs  
**Data Source**: HACKER API (`/v1/hackers/programs`)  
**Organization**: Structured analysis of programs for bug hunters

## 📁 Documentation Structure

```
hackerone/
├── README.md                    # This file - overview
├── PROGRAMS-INDEX.md           # Master index of all programs
├── hackerone-api-explore.md    # API exploration guide
└── programs/                    # Individual program analyses
    └── {program_handle}/       # One folder per program
        ├── analysis files
        ├── raw data (JSON)
        └── notes
```

## 🔍 Quick Navigation

### Core Documentation
- [**Programs Index**](./PROGRAMS-INDEX.md) - List of all analyzed programs
- [**API Exploration**](./hackerone-api-explore.md) - How to explore programs via API

### Program Analyses
- [**Coinbase**](./programs/coinbase/) - $1M standard, $5M smart contracts
- More programs coming...

## 📊 What We Document

For each bug bounty program, we capture:

### 1. Program Structure
- How data is organized in HACKER API
- Available fields and relationships
- User-specific information

### 2. Reward Information
- Bounty tiers and amounts
- Special programs or bonuses
- Payment methods and speed

### 3. Scope Details
- In-scope assets (domains, apps, IPs)
- Out-of-scope items
- Special focus areas

### 4. Strategic Analysis
- High-value targets
- Program priorities
- Best practices for submissions

## 🛠️ How to Use This Documentation

### For Bug Hunters
1. Check [PROGRAMS-INDEX.md](./PROGRAMS-INDEX.md) for analyzed programs
2. Read program-specific analysis before hunting
3. Focus on high-value targets identified

### For Researchers
1. Use API exploration guide to fetch new programs
2. Follow analysis template for consistency
3. Update index when adding new programs

### For Automation
1. Scripts in `/scripts/` for data fetching
2. JSON data stored with each program
3. Parseable markdown format

## 📈 Current Coverage

- **Programs Analyzed**: 1 (Coinbase)
- **Programs Available**: 570 via HACKER API
- **Coverage**: 0.2%
- **Goal**: Analyze top 50 programs

## 🚀 Contribution Guidelines

### Adding New Program Analysis

1. **Fetch Data**:
   ```python
   # Use HACKER API to get program
   GET /v1/hackers/programs
   ```

2. **Create Structure**:
   ```bash
   mkdir programs/{handle}
   ```

3. **Analyze & Document**:
   - Follow template in PROGRAMS-INDEX.md
   - Include all key sections
   - Save raw JSON data

4. **Update Index**:
   - Add to PROGRAMS-INDEX.md
   - Include summary and links

## ⚠️ Important Notes

### API Usage
- **ONLY use HACKER API** (`/v1/hackers/*`)
- **NEVER use Enterprise API** (costs $15K+/year)
- Free access for all bug hunters

### Data Accuracy
- All data from official HackerOne API
- No fake or test data
- Updated regularly

### Legal Compliance
- Respect program policies
- Follow responsible disclosure
- No unauthorized testing

## 📊 Statistics

From 570 programs available:
- **80%** accepting submissions
- **52%** offer bounties
- **42%** allow bounty splitting
- **26%** have Gold Standard Safe Harbor

## 🔗 Related Resources

### Internal
- [Main BBHK Documentation](/docs/)
- [API Reference](/docs/API-REFERENCE.md)
- [HACKER API Guide](/docs/HACKER-API-ONLY.md)

### External
- [HackerOne Platform](https://hackerone.com)
- [HackerOne Docs](https://docs.hackerone.com)
- [Hacker101](https://hacker101.com)

---

**Last Updated**: August 17, 2025  
**Maintainer**: BBHK Team  
**License**: For bug bounty research only