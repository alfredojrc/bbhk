# 📚 HackerOne Bug Bounty Programs Index

**Last Updated**: August 17, 2025  
**Data Source**: HackerOne HACKER API (`/v1/hackers/programs`)  
**Organization**: All program analyses stored in `/docs/bb-sites/hackerone/programs/`

## 📁 Directory Structure

```
docs/bb-sites/hackerone/
├── PROGRAMS-INDEX.md           # This file - master index
├── hackerone-api-explore.md    # API exploration documentation
└── programs/                    # Individual program analyses
    ├── coinbase/               # Coinbase program
    │   ├── coinbase-program-analysis.md
    │   ├── coinbase-complete-exploration.md
    │   └── coinbase_program_*.json
    ├── shopify/                # Future: Shopify analysis
    ├── paypal/                 # Future: PayPal analysis
    └── ...                     # Other programs
```

## 🎯 Analyzed Programs

### ✅ Completed Analyses

#### 1. Coinbase (`/programs/coinbase/`)
- **Status**: ✅ Complete Analysis
- **Program ID**: 104
- **Handle**: coinbase
- **Key Features**:
  - Up to $1M bounties (standard)
  - $5M for smart contract bugs
  - Gold Standard Safe Harbor
  - 10+ years old program
- **Files**:
  - `coinbase-program-analysis.md` - Initial analysis
  - `coinbase-complete-exploration.md` - Full detailed exploration
  - `coinbase_program_20250817_200908.json` - Raw API data

### 📋 Programs to Analyze

Based on our 570 programs from HACKER API, priority targets:

#### High-Value Programs ($50K+ max bounty)
- [ ] Shopify (`shopify`)
- [ ] Spotify (`spotify`)
- [ ] Airbnb (`airbnb`)
- [ ] PayPal (`paypal`)
- [ ] Snapchat (`snapchat`)
- [ ] Slack (`slack`)
- [ ] Stripe (`stripe`)
- [ ] Netflix (`netflix`)
- [ ] GitHub (`github`)

#### Government Programs
- [ ] U.S. Dept of Defense (`deptofdefense`)
- [ ] European Commission (`ec-digit`)

#### Crypto/Blockchain Focus
- [ ] Crypto.com (`crypto`)
- [ ] Binance (`binance`)
- [ ] Kraken (`kraken`)
- [ ] OpenSea (`opensea`)

#### AI/Tech Companies
- [ ] Anthropic VDP (`anthropic-vdp`)
- [ ] OpenAI (`openai`)
- [ ] Microsoft (`microsoft`)

## 📊 Analysis Template

Each program analysis should include:

### Required Sections
1. **Program Overview**
   - ID, Handle, Name
   - Status (open/closed)
   - Age of program
   
2. **Data Structure**
   - JSON structure from API
   - Available fields
   - User-specific data

3. **Reward Structure**
   - Bounty tiers
   - Maximum payouts
   - Special programs

4. **Scope Analysis**
   - In-scope assets
   - Out-of-scope items
   - Special focus areas

5. **Strategic Insights**
   - High-value targets
   - What the program values
   - Best practices

### File Naming Convention
```
programs/{handle}/
├── {handle}-program-analysis.md      # Initial analysis
├── {handle}-complete-exploration.md  # Detailed exploration
├── {handle}_program_{timestamp}.json # Raw API data
└── {handle}-notes.md                # Additional research notes
```

## 🔧 How to Add New Program Analysis

1. **Create program directory**:
   ```bash
   mkdir -p docs/bb-sites/hackerone/programs/{program_handle}
   ```

2. **Fetch program data**:
   ```python
   # Use scripts/explore-coinbase-hacker-api.py as template
   # Modify for new program
   ```

3. **Create analysis files**:
   - Start with `{handle}-program-analysis.md`
   - Add detailed exploration
   - Save raw JSON data

4. **Update this index**:
   - Add to completed analyses
   - Include key findings
   - Link to files

## 📈 Statistics from 570 Programs

### Program Distribution
- **Total Programs**: 570
- **Open for Submissions**: 459 (80%)
- **Offering Bounties**: 294 (52%)
- **Allow Bounty Splitting**: 237 (42%)
- **Gold Standard Safe Harbor**: ~150 (26%)

### Top Categories
1. **Financial Services**: ~80 programs
2. **Cryptocurrency**: ~60 programs
3. **E-commerce**: ~50 programs
4. **Social Media**: ~40 programs
5. **Government**: ~20 programs

## 🚀 Next Steps

1. **Prioritize High-Value Programs**
   - Focus on $50K+ max bounty programs
   - Analyze crypto/blockchain programs
   - Study government programs

2. **Automate Analysis**
   - Create script to batch analyze programs
   - Extract scope automatically from policy
   - Generate comparison reports

3. **Track Changes**
   - Monitor program updates
   - Track scope changes
   - Alert on new programs

## 📝 Notes

- All data from HACKER API (FREE)
- No Enterprise API needed ($0 cost)
- Updated via `/v1/hackers/programs` endpoint
- Real data only - no fake/test data

---

**Remember**: Use HACKER API only (`/v1/hackers/*`) - Never use Enterprise API!