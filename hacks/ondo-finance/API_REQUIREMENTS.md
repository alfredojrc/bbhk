# 🔑 API REQUIREMENTS - CRITICAL FOR EXECUTION

## 🚨 PRIORITY 1: BLOCKING APIs (GET TODAY!)

### 1. ETHERSCAN API ⭐⭐⭐⭐⭐
**Status**: ❌ CRITICAL BLOCKER - Only have placeholder  
**Purpose**: Download contract source code and ABIs  
**Get it from**: https://etherscan.io/apis  
**Free tier**: 5 calls/sec, 100k calls/day  
**What we need**: 
- Contract source code for all 39 in-scope contracts
- ABIs for interaction scripts
- Constructor arguments and proxy implementations
- Event logs for historical analysis

```bash
# After you get it, update:
echo "ETHERSCAN_API_KEY=YOUR_KEY_HERE" >> .env
```

### 2. INFURA API (Backup RPC) ⭐⭐⭐⭐
**Status**: ❌ Need for redundancy  
**Purpose**: Backup for Alchemy, different block states  
**Get it from**: https://infura.io/  
**Free tier**: 100k requests/day  
**What we need**:
- Mainnet RPC endpoint
- Archive node access for historical blocks
- WebSocket for event monitoring

```bash
INFURA_PROJECT_ID=YOUR_PROJECT_ID
INFURA_URL=https://mainnet.infura.io/v3/YOUR_PROJECT_ID
```

## 📊 PRIORITY 2: DATA APIS (FOR ATTACK VECTORS)

### 3. COINGECKO API ⭐⭐⭐⭐
**Status**: ❌ Need for price monitoring  
**Purpose**: Track USDC depeg in real-time  
**Get it from**: https://www.coingecko.com/en/api  
**Free tier**: 10-30 calls/min  
**What we need**:
- USDC/USD historical prices (especially March 2023 depeg)
- OUSG, USDY price data
- Real-time price alerts

```javascript
// For depeg monitoring
const DEPEG_THRESHOLD = 0.95; // Alert when USDC < $0.95
```

### 4. DEFILAMA API ⭐⭐⭐
**Status**: ❌ Need for TVL analysis  
**Purpose**: Track Ondo protocol TVL and liquidity  
**Get it from**: https://defillama.com/docs/api  
**Free tier**: Open API, no key needed  
**What we need**:
- Ondo Finance TVL ($500M+)
- Pool liquidity for empty market attacks
- Historical TVL for pattern analysis

### 5. THE GRAPH API ⭐⭐⭐
**Status**: ❌ Need for efficient queries  
**Purpose**: Query on-chain data without expensive RPC calls  
**Get it from**: https://thegraph.com/  
**What we need**:
- Ondo subgraph if exists
- Compound V2 (Flux) subgraph
- Event indexing for transactions

## 🎯 PRIORITY 3: SPECIALIZED APIS (FOR NOVEL ATTACKS)

### 6. FLASHBOTS API ⭐⭐⭐
**Status**: ❌ For MEV testing  
**Purpose**: Test MEV bundle griefing attacks  
**Get it from**: https://docs.flashbots.net/  
**What we need**:
- Bundle submission endpoint
- Searcher reputation building
- Block builder connections

```javascript
// For MEV griefing
const flashbotsProvider = new FlashbotsBundleProvider(
    provider,
    authSigner,
    'https://relay.flashbots.net'
);
```

### 7. CHAINLINK API ⭐⭐
**Status**: ❌ For oracle analysis  
**Purpose**: Monitor oracle updates and delays  
**Get it from**: https://data.chain.link/  
**What we need**:
- USDC/USD price feed data
- Oracle update frequencies
- Historical oracle failures

### 8. GITHUB API ⭐⭐
**Status**: ❌ For latest code  
**Purpose**: Get latest Ondo contracts directly  
**Get it from**: https://github.com/settings/tokens  
**What we need**:
- Access to ondoprotocol repos
- Commit history for patch analysis
- Issue tracker for known bugs

```bash
# Clone latest code
gh repo clone ondoprotocol/ondo-protocol
gh repo clone ondoprotocol/flux-finance
```

## 🔧 PRIORITY 4: NICE TO HAVE

### 9. IMMUNEFI API
**Status**: ❌ Would automate scope discovery  
**Purpose**: Programmatically fetch program details  
**Note**: May not have public API, scraping needed

### 10. ALCHEMY ENHANCED APIS
**Status**: ⚠️ Have basic, might need premium  
**Consider**: 
- Trace API for transaction debugging
- Mempool access for front-running tests
- Enhanced compute units for complex queries

## 📝 QUICK SETUP SCRIPT

```bash
#!/bin/bash
# After getting APIs, run this:

# Priority 1
echo "ETHERSCAN_API_KEY=YOUR_KEY" >> .env
echo "INFURA_PROJECT_ID=YOUR_ID" >> .env

# Priority 2  
echo "COINGECKO_API_KEY=YOUR_KEY" >> .env
echo "THEGRAPH_API_KEY=YOUR_KEY" >> .env

# Priority 3
echo "GITHUB_TOKEN=YOUR_TOKEN" >> .env
echo "FLASHBOTS_AUTH_KEY=YOUR_KEY" >> .env

# Test connections
node scripts/test-apis.js
```

## 🎯 WHAT TO ASK FOR

**Message to send:**
```
I need these APIs for the Ondo Finance bug bounty:

CRITICAL (Blocking everything):
1. Etherscan API - https://etherscan.io/apis
2. Infura - https://infura.io/

HIGH PRIORITY (For attack vectors):
3. CoinGecko - https://www.coingecko.com/en/api
4. The Graph - https://thegraph.com/

NICE TO HAVE:
5. GitHub token - https://github.com/settings/tokens
6. Flashbots access

Can you register and get API keys for at least #1 and #2?
The Etherscan API is the most critical - we can't download contracts without it.
```

## ⚡ IMPACT OF EACH API

| API | Without It | With It |
|-----|------------|---------|
| **Etherscan** | ❌ Can't download contracts = DEAD | ✅ Full source code analysis |
| **Infura** | ⚠️ Single point of failure | ✅ Redundant RPC, historical data |
| **CoinGecko** | ⚠️ Can't monitor depeg | ✅ Real-time price exploitation |
| **DeFiLlama** | ⚠️ Blind to TVL | ✅ Empty market detection |
| **The Graph** | ⚠️ Expensive RPC calls | ✅ Efficient data queries |
| **Flashbots** | ⚠️ No MEV testing | ✅ Bundle griefing attacks |

---

**Bottom Line**: Without Etherscan API, we're completely blocked. Get that FIRST!

*Per Grok4: "Stop planning, start hacking" - but we need APIs to hack!*