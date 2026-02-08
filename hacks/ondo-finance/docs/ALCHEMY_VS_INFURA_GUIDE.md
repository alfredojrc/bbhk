# 🔧 ALCHEMY VS INFURA - API PROVIDER COMPARISON
*For Ondo Finance Bug Bounty Testing - August 2025*

## 🎯 Quick Decision

**RECOMMENDATION**: Start with **ALCHEMY** for better reliability and accuracy
**BACKUP**: Also register for **INFURA** as fallback option

## 📊 Free Tier Comparison (2025)

| Feature | Alchemy | Infura |
|---------|---------|--------|
| **Monthly Limit** | 300M compute units | 100k requests/day (3M/month) |
| **Daily Limit** | None | 100,000 requests |
| **RPS (Requests/sec)** | ~0.67 RPS (40/min) | ~1.15 RPS |
| **Archival Data** | ✅ Yes (needed for forking) | ✅ Yes |
| **Applications** | 5 apps | Unlimited |
| **Credit Card Required** | ❌ No | ❌ No (✅ for L2) |

## 🚀 Setup Instructions

### Alchemy (Recommended)
1. **Register**: https://www.alchemy.com/
2. **Create App**: 
   - Network: Ethereum Mainnet
   - Name: "Ondo-Testing"
3. **Get API Key**: Dashboard → View Key
4. **Hardhat Config**:
```javascript
forking: {
  url: "https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY",
  blockNumber: 20500000 // Optional: pin to specific block
}
```

### Infura (Backup)
1. **Register**: https://infura.io/
2. **Create Project**: "Ondo-Testing"
3. **Get Project ID**: Settings → Project ID
4. **Hardhat Config**:
```javascript
forking: {
  url: "https://mainnet.infura.io/v3/YOUR_PROJECT_ID",
  blockNumber: 20500000
}
```

## ⚡ Performance Comparison

### Data Accuracy (Critical for Testing)
- **Alchemy**: 0 errors in 1M queries ✅
- **Infura**: 705 errors in 1M queries ⚠️

### Speed
- **Alchemy**: 39.96ms average latency
- **Infura**: 38.18ms average latency (4% faster)

### Uptime
- **Alchemy**: Multiple 100% uptime months
- **Infura**: 99.91-100% uptime

## 💰 When You Hit Limits

### Upgrading from Free Tier

**Alchemy Growth Plan**: $49/month
- 400M compute units
- 15 applications

**Infura Developer Plan**: $225/month
- 3M requests/day
- Priority support

### Alternative: ZMOK
- **Free**: 50M requests/month (69.4 RPS!)
- **URL**: https://zmok.io/
- Consider if you need high volume

## 🔨 Hardhat Optimization Tips

### 1. Enable Block Pinning (20x faster)
```javascript
forking: {
  url: "YOUR_URL",
  blockNumber: 20500000, // Pin to specific block
  enabled: true
}
```

### 2. Cache Fork Data
```javascript
hardhat: {
  forking: {
    url: "YOUR_URL",
    blockNumber: 20500000,
    // Cache responses
    cachePath: ".hardhat-fork-cache"
  }
}
```

### 3. Use Multiple Providers (Failover)
```javascript
const ALCHEMY_URL = process.env.ALCHEMY_URL;
const INFURA_URL = process.env.INFURA_URL;

forking: {
  url: ALCHEMY_URL || INFURA_URL || "https://eth.public-rpc.com",
}
```

## 🎯 For Ondo Finance Testing

### Why We Need Archival Data
- Fork historical state
- Access past contract storage
- Replay transactions
- Test at specific blocks (e.g., during USDC depeg)

### Recommended Setup
1. **Primary**: Alchemy (accuracy matters for PoCs)
2. **Backup**: Infura (if Alchemy hits limits)
3. **High Volume**: ZMOK (if extensive fuzzing)

### Environment Variables (.env)
```bash
# Primary
ALCHEMY_API_KEY=your_alchemy_key_here
ALCHEMY_URL=https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}

# Backup
INFURA_PROJECT_ID=your_infura_id_here
INFURA_URL=https://mainnet.infura.io/v3/${INFURA_PROJECT_ID}

# Fork block (optional)
FORK_BLOCK_NUMBER=20500000
```

### Hardhat Config (hardhat.config.js)
```javascript
require('dotenv').config();

module.exports = {
  networks: {
    hardhat: {
      forking: {
        url: process.env.ALCHEMY_URL || process.env.INFURA_URL,
        blockNumber: parseInt(process.env.FORK_BLOCK_NUMBER) || undefined,
        enabled: true
      }
    }
  }
};
```

## ⚠️ Common Issues & Solutions

### Rate Limiting
- **Symptom**: "429 Too Many Requests"
- **Solution**: Add delay between tests or upgrade plan

### Archival Data Access
- **Symptom**: "Missing trie node" errors
- **Solution**: Both free tiers include archival data ✅

### Slow Fork Performance
- **Symptom**: Tests taking forever
- **Solution**: Pin to specific block number

## 📋 Action Items

1. [ ] Register for Alchemy account
2. [ ] Create Ethereum Mainnet app
3. [ ] Copy API key
4. [ ] Register for Infura (backup)
5. [ ] Create .env file with keys
6. [ ] Configure hardhat.config.js
7. [ ] Test fork with: `npx hardhat node --fork`

## 🔗 Quick Links

- **Alchemy Dashboard**: https://dashboard.alchemy.com/
- **Infura Dashboard**: https://infura.io/dashboard
- **Hardhat Forking Docs**: https://hardhat.org/hardhat-network/docs/guides/forking-other-networks
- **ZMOK (Alternative)**: https://zmok.io/

---
*Choose Alchemy for reliability, Infura for speed, or both for redundancy!*