# 🚀 ONDO FINANCE - QUICK REFERENCE CARD

## 🎯 CRITICAL INFO
**Max Bounty**: $1,000,000  
**Platform**: Immunefi  
**Complexity**: LOW (13 repos)  
**Expected**: $50-200k in 14 days  

## 📍 CONTRACT ADDRESSES
```
OUSGInstantManager: 0xF16c188c2D411627d39655A60409eC6707D3d5e8
USDYManager:        0x25A103A1D6AeC5967c1A4fe2039cdc514886b97e
OUSG Token:         0x1B19C19393e2d034D8Ff31ff34c81252FcBbee92
USDY Token:         0x96F6eF951840721AdBF46Ac996b59E0235CB985C
USDC:               0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
```

## 🔑 API KEYS
```bash
ALCHEMY_API_KEY=<YOUR_ALCHEMY_API_KEY>
ALCHEMY_URL=https://eth-mainnet.g.alchemy.com/v2/<YOUR_ALCHEMY_API_KEY>
FORK_BLOCK=20500000
```

## 💣 TOP ATTACK VECTORS

### 1. USDC Depeg (13.6% profit)
```javascript
// When USDC < $0.95
await OUSGInstantManager.mint(MAX_USDC)  // Get OUSG at 1:1
// Wait for repeg
await OUSGInstantManager.redeem(OUSG)    // Profit!
```

### 2. Compound V2 Precision Loss
```solidity
if (totalSupply == 0) {
    exchangeRate = attacker_controlled;  // Manipulate!
}
```

### 3. KYC Signature Replay
```solidity
// Reuse valid signature before expiry
// Create wrapper contract to bypass
```

### 4. BUIDL Integration Bug
- Balance sync issues
- Oracle delays
- Redemption queue manipulation

## 🛠️ QUICK COMMANDS

### Test Fork
```bash
node test-fork.js
```

### Run Vulnerability Test
```bash
node test/001-usdc-depeg-test.js
```

### Static Analysis
```bash
slither contracts/OUSGInstantManager.sol
mythril analyze contracts/OUSGInstantManager.sol
```

### Start Hardhat Fork
```bash
npx hardhat node --fork $ALCHEMY_URL
```

## 📊 VULNERABILITY STATS 2025

| Type | Losses | Bounty Range |
|------|--------|--------------|
| Oracle Manipulation | $38.9M | $10-100k |
| RWA Exploits | $14.6M | $20-200k |
| Front-End | $50M+ | $50-500k |
| Vault Logic | $9.5M | $30-300k |

## ⚡ EXPLOIT PATTERNS

### Oracle Manipulation
```
Flash Loan → Manipulate Pool → Inflate Price → Profit
```

### Reentrancy (Advanced)
```
withdrawBalance() → msg.sender.call → transfer() → Drain
```

### Vault Inflation
```
Donate → Inflate Rate → Mint Cheap → Redeem High
```

## 🎯 SUCCESS METRICS

**Conservative**: 2-3 Medium = $20-30k (70%)  
**Realistic**: 1 High = $50k+ (50%)  
**Optimistic**: 1 Critical = $200k+ (30%)  
**Expected Value**: $102.5k  

## ⏰ TIMELINE

Days 1-4: Known vulnerabilities (USDC depeg)  
Days 5-8: Compound V2 patterns  
Days 9-12: Novel attacks (BUIDL, KYC)  
Days 13-14: PoC & submission  

## 🚨 CRITICAL REMINDERS

1. **NEVER test on mainnet**
2. **Always use local fork**
3. **KYC required for payment**
4. **Follow Immunefi rules**
5. **Document everything**

## 📱 CONTACTS

HackerOne: @<YOUR_H1_USERNAME>  
Gmail: <YOUR_EMAIL>  
Token: <YOUR_HACKERONE_TOKEN>  

## 📈 PROGRESS: 85% COMPLETE

✅ Research complete  
✅ API configured  
✅ Tools installed  
✅ Vulnerabilities analyzed  
✅ AI review doc created  
⏳ Etherscan API needed  
⏳ Full PoC development  

---
*Last Updated: 2025-08-24 17:20*