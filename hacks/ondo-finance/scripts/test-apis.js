import dotenv from 'dotenv';
import { ethers } from 'ethers';

dotenv.config();

/**
 * TEST ALL APIs - Verify they work before proceeding
 * Based on Grok4: "Validate everything or fail"
 */

async function testEtherscan() {
    console.log('\n🔍 Testing Etherscan API...');
    const apiKey = process.env.ETHERSCAN_API_KEY;
    
    if (!apiKey || apiKey === 'placeholder_replace_with_real_key') {
        console.error('❌ ETHERSCAN_API_KEY not set or still placeholder!');
        return false;
    }
    
    try {
        // Test with OUSG contract
        const testAddress = '0x1B19C19393e2d034D8Ff31ff34c81252FcBbee92';
        const url = `https://api.etherscan.io/api?module=contract&action=getabi&address=${testAddress}&apikey=${apiKey}`;
        
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.status === '1') {
            console.log('✅ Etherscan API working!');
            console.log(`   Can download contracts: YES`);
            return true;
        } else {
            console.error('❌ Etherscan API failed:', data.result);
            return false;
        }
    } catch (error) {
        console.error('❌ Etherscan API error:', error.message);
        return false;
    }
}

async function testInfura() {
    console.log('\n🔍 Testing Infura API...');
    const projectId = process.env.INFURA_PROJECT_ID;
    
    if (!projectId) {
        console.warn('⚠️  INFURA_PROJECT_ID not set - using Alchemy only');
        return false;
    }
    
    try {
        const provider = new ethers.JsonRpcProvider(
            `https://mainnet.infura.io/v3/${projectId}`
        );
        
        const blockNumber = await provider.getBlockNumber();
        console.log('✅ Infura API working!');
        console.log(`   Current block: ${blockNumber}`);
        
        // Test archive access (SVB depeg block)
        const depegBlock = await provider.getBlock(16800000);
        if (depegBlock) {
            console.log(`   Archive access: YES (depeg block accessible)`);
        }
        
        return true;
    } catch (error) {
        console.error('❌ Infura API error:', error.message);
        return false;
    }
}

async function testCoinGecko() {
    console.log('\n🔍 Testing CoinGecko API...');
    
    try {
        // Free tier doesn't always need API key
        const url = 'https://api.coingecko.com/api/v3/simple/price?ids=usd-coin&vs_currencies=usd';
        const response = await fetch(url);
        const data = await response.json();
        
        if (data['usd-coin']) {
            const usdcPrice = data['usd-coin'].usd;
            console.log('✅ CoinGecko API working!');
            console.log(`   USDC Price: $${usdcPrice}`);
            
            // Check for depeg
            if (usdcPrice < 0.95) {
                console.log('   🚨 DEPEG DETECTED! Time to exploit!');
            }
            
            return true;
        }
    } catch (error) {
        console.warn('⚠️  CoinGecko API error:', error.message);
        return false;
    }
}

async function testDeFiLlama() {
    console.log('\n🔍 Testing DeFiLlama API...');
    
    try {
        // No API key needed
        const url = 'https://api.llama.fi/protocol/ondo-finance';
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.tvl) {
            console.log('✅ DeFiLlama API working!');
            console.log(`   Ondo TVL: $${(data.tvl[data.tvl.length - 1].totalLiquidityUSD / 1e6).toFixed(2)}M`);
            return true;
        }
    } catch (error) {
        console.warn('⚠️  DeFiLlama API not critical, continuing...');
        return false;
    }
}

async function testAlchemy() {
    console.log('\n🔍 Testing Alchemy API (existing)...');
    
    try {
        const provider = new ethers.JsonRpcProvider(process.env.ALCHEMY_URL);
        const blockNumber = await provider.getBlockNumber();
        
        // Test contract access
        const ousgCode = await provider.getCode('0x1B19C19393e2d034D8Ff31ff34c81252FcBbee92');
        
        console.log('✅ Alchemy API working!');
        console.log(`   Current block: ${blockNumber}`);
        console.log(`   Contract access: ${ousgCode.length > 2 ? 'YES' : 'NO'}`);
        
        return true;
    } catch (error) {
        console.error('❌ Alchemy API error:', error.message);
        return false;
    }
}

async function main() {
    console.log('🚀 TESTING ALL APIs FOR ONDO FINANCE HACK\n');
    console.log('Per Grok4: "Stop planning, start hacking!"');
    console.log('But first, we need working APIs...\n');
    
    const results = {
        etherscan: await testEtherscan(),
        alchemy: await testAlchemy(),
        infura: await testInfura(),
        coingecko: await testCoinGecko(),
        defillama: await testDeFiLlama()
    };
    
    console.log('\n📊 API STATUS SUMMARY');
    console.log('=' * 40);
    
    // Critical APIs
    if (!results.etherscan) {
        console.log('🚨 CRITICAL: Etherscan API not working - CANNOT PROCEED!');
        console.log('   Get it from: https://etherscan.io/apis');
    }
    
    if (!results.alchemy && !results.infura) {
        console.log('🚨 CRITICAL: No RPC provider working - CANNOT TEST!');
    }
    
    // Nice to have
    if (!results.coingecko) {
        console.log('⚠️  WARNING: CoinGecko not working - can\'t monitor USDC depeg');
    }
    
    // Ready to hack?
    const criticalApisWorking = results.etherscan && (results.alchemy || results.infura);
    
    if (criticalApisWorking) {
        console.log('\n✅ READY TO HACK! Critical APIs working.');
        console.log('📝 Next steps:');
        console.log('1. Run: node scripts/download-contracts.js');
        console.log('2. Run: slither contracts/source/*.sol');
        console.log('3. Build PoCs for novel attack vectors');
    } else {
        console.log('\n❌ NOT READY - Get missing APIs first!');
        console.log('Priority order:');
        console.log('1. Etherscan (CRITICAL)');
        console.log('2. Infura (backup RPC)');
        console.log('3. CoinGecko (price monitoring)');
    }
}

main().catch(console.error);