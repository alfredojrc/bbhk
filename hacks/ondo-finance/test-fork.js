import { ethers } from 'ethers';
import dotenv from 'dotenv';

dotenv.config();

async function testFork() {
    console.log("🔍 Testing Alchemy Fork Connection...");
    
    const provider = new ethers.JsonRpcProvider(process.env.ALCHEMY_URL);
    
    try {
        // Test basic connection
        const blockNumber = await provider.getBlockNumber();
        console.log(`✅ Connected to Ethereum Mainnet`);
        console.log(`📦 Current block: ${blockNumber}`);
        
        // Test getting Ondo Finance contract data
        const ousqAddress = "0x1B19C19393e2d034D8Ff31ff34c81252FcBbee92"; // OUSG Token
        const usdyAddress = "0x96F6eF951840721AdBF46Ac996b59E0235CB985C"; // USDY Token
        
        // Get contract bytecode to verify existence
        const ousqCode = await provider.getCode(ousqAddress);
        const usdyCode = await provider.getCode(usdyAddress);
        
        console.log(`\n🏦 Ondo Finance Contracts:`);
        console.log(`OUSG Token: ${ousqCode.length > 2 ? '✅ Deployed' : '❌ Not found'}`);
        console.log(`USDY Token: ${usdyCode.length > 2 ? '✅ Deployed' : '❌ Not found'}`);
        
        // Get some mainnet state for testing
        const usdcAddress = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // USDC
        const usdcBalance = await provider.getBalance(usdcAddress);
        console.log(`\n💰 USDC Contract ETH balance: ${ethers.formatEther(usdcBalance)} ETH`);
        
        // Test getting a specific block (for forking)
        const forkBlock = parseInt(process.env.FORK_BLOCK_NUMBER) || 20500000;
        const block = await provider.getBlock(forkBlock);
        console.log(`\n🔗 Fork block ${forkBlock}:`);
        console.log(`   Timestamp: ${new Date(block.timestamp * 1000).toISOString()}`);
        console.log(`   Transactions: ${block.transactions.length}`);
        
        console.log("\n✅ Alchemy API working perfectly!");
        console.log("📝 Ready to start vulnerability testing on Ondo Finance");
        
    } catch (error) {
        console.error("❌ Error:", error.message);
    }
}

testFork();