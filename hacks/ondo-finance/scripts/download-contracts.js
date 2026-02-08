import { ethers } from 'ethers';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

/**
 * DOWNLOAD ALL ONDO FINANCE CONTRACTS
 * Based on Grok4 feedback - STOP PLANNING, START DOING!
 */

const CONTRACTS = {
    // Core contracts
    OUSGInstantManager: "0xF16c188c2D411627d39655A60409eC6707D3d5e8",
    USDYManager: "0x25A103A1D6AeC5967c1A4fe2039cdc514886b97e",
    OUSG: "0x1B19C19393e2d034D8Ff31ff34c81252FcBbee92",
    USDY: "0x96F6eF951840721AdBF46Ac996b59E0235CB985C",
    
    // Add more from Immunefi scope (39 total)
    // These need to be discovered from Etherscan
};

async function downloadContract(name, address) {
    const apiKey = process.env.ETHERSCAN_API_KEY;
    
    if (!apiKey || apiKey === 'placeholder_replace_with_real_key') {
        console.error('❌ ETHERSCAN_API_KEY not set! Get it from https://etherscan.io/apis');
        process.exit(1);
    }
    
    try {
        // Get contract ABI
        const abiUrl = `https://api.etherscan.io/api?module=contract&action=getabi&address=${address}&apikey=${apiKey}`;
        const abiResponse = await fetch(abiUrl);
        const abiData = await abiResponse.json();
        
        if (abiData.status === '1') {
            const abiPath = path.join('contracts', 'abis', `${name}.json`);
            fs.mkdirSync(path.dirname(abiPath), { recursive: true });
            fs.writeFileSync(abiPath, JSON.stringify(JSON.parse(abiData.result), null, 2));
            console.log(`✅ Downloaded ABI for ${name}`);
        } else {
            console.error(`❌ Failed to get ABI for ${name}: ${abiData.result}`);
        }
        
        // Get contract source code
        const sourceUrl = `https://api.etherscan.io/api?module=contract&action=getsourcecode&address=${address}&apikey=${apiKey}`;
        const sourceResponse = await fetch(sourceUrl);
        const sourceData = await sourceResponse.json();
        
        if (sourceData.status === '1' && sourceData.result[0].SourceCode) {
            const sourcePath = path.join('contracts', 'source', `${name}.sol`);
            fs.mkdirSync(path.dirname(sourcePath), { recursive: true });
            
            // Handle flattened vs multi-file source
            let sourceCode = sourceData.result[0].SourceCode;
            if (sourceCode.startsWith('{{')) {
                // Multi-file, extract main contract
                const sources = JSON.parse(sourceCode.slice(1, -1));
                const mainFile = Object.keys(sources.sources).find(f => f.includes(name));
                sourceCode = sources.sources[mainFile]?.content || sourceCode;
            }
            
            fs.writeFileSync(sourcePath, sourceCode);
            console.log(`✅ Downloaded source for ${name}`);
            
            // Save metadata
            const metadata = {
                name,
                address,
                compiler: sourceData.result[0].CompilerVersion,
                optimization: sourceData.result[0].OptimizationUsed === '1',
                runs: sourceData.result[0].Runs,
                constructorArgs: sourceData.result[0].ConstructorArguments,
                implementation: sourceData.result[0].Implementation,
                proxy: sourceData.result[0].Proxy === '1'
            };
            
            const metadataPath = path.join('contracts', 'metadata', `${name}.json`);
            fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
            fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
            
        } else {
            console.error(`❌ Failed to get source for ${name}: Not verified or error`);
        }
        
        // Rate limit to avoid Etherscan throttling
        await new Promise(resolve => setTimeout(resolve, 250));
        
    } catch (error) {
        console.error(`❌ Error downloading ${name}: ${error.message}`);
    }
}

async function findAllContracts() {
    console.log('🔍 Discovering all Ondo Finance contracts...');
    
    // This would normally query Immunefi API or parse their page
    // For now, using known contracts
    
    // TODO: Add contract discovery logic
    // - Parse Immunefi scope page
    // - Query GitHub for contract list
    // - Use Etherscan to find related contracts
    
    return CONTRACTS;
}

async function main() {
    console.log('🚀 DOWNLOADING ONDO FINANCE CONTRACTS');
    console.log('📍 Based on Grok4 feedback: STOP PLANNING, START HACKING!\n');
    
    const contracts = await findAllContracts();
    const contractList = Object.entries(contracts);
    
    console.log(`📦 Found ${contractList.length} contracts to download\n`);
    
    for (const [name, address] of contractList) {
        await downloadContract(name, address);
    }
    
    console.log('\n✅ Contract download complete!');
    console.log('📝 Next steps:');
    console.log('1. Run: slither contracts/source/*.sol');
    console.log('2. Run: myth analyze contracts/source/OUSGInstantManager.sol');
    console.log('3. Build PoCs for novel attack vectors');
}

main().catch(console.error);