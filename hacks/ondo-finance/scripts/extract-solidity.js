import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Extract Solidity source code from Etherscan JSON format
 */

const contractsDir = path.join(__dirname, '../contracts');
const sourceDir = path.join(contractsDir, 'source');
const extractedDir = path.join(contractsDir, 'extracted');

// Create extracted directory if it doesn't exist
if (!fs.existsSync(extractedDir)) {
    fs.mkdirSync(extractedDir, { recursive: true });
}

// Process each contract file
const files = fs.readdirSync(sourceDir);

files.forEach(file => {
    if (!file.endsWith('.sol')) return;
    
    console.log(`Processing ${file}...`);
    
    const filePath = path.join(sourceDir, file);
    let content = fs.readFileSync(filePath, 'utf8');
    
    try {
        // Fix double curly braces if present
        if (content.startsWith('{{')) {
            content = content.substring(1);
        }
        if (content.endsWith('}}')) {
            content = content.substring(0, content.length - 1);
        }
        
        // Parse the JSON
        const jsonData = JSON.parse(content);
        
        // Extract all sources
        if (jsonData.sources) {
            Object.entries(jsonData.sources).forEach(([sourcePath, sourceData]) => {
                // Get just the filename from the path
                const fileName = path.basename(sourcePath);
                const outputPath = path.join(extractedDir, fileName);
                
                // Write the Solidity content
                fs.writeFileSync(outputPath, sourceData.content);
                console.log(`  ✅ Extracted ${fileName}`);
            });
        }
        
        // Also save the main contract (first source)
        const mainContractName = file.replace('.sol', '_main.sol');
        const mainOutputPath = path.join(extractedDir, mainContractName);
        const firstSource = Object.values(jsonData.sources)[0];
        if (firstSource) {
            fs.writeFileSync(mainOutputPath, firstSource.content);
            console.log(`  ✅ Main contract saved as ${mainContractName}`);
        }
        
    } catch (error) {
        console.error(`  ❌ Error processing ${file}:`, error.message);
    }
});

console.log('\n✅ Extraction complete! Check contracts/extracted/ directory');