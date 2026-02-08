import dotenv from 'dotenv';
import "@nomicfoundation/hardhat-toolbox";

dotenv.config();

/** @type import('hardhat/config').HardhatUserConfig */
export default {
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  networks: {
    hardhat: {
      forking: {
        url: process.env.ALCHEMY_URL || process.env.INFURA_URL,
        blockNumber: parseInt(process.env.FORK_BLOCK_NUMBER) || undefined,
        enabled: true
      },
      // Accounts with ETH for testing
      accounts: {
        mnemonic: "test test test test test test test test test test test junk",
        count: 10,
        accountsBalance: "10000000000000000000000" // 10,000 ETH each
      }
    },
    localhost: {
      url: "http://127.0.0.1:8545"
    }
  },
  // For gas reporting
  gasReporter: {
    enabled: true,
    currency: "USD",
    gasPrice: 20
  },
  // Etherscan verification (if needed later)
  etherscan: {
    apiKey: {
      mainnet: "YOUR_ETHERSCAN_API_KEY"
    }
  }
};