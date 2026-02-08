import dotenv from 'dotenv';

dotenv.config();

/** @type import('hardhat/config').HardhatUserConfig */
const config = {
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
        blockNumber: parseInt(process.env.FORK_BLOCK_NUMBER) || 20500000,
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
  // Module paths
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  }
};

export default config;