/**
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import "dotenv/config";
import { SmartAccount, AAWrapProvider, SendTransactionMode } from '@particle-network/aa/dist/esm/index.mjs';
import { createWalletClient, custom, encodeFunctionData } from "viem";
import { privateKeyToAccount } from "viem/accounts";

// Particle Network configuration
const PARTICLE_CONFIG = {
  projectId: process.env.PARTICLE_PROJECT_ID || 'your-project-id',
  clientKey: process.env.PARTICLE_CLIENT_KEY || 'your-client-key', 
  appId: process.env.PARTICLE_APP_ID || 'your-app-id',
};

// Chain ID mappings for different networks
const CHAIN_IDS = {
  sepolia: 11155111,
  baseSepolia: 84532,
  avalancheFuji: 43113,
};

/**
 * Creates a SmartAccount instance for the given EOA provider
 * @param {Object} eoaProvider - The EOA provider (from viem's privateKeyToAccount)
 * @param {string} chainName - The chain name (sepolia, baseSepolia, avalancheFuji)
 * @returns {SmartAccount} Configured SmartAccount instance
 */
export function createSmartAccount(eoaProvider, chainName) {
  const chainId = CHAIN_IDS[chainName];
  
  if (!chainId) {
    console.error(`❌ Unsupported chain: ${chainName}`);
    throw new Error(`Unsupported chain: ${chainName}`);
  }

  const smartAccount = new SmartAccount(eoaProvider, {
    projectId: PARTICLE_CONFIG.projectId,
    clientKey: PARTICLE_CONFIG.clientKey,
    appId: PARTICLE_CONFIG.appId,
    aaOptions: {
      accountContracts: {
        BICONOMY: [
          {
            version: '2.0.0',
            chainIds: [CHAIN_IDS.avalancheFuji, CHAIN_IDS.baseSepolia, CHAIN_IDS.sepolia],
          }
        ],
      }
    }
  });

  smartAccount.setSmartAccountContract({ name: 'BICONOMY', version: '2.0.0' });
  return smartAccount;
}

/**
 * Creates an AA-enabled wallet client using viem
 * @param {SmartAccount} smartAccount - The configured SmartAccount instance
 * @param {Object} chain - The viem chain object
 * @returns {Object} Wallet client with AA support
 */
export function createAAWalletClient(smartAccount, chain) {
  const aaProvider = new AAWrapProvider(smartAccount, SendTransactionMode.Gasless);
  
  return {
    aaProvider,
    smartAccount
  };
}

/**
 * Gets the smart account address
 * @param {SmartAccount} smartAccount - The SmartAccount instance
 * @returns {Promise<string>} The smart account address
 */
export async function getSmartAccountAddress(smartAccount) {
  const address = await smartAccount.getAddress();
  return address;
}

/**
 * Checks if the smart account is deployed
 * @param {SmartAccount} smartAccount - The SmartAccount instance  
 * @returns {Promise<boolean>} Whether the smart account is deployed
 */
export async function isSmartAccountDeployed(smartAccount) {
  const isDeployed = await smartAccount.isDeployed();
  return isDeployed;
}

/**
 * Deploys the smart account if not already deployed
 * @param {SmartAccount} smartAccount - The SmartAccount instance
 * @returns {Promise<string|null>} Transaction hash if deployed, null if already deployed
 */
export async function deploySmartAccountIfNeeded(smartAccount) {
  const isDeployed = await smartAccount.isDeployed();
  if (!isDeployed) {
    console.log("🚀 Deploying smart account...");
    const txHash = await smartAccount.deployWalletContract();
    console.log("🚀 Smart account deployed! Transaction hash:", txHash);
    return txHash;
  }
  return null;
}

/**
 * Comprehensive test function to verify smart account setup
 * @param {string} chainName - The chain to test (sepolia, baseSepolia, avalancheFuji)
 * @param {Object} account - The EOA account from viem
 */
export async function testSmartAccountSetup(chainName = 'sepolia', account) {
  console.log('\n🧪 ===== SMART ACCOUNT SETUP TEST =====');
  console.log(`🔗 Testing chain: ${chainName}`);
  console.log(`👤 EOA address: ${account.address}`);
  
  try {
    // Step 1: Validate configuration
    console.log('\n📋 Step 1: Validating configuration...');
    if (!PARTICLE_CONFIG.projectId || PARTICLE_CONFIG.projectId === 'your-project-id') {
      throw new Error('PARTICLE_PROJECT_ID not set in environment');
    }
    if (!PARTICLE_CONFIG.clientKey || PARTICLE_CONFIG.clientKey === 'your-client-key') {
      throw new Error('PARTICLE_CLIENT_KEY not set in environment');
    }
    if (!PARTICLE_CONFIG.appId || PARTICLE_CONFIG.appId === 'your-app-id') {
      throw new Error('PARTICLE_APP_ID not set in environment');
    }
    console.log('✅ Configuration valid');

    // Step 2: Create EOA provider
    console.log('\n🔧 Step 2: Creating EOA provider...');
    const eoaProvider = {
      request: async ({ method, params }) => {
        console.log(`📞 EOA Provider called: ${method}`);
        if (method === 'eth_accounts') {
          return [account.address];
        }
        if (method === 'eth_requestAccounts') {
          return [account.address];
        }
        if (method === 'eth_chainId') {
          return `0x${CHAIN_IDS[chainName].toString(16)}`;
        }
        if (method === 'net_version') {
          return CHAIN_IDS[chainName].toString();
        }
        if (method === 'personal_sign') {
          const [message, address] = params;
          return await account.signMessage({ message });
        }
        if (method === 'eth_signTypedData_v4') {
          const [address, typedData] = params;
          return await account.signTypedData(JSON.parse(typedData));
        }
        if (method === 'eth_sign') {
          const [address, message] = params;
          return await account.signMessage({ message });
        }
        console.warn(`⚠️  Unsupported method: ${method}, returning null`);
        return null;
      }
    };
    console.log('✅ EOA provider created');

    // Step 3: Create smart account
    console.log('\n🏗️  Step 3: Creating smart account...');
    const smartAccount = createSmartAccount(eoaProvider, chainName);

    // Step 4: Get smart account address
    console.log('\n📍 Step 4: Getting smart account address...');
    const smartAccountAddress = await getSmartAccountAddress(smartAccount);

    // Step 5: Check deployment status
    console.log('\n🔍 Step 5: Checking deployment status...');
    const isDeployed = await isSmartAccountDeployed(smartAccount);

    // Step 6: Get account info
    console.log('\n📊 Step 6: Getting account information...');
    try {
      const accountInfo = await smartAccount.getAccount();
      console.log('📊 Account info:', {
        address: accountInfo.address || 'N/A',
        owner: accountInfo.owner || 'N/A',
        chainId: accountInfo.chainId || 'N/A'
      });
    } catch (error) {
      console.log('⚠️  Could not get account info:', error.message);
    }

    // Step 7: Get owner address
    console.log('\n👤 Step 7: Getting owner address...');
    try {
      const owner = await smartAccount.getOwner();
      console.log(`👤 Owner address: ${owner}`);
      
      if (owner.toLowerCase() !== account.address.toLowerCase()) {
        console.warn('⚠️  Owner mismatch! Expected:', account.address, 'Got:', owner);
      } else {
        console.log('✅ Owner matches EOA address');
      }
    } catch (error) {
      console.log('⚠️  Could not get owner:', error.message);
    }

    // Summary
    console.log('\n📋 ===== TEST SUMMARY =====');
    console.log(`🔗 Chain: ${chainName} (${CHAIN_IDS[chainName]})`);
    console.log(`👤 EOA Address: ${account.address}`);
    console.log(`🏠 Smart Account: ${smartAccountAddress}`);
    console.log(`🚀 Deployed: ${isDeployed ? '✅ YES' : '❌ NO'}`);
    console.log(`🔧 Implementation: BICONOMY v2.0.0`);
    console.log(`💰 Gas Mode: Gasless (testnet)`);
    
    if (!isDeployed) {
      console.log('\n💡 Note: Smart account will be deployed automatically on first transaction');
    }
    
    console.log('\n🎉 Smart account setup test completed successfully!');
    return {
      chainName,
      chainId: CHAIN_IDS[chainName],
      eoaAddress: account.address,
      smartAccountAddress,
      isDeployed,
      smartAccount
    };

  } catch (error) {
    console.error('\n❌ Smart account setup test failed:');
    console.error('Error:', error.message);
    console.error('Stack:', error.stack);
    throw error;
  }
}

// Main execution block - runs when file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  console.log('🚀 Running AA Config Test...');
  
  async function main() {
    try {
      // Check if PRIVATE_KEY is set
      if (!process.env.PRIVATE_KEY) {
        console.error('❌ PRIVATE_KEY environment variable is required');
        console.log('💡 Set it in your .env file or run: PRIVATE_KEY=your-key node aa-config.js');
        process.exit(1);
      }

      // Create account from private key
      const account = privateKeyToAccount(process.env.PRIVATE_KEY);
      console.log(`🔑 Loaded EOA: ${account.address}`);

      // Test on all supported chains
      const chains = ['sepolia', 'baseSepolia', 'avalancheFuji'];
      const results = [];

      for (const chainName of chains) {
        try {
          console.log(`\n${'='.repeat(60)}`);
          console.log(`🔗 Testing ${chainName.toUpperCase()}`);
          console.log(`${'='.repeat(60)}`);
          
          const result = await testSmartAccountSetup(chainName, account);
          results.push({ chainName, success: true, result });
          
        } catch (error) {
          console.error(`❌ Failed to test ${chainName}:`, error.message);
          results.push({ chainName, success: false, error: error.message });
        }
      }

      // Final summary
      console.log('\n' + '='.repeat(80));
      console.log('🏁 FINAL TEST RESULTS');
      console.log('='.repeat(80));
      
      results.forEach(({ chainName, success, result, error }) => {
        if (success) {
          console.log(`✅ ${chainName}: Smart Account ${result.smartAccountAddress}`);
        } else {
          console.log(`❌ ${chainName}: ${error}`);
        }
      });

      const successCount = results.filter(r => r.success).length;
      console.log(`\n📊 Success Rate: ${successCount}/${results.length} chains`);
      
      if (successCount === results.length) {
        console.log('🎉 All tests passed! Smart account setup is working correctly.');
      } else {
        console.log('⚠️  Some tests failed. Check your Particle Network configuration.');
      }

    } catch (error) {
      console.error('❌ Main execution failed:', error.message);
      process.exit(1);
    }
  }

  main().catch(console.error);
}
