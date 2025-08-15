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

// Chain ID mappings for different networks
const CHAIN_IDS = {
  sepolia: 11155111,
  baseSepolia: 84532,
  avalancheFuji: 43113,
};

// Biconomy smart account configuration
const BICONOMY_CONFIG = {
  name: 'BICONOMY',
  version: '2.0.0',
  chainIds: Object.values(CHAIN_IDS),
};

// Particle Network configuration
const getParticleConfig = () => ({
  projectId: process.env.PARTICLE_PROJECT_ID || 'your-project-id',
  clientKey: process.env.PARTICLE_CLIENT_KEY || 'your-client-key', 
  appId: process.env.PARTICLE_APP_ID || 'your-app-id',
});

/**
 * Creates a SmartAccount instance for the given EOA provider
 * @param {Object} eoaProvider - The EOA provider (from viem's privateKeyToAccount)
 * @param {string} chainName - The chain name (sepolia, baseSepolia, avalancheFuji)
 * @returns {SmartAccount} Configured SmartAccount instance
 */
export function createSmartAccount(eoaProvider, chainName) {
  if (!CHAIN_IDS[chainName]) {
    throw new Error(`Unsupported chain: ${chainName}`);
  }

  const config = getParticleConfig();
  const smartAccount = new SmartAccount(eoaProvider, {
    ...config,
    aaOptions: {
      accountContracts: {
        [BICONOMY_CONFIG.name]: [{
          version: BICONOMY_CONFIG.version,
          chainIds: BICONOMY_CONFIG.chainIds,
        }],
      }
    }
  });

  smartAccount.setSmartAccountContract({
    name: BICONOMY_CONFIG.name,
    version: BICONOMY_CONFIG.version
  });
  return smartAccount;
}

/**
 * Creates an AA-enabled wallet client using viem
 * @param {SmartAccount} smartAccount - The configured SmartAccount instance
 * @returns {Object} Wallet client with AA support
 */
export function createAAWalletClient(smartAccount) {
  return {
    aaProvider: new AAWrapProvider(smartAccount, SendTransactionMode.Gasless),
    smartAccount
  };
}

/**
 * Gets the smart account address (direct passthrough)
 * @param {SmartAccount} smartAccount - The SmartAccount instance
 * @returns {Promise<string>} The smart account address
 */
export const getSmartAccountAddress = (smartAccount) => smartAccount.getAddress();

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

