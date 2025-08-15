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

/**
 * @fileoverview Circle Gateway Setup with Dual Account Support (EOA + Account Abstraction)
 * 
 * This module provides unified setup for Circle Gateway contracts supporting both traditional 
 * EOA and Account Abstraction modes via Particle Network + Biconomy smart accounts.
 * 
 * For detailed architecture documentation, usage examples, and implementation details,
 * see README-AA.md in this directory.
 * 
 * @example
 * // EOA Mode
 * USE_SMART_ACCOUNT=false node deposit.js
 * 
 * @example  
 * // AA Mode (gasless)
 * USE_SMART_ACCOUNT=true node deposit.js
 */

import "dotenv/config";
import { createPublicClient, createWalletClient, getContract, http, erc20Abi, custom } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import * as chains from "viem/chains";
import { GatewayClient } from "./gateway-client.js";
import { gatewayWalletAbi, gatewayMinterAbi } from "./abis.js";
import { createSmartAccount, createAAWalletClient, getSmartAccountAddress } from "../config/aa-config.js";

// Configuration
const USE_SMART_ACCOUNT = process.env.USE_SMART_ACCOUNT === 'true';

// Contract addresses (same across all networks)
const ADDRESSES = {
  gatewayWallet: "0x0077777d7EBA4688BDeF3E311b846F25870A19B9",
  gatewayMinter: "0x0022222ABE238Cc2C7Bb1f21003F0a260052475B",
  usdc: {
    sepolia: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
    baseSepolia: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    avalancheFuji: "0x5425890298aed601595a70ab815c96711a31bc65",
  }
};

// Helper function to create EOA provider for AA mode
function createEOAProvider(account, chainId) {
  return {
    request: async ({ method, params }) => {
      switch (method) {
        case 'eth_accounts':
        case 'eth_requestAccounts':
          return [account.address];
        case 'eth_chainId':
          return `0x${chainId.toString(16)}`;
        case 'net_version':
          return chainId.toString();
        case 'personal_sign':
          const [message] = params;
          return await account.signMessage({ 
            message: typeof message === 'string' && message.startsWith('0x') 
              ? { raw: message } 
              : message 
          });
        case 'eth_signTypedData_v4':
          const [, typedData] = params;
          const parsedData = typeof typedData === 'string' ? JSON.parse(typedData) : typedData;
          return await account.signTypedData(parsedData);
        case 'eth_sign':
          const [, rawMessage] = params;
          return await account.signMessage({ message: { raw: rawMessage } });
        case 'eth_sendTransaction':
          console.log(`🔄 Delegating eth_sendTransaction to AA provider`);
          return null;
        default:
          console.warn(`⚠️  Unsupported method: ${method}, returning null`);
          return null;
      }
    }
  };
}

// Helper function to get transport for chain
const getTransport = (chainName) => 
  chainName === "baseSepolia" ? http("https://sepolia-preconf.base.org") : http();

// Sets up a client and contracts for the given chain and account
async function setup(chainName, account) {
  const chain = chains[chainName];
  const transport = getTransport(chainName);
  
  let client, walletClient, smartAccount, accountAddress;
  
  if (USE_SMART_ACCOUNT) {
    // AA Mode setup
    const eoaProvider = createEOAProvider(account, chain.id);
    smartAccount = createSmartAccount(eoaProvider, chainName);
    const aaSetup = createAAWalletClient(smartAccount);
    accountAddress = await getSmartAccountAddress(smartAccount);
    
    walletClient = createWalletClient({
      account: { address: accountAddress, type: 'json-rpc' },
      chain,
      transport: custom({
        request: async ({ method, params }) => {
          return await aaSetup.aaProvider.request({ method, params });
        }
      })
    });
    
    client = createPublicClient({ chain, transport });
    console.log(`Using Smart Account: ${accountAddress} (owner: ${account.address})`);
  } else {
    // EOA Mode setup
    client = createPublicClient({ chain, account, transport });
    walletClient = client;
    accountAddress = account.address;
    console.log(`Using EOA: ${accountAddress}`);
  }

  // Helper function to create contracts
  const createContracts = (readClient, writeClient) => ({
    usdc: getContract({ address: ADDRESSES.usdc[chainName], abi: erc20Abi, client: readClient }),
    gatewayWallet: getContract({ address: ADDRESSES.gatewayWallet, abi: gatewayWalletAbi, client: readClient }),
    gatewayMinter: getContract({ address: ADDRESSES.gatewayMinter, abi: gatewayMinterAbi, client: readClient }),
    usdcWrite: getContract({ address: ADDRESSES.usdc[chainName], abi: erc20Abi, client: writeClient }),
    gatewayWalletWrite: getContract({ address: ADDRESSES.gatewayWallet, abi: gatewayWalletAbi, client: writeClient }),
    gatewayMinterWrite: getContract({ address: ADDRESSES.gatewayMinter, abi: gatewayMinterAbi, client: writeClient }),
  });

  return {
    client,
    walletClient,
    smartAccount,
    accountAddress,
    name: chain.name,
    domain: GatewayClient.DOMAINS[chainName],
    currency: chain.nativeCurrency.symbol,
    ...createContracts(client, walletClient),
  };
}

// Create an account from the private key set in .env
export const account = privateKeyToAccount(process.env.PRIVATE_KEY);
console.log(`Using account: ${account.address}`);
console.log(`Smart Account mode: ${USE_SMART_ACCOUNT ? 'ENABLED' : 'DISABLED'}`);

// Set up clients and contracts for each chain (now async)
export const ethereum = await setup("sepolia", account);
export const base = await setup("baseSepolia", account);
export const avalanche = await setup("avalancheFuji", account);
