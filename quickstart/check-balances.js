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

import { account, ethereum, base, avalanche } from "./setup.js";
import { GatewayClient } from "./gateway-client.js";

console.log("🔍 Balance Verification Script");
console.log("=" .repeat(50));

// Initialize Gateway client
const gatewayClient = new GatewayClient();

// Get account addresses
const accountAddress = ethereum.accountAddress;
const eoaAddress = account.address;

console.log(`📍 Account Information:`);
console.log(`   EOA Address: ${eoaAddress}`);
console.log(`   Account Address: ${accountAddress}`);
console.log(`   Smart Account Mode: ${ethereum.smartAccount ? 'ENABLED' : 'DISABLED'}`);
console.log();

// Check Gateway API balances
console.log("🌐 Gateway API Balances:");
console.log("-".repeat(30));

try {
  const { balances } = await gatewayClient.balances("USDC", accountAddress);
  
  if (balances.length === 0) {
    console.log("   No balances found");
  } else {
    for (const balance of balances) {
      const chainName = GatewayClient.CHAINS[balance.domain];
      console.log(`   ${chainName}: ${balance.balance} USDC`);
    }
  }
} catch (error) {
  console.error(`   Error fetching Gateway balances: ${error.message}`);
}

console.log();

// If using AA, also check EOA balances
if (ethereum.smartAccount) {
  console.log("👤 EOA Balances (for comparison):");
  console.log("-".repeat(30));
  
  try {
    const { balances: eoaBalances } = await gatewayClient.balances("USDC", eoaAddress);
    
    if (eoaBalances.length === 0) {
      console.log("   No EOA balances found");
    } else {
      for (const balance of eoaBalances) {
        const chainName = GatewayClient.CHAINS[balance.domain];
        console.log(`   ${chainName}: ${balance.balance} USDC`);
      }
    }
  } catch (error) {
    console.error(`   Error fetching EOA balances: ${error.message}`);
  }
  
  console.log();
}

// Check on-chain USDC balances directly
console.log("⛓️  On-Chain USDC Balances:");
console.log("-".repeat(30));

const chains = [
  { name: "Ethereum Sepolia", chain: ethereum },
  { name: "Base Sepolia", chain: base },
  { name: "Avalanche Fuji", chain: avalanche }
];

for (const { name, chain } of chains) {
  try {
    const balance = await chain.usdc.read.balanceOf([accountAddress]);
    const readableBalance = Number(balance) / 10 ** 6; // USDC has 6 decimals
    console.log(`   ${name}: ${readableBalance.toFixed(6)} USDC`);
  } catch (error) {
    console.error(`   ${name}: Error - ${error.message}`);
  }
}

console.log();

// If using AA, check delegation status
if (ethereum.smartAccount) {
  console.log("🔗 Delegation Status:");
  console.log("-".repeat(30));
  
  for (const { name, chain } of chains.slice(0, 2)) { // Only check source chains
    try {
      const isAuthorized = await chain.gatewayWallet.read.isAuthorizedForBalance([
        chain.usdc.address,
        accountAddress, // smart account as depositor
        eoaAddress      // EOA as delegate
      ]);
      console.log(`   ${name}: EOA authorized = ${isAuthorized ? '✅' : '❌'}`);
    } catch (error) {
      console.log(`   ${name}: Error checking delegation - ${error.message}`);
    }
  }
  
  console.log();
}

console.log("✅ Balance verification completed!");
