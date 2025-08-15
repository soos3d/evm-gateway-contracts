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

import { account, ethereum, base, avalanche } from "./lib/setup.js";
import { GatewayClient } from "./lib/gateway-client.js";
import { burnIntent, burnIntentTypedData } from "./lib/typed-data.js";
import { deploySmartAccountIfNeeded } from "./config/aa-config.js";

// Deploy smart accounts if needed (before any operations)
for (const chain of [ethereum, base, avalanche]) {
  if (chain.smartAccount) {
    try {
      await deploySmartAccountIfNeeded(chain.smartAccount);
    } catch (error) {
      console.log(`⚠️  Smart account deployment failed on ${chain.name}, but continuing...`);
      console.log(`Error: ${error.message}`);
    }
  }
}

// Initialize a lightweight API client for interacting with Gateway
const gatewayClient = new GatewayClient();

// Check the account's balances with the Gateway API
console.log("Checking balances...");
const accountAddress = ethereum.accountAddress;

const { balances } = await gatewayClient.balances("USDC", accountAddress);
for (const balance of balances) {
  console.log(`  - ${GatewayClient.CHAINS[balance.domain]}:`, `${balance.balance} USDC`);
}

// These are the amounts we intent on transferring from each chain we deposited on
const fromEthereumAmount = 1;
const fromAvalancheAmount = 1;

// Validate sufficient balances for transfer
const avalancheBalance = balances.find((b) => b.domain === GatewayClient.DOMAINS.avalanche).balance;
const ethereumBalance = balances.find((b) => b.domain === GatewayClient.DOMAINS.ethereum).balance;

if (parseFloat(avalancheBalance) < fromAvalancheAmount) {
  console.error("Insufficient Avalanche balance - wait for deposit finalization");
  process.exit(1);
}

if (parseFloat(ethereumBalance) < fromEthereumAmount) {
  console.error("Insufficient Ethereum balance - wait for deposit finalization");
  process.exit(1);
}

console.log("✅ Sufficient balances confirmed for transfer");

// Add EOA as delegate for smart account on source chains only (required for AA transfers)
if (ethereum.smartAccount) {
  console.log("🔗 Checking delegation status for Account Abstraction...");
  
  // Check if delegation is already set up
  const delegationNeeded = [];
  for (const chain of [ethereum, avalanche]) {
    try {
      const isAuthorized = await chain.gatewayWallet.read.isAuthorizedForBalance([
        chain.usdc.address,
        accountAddress, // smart account as depositor
        account.address  // EOA as delegate
      ]);
      
      if (isAuthorized) {
        console.log(`✅ ${chain.name}: EOA already authorized for smart account`);
      } else {
        console.log(`❌ ${chain.name}: EOA not authorized, delegation needed`);
        delegationNeeded.push(chain);
      }
    } catch (error) {
      console.log(`⚠️  Failed to check authorization on ${chain.name}: ${error.message}`);
      delegationNeeded.push(chain); // Add to delegation needed if we can't check
    }
  }
  
  // Only add delegates where needed
  if (delegationNeeded.length > 0) {
    console.log("🔗 Setting up missing delegates...");
    for (const chain of delegationNeeded) {
      try {
        console.log(`Adding EOA ${account.address} as delegate on ${chain.name}...`);
        const delegateTx = await chain.gatewayWalletWrite.write.addDelegate([chain.usdc.address, account.address]);
        await chain.client.waitForTransactionReceipt({ hash: delegateTx });
        console.log(`✅ Delegate added on ${chain.name}! Transaction hash: ${delegateTx}`);
      } catch (error) {
        console.log(`⚠️  Failed to add delegate on ${chain.name}: ${error.message}`);
      }
    }
    
    // Wait for the Gateway API to recognize the new delegation
    console.log("⏳ Waiting for Gateway API to recognize delegation...");
    await new Promise(resolve => setTimeout(resolve, 5000));
  } else {
    console.log("✅ All delegations already in place!");
  }
}

// Construct the burn intents
console.log("Creating burn intents for cross-chain transfer...");
const burnIntents = [
  burnIntent({
    account, // EOA for signing
    from: ethereum,
    to: base,
    amount: fromEthereumAmount,
    recipient: accountAddress,
    depositor: accountAddress, // Smart account that made the deposit
  }),
  burnIntent({
    account, // EOA for signing
    from: avalanche,
    to: base,
    amount: fromAvalancheAmount,
    recipient: accountAddress,
    depositor: accountAddress, // Smart account that made the deposit
  }),
];

// Sign the burn intents
console.log("Signing burn intents...");
const request = await Promise.all(
  burnIntents.map(async (intent) => {
    const typedData = burnIntentTypedData(intent);
    // EOA signs for both EOA and AA modes (Gateway API requirement)
    const signature = await account.signTypedData(typedData);
    return { burnIntent: typedData.message, signature };
  })
);

// Request the attestation
console.log("Requesting attestation from Gateway API...");
const start = performance.now();
const response = await gatewayClient.transfer(request);
const end = performance.now();
if (response.success === false) {
  console.error("Error from Gateway API:", response.message);
  process.exit(1);
}
console.log("Received attestation from Gateway API in", (end - start).toFixed(2), "ms");

// Mint the funds on Base
console.log("Minting funds on Base...");
const { attestation, signature } = response;
const mintTx = await base.gatewayMinterWrite.write.gatewayMint([attestation, signature]);
await base.client.waitForTransactionReceipt({ hash: mintTx });
console.log("Done! Transaction hash:", mintTx);
process.exit(0);
