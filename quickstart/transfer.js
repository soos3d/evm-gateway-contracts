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
import { burnIntent, burnIntentTypedData } from "./typed-data.js";
import { deploySmartAccountIfNeeded } from "./aa-config.js";

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

// Check the info endpoint to confirm which chains are supported
// Not necessary for the transfer, but useful information
console.log("Fetching Gateway API info...");
const info = await gatewayClient.info();
for (const domain of info.domains) {
  console.log(
    `  - ${domain.chain} ${domain.network}`,
    `(wallet: ${"walletContract" in domain}, minter: ${"minterContract" in domain})`
  );
}

// Check the account's balances with the Gateway API
console.log(`Checking balances...`);
// Use the appropriate account address (smart account or EOA)
const accountAddress = ethereum.accountAddress;
console.log(`🔍 Using account address for balance check: ${accountAddress}`);
console.log(`🔍 EOA address: ${account.address}`);

const { balances } = await gatewayClient.balances("USDC", accountAddress);
for (const balance of balances) {
  console.log(`  - ${GatewayClient.CHAINS[balance.domain]}:`, `${balance.balance} USDC`);
}

// These are the amounts we intent on transferring from each chain we deposited on
const fromEthereumAmount = 1;
const fromAvalancheAmount = 1;

// Check to see if Gateway has picked up the Avalanche deposit yet
// Since Avalanche has instant finality, this should be quick
const avalancheBalance = balances.find((b) => b.domain === GatewayClient.DOMAINS.avalanche).balance;
if (parseFloat(avalancheBalance) < fromAvalancheAmount) {
  console.error("Gateway deposit not yet picked up on Avalanche, wait until finalization");
  process.exit(1);
} else {
  console.error("Gateway deposit picked up on Avalanche!");
}

// Check to see if Gateway has picked up the Ethereum deposit yet
// Ethereum takes about 20 minutes to finalize blocks, so you may need to wait a bit
const ethereumBalance = balances.find((b) => b.domain === GatewayClient.DOMAINS.ethereum).balance;
if (parseFloat(ethereumBalance) < fromEthereumAmount) {
  console.error("Gateway deposit not yet picked up on Ethereum, wait until finalization");
  process.exit(1);
} else {
  console.error("Gateway deposit picked up on Ethereum!");
}

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
console.log("Constructing burn intent set...");
console.log(`🔍 Creating burn intents with:`);
console.log(`   - EOA signer: ${account.address}`);
console.log(`   - Smart account depositor: ${accountAddress}`);
console.log(`   - Recipient: ${accountAddress}`);
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

// Log the burn intent details
console.log(`🔍 Burn intent details:`);
burnIntents.forEach((intent, i) => {
  console.log(`   Intent ${i + 1}:`);
  console.log(`     - sourceDepositor: ${intent.spec.sourceDepositor}`);
  console.log(`     - sourceSigner: ${intent.spec.sourceSigner}`);
  console.log(`     - destinationRecipient: ${intent.spec.destinationRecipient}`);
  console.log(`     - amount: ${intent.spec.value}`);
});

// Sign the burn intents
console.log("Signing burn intents...");
const request = await Promise.all(
  burnIntents.map(async (intent, i) => {
    const typedData = burnIntentTypedData(intent);
    console.log(`🔍 Signing intent ${i + 1} with smart account: ${accountAddress}`);
    
    let signature;
    if (ethereum.smartAccount) {
      console.log(`🔍 AA mode detected, but using EOA signing for Gateway compatibility...`);
      // In AA mode, the EOA (owner) signs on behalf of the smart account
      // The Gateway API expects the signature to come from the sourceSigner (EOA)
      signature = await account.signTypedData(typedData);
    } else {
      console.log(`🔍 Using standard EOA signing...`);
      signature = await account.signTypedData(typedData);
    }
    
    console.log(`✅ Signature generated: ${signature.slice(0, 10)}...`);
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
