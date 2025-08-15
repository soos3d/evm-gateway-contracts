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
import { deploySmartAccountIfNeeded } from "./config/aa-config.js";
import { executeContractWithRetry, addTransactionDelay } from "./utils/aa-utils.js";

const decimals = 6; // USDC has 6 decimal places
const DEPOSIT_AMOUNT = 2000000n; // 2 USDC

console.log("🚀 Starting USDC deposits across all chains...\n");

// Deposit into the GatewayWallet contract on all chains
const chains = [ethereum, base, avalanche];
for (let i = 0; i < chains.length; i++) {
  const chain = chains[i];
  
  // Add chain header with divider
  console.log(`${"=".repeat(50)}`);
  console.log(`📍 ${chain.name.toUpperCase()}`);
  console.log(`${"=".repeat(50)}`);
  console.log(`Account: ${chain.accountAddress}`);
  console.log("");
  // Deploy smart account if needed (before any transactions)
  if (chain.smartAccount) {
    try {
      await deploySmartAccountIfNeeded(chain.smartAccount);
    } catch (error) {
      console.log(`⚠️  Smart account deployment failed on ${chain.name}, but continuing with transactions...`);
      console.log(`Error: ${error.message}`);
    }
  }

  // Get the wallet's current USDC balance
  console.log(`💰 Checking USDC balance...`);
  const balance = await chain.usdc.read.balanceOf([chain.accountAddress]);
  const readableBalance = Number(balance) / 10 ** decimals;
  console.log(`   Balance: ${readableBalance} USDC`);
  console.log("");

  // Ensure the balance is sufficient for the deposit
  if (balance < DEPOSIT_AMOUNT) {
    console.error(`❌ Insufficient USDC balance on ${chain.name}!`);
    console.error("   Please top up at https://faucet.circle.com.");
    process.exit(1);
  }

  // Attempt to approve and deposit USDC into the GatewayWallet contract, and
  // handle the error if the wallet does not have enough funds to pay for gas
  try {
    // Approve the GatewayWallet contract for the wallet's USDC
    console.log("🔐 Approving Gateway Wallet for USDC...");
    if (chain.smartAccount) {
      // Use retry logic for AA transactions
      await executeContractWithRetry(
        chain.usdcWrite, 
        chain.client, 
        'approve', 
        [chain.gatewayWallet.address, DEPOSIT_AMOUNT],
        { maxRetries: 3, retryDelay: 2000 }
      );
    } else {
      // Standard EOA transaction
      const approvalTx = await chain.usdcWrite.write.approve([chain.gatewayWallet.address, DEPOSIT_AMOUNT]);
      await chain.client.waitForTransactionReceipt({ hash: approvalTx });
      console.log(`✅ ${approvalTx}`);
    }

    // Add delay between transactions for AA nonce synchronization
    if (chain.smartAccount) {
      await addTransactionDelay(2000);
    }

    // Deposit USDC into the GatewayWallet contract
    console.log("💸 Depositing 0.5 USDC into Gateway Wallet...");
    if (chain.smartAccount) {
      // Use retry logic for AA transactions
      await executeContractWithRetry(
        chain.gatewayWalletWrite, 
        chain.client, 
        'deposit', 
        [chain.usdc.address, DEPOSIT_AMOUNT],
        { maxRetries: 3, retryDelay: 2000 }
      );
    } else {
      // Standard EOA transaction
      const depositTx = await chain.gatewayWalletWrite.write.deposit([chain.usdc.address, DEPOSIT_AMOUNT]);
      await chain.client.waitForTransactionReceipt({ hash: depositTx });
      console.log(`✅ ${depositTx}`);
    }

    console.log(`✅ ${chain.name} deposit completed successfully!`);
    
    // Add spacing between chains (except for the last one)
    if (i < chains.length - 1) {
      console.log("\n");
    }

  } catch (error) {
    if (error.details && error.details.includes("insufficient funds")) {
      // If there wasn't enough for gas, log an error message and exit
      console.error(`❌ Insufficient ${chain.currency} for gas on ${chain.name}!`);
      console.error(`   Please top up using a faucet.`);
    } else {
      // Log any other errors for debugging
      console.error(`❌ Error on ${chain.name}:`, error.message);
    }
    process.exit(1);
  }
}

console.log("\n🎉 All deposits completed successfully!");
