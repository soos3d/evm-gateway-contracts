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
import { deploySmartAccountIfNeeded } from "./aa-config.js";
import { executeContractWithRetry, addTransactionDelay } from "./aa-utils.js";

const decimals = 6; // USDC has 6 decimal places
const DEPOSIT_AMOUNT = 1_000000n; // 4 USDC

// Deposit into the GatewayWallet contract on all chains
for (const chain of [ethereum, base, avalanche]) {
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
  console.log(`Checking USDC balance on ${chain.name}...`);
  const balance = await chain.usdc.read.balanceOf([chain.accountAddress]);
  const readableBalance = Number(balance) / 10 ** decimals;
  console.log("Current USDC balance:", readableBalance);
  // Ensure the balance is sufficient for the deposit
  if (balance < DEPOSIT_AMOUNT) {
    console.error(`Insufficient USDC balance on ${chain.name}!`);
    console.error("Please top up at https://faucet.circle.com.");
    process.exit(1);
  }

  // Attempt to approve and deposit USDC into the GatewayWallet contract, and
  // handle the error if the wallet does not have enough funds to pay for gas
  try {
    // Approve the GatewayWallet contract for the wallet's USDC
    console.log("Approving the GatewayWallet contract for USDC...");
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
      console.log("Done! Transaction hash:", approvalTx);
    }

    // Add delay between transactions for AA nonce synchronization
    if (chain.smartAccount) {
      await addTransactionDelay(2000);
    }

    // Deposit USDC into the GatewayWallet contract
    console.log("Depositing USDC into the GatewayWallet contract...");
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
      console.log("Done! Transaction hash:", depositTx);
    }
  } catch (error) {
    if (error.details && error.details.includes("insufficient funds")) {
      // If there wasn't enough for gas, log an error message and exit
      console.error(`The wallet does not have enough ${chain.currency} to pay for gas on ${chain.name}!`);
      console.error(`Please top up using a faucet.`);
    } else {
      // Log any other errors for debugging
      console.error(error);
    }
    process.exit(1);
  }
}
