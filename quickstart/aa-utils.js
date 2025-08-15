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
 * Utility functions for handling Account Abstraction transactions with proper nonce management
 */

/**
 * Executes a contract write with retry logic for AA nonce issues
 * @param {Object} contract - The viem contract instance
 * @param {string} functionName - The function name to call
 * @param {Array} args - Function arguments
 * @param {Object} options - Additional options
 * @returns {Promise<string>} Transaction hash
 */
export async function executeWithRetry(contract, functionName, args, options = {}) {
  const maxRetries = options.maxRetries || 3;
  const retryDelay = options.retryDelay || 2000; // 2 seconds
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.log(`🔄 Attempt ${attempt}/${maxRetries}: Executing ${functionName}...`);
      
      // Add a small delay between attempts to allow nonce to sync
      if (attempt > 1) {
        console.log(`⏳ Waiting ${retryDelay}ms before retry...`);
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      }
      
      const txHash = await contract.write[functionName](args);
      console.log(`✅ Transaction successful on attempt ${attempt}: ${txHash}`);
      return txHash;
      
    } catch (error) {
      const isNonceError = error.message.includes('AA25 invalid account nonce') || 
                          error.message.includes('nonce') ||
                          error.details?.includes('AA25 invalid account nonce');
      
      const isLastAttempt = attempt === maxRetries;
      
      if (isNonceError && !isLastAttempt) {
        console.log(`⚠️  Nonce error on attempt ${attempt}, retrying...`);
        console.log(`Error: ${error.message}`);
        continue;
      }
      
      // If it's not a nonce error or we've exhausted retries, throw the error
      console.error(`❌ Transaction failed on attempt ${attempt}:`);
      console.error(`Error: ${error.message}`);
      throw error;
    }
  }
}

/**
 * Waits for a transaction receipt with timeout
 * @param {Object} client - The viem client
 * @param {string} hash - Transaction hash
 * @param {number} timeout - Timeout in milliseconds (default 60s)
 * @returns {Promise<Object>} Transaction receipt
 */
export async function waitForTransactionWithTimeout(client, hash, timeout = 60000) {
  console.log(`⏳ Waiting for transaction receipt: ${hash}`);
  
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => reject(new Error('Transaction receipt timeout')), timeout);
  });
  
  try {
    const receipt = await Promise.race([
      client.waitForTransactionReceipt({ hash }),
      timeoutPromise
    ]);
    
    console.log(`✅ Transaction confirmed: ${hash}`);
    return receipt;
  } catch (error) {
    if (error.message === 'Transaction receipt timeout') {
      console.log(`⚠️  Transaction receipt timeout for ${hash}, but transaction may still be processing`);
      throw error;
    }
    throw error;
  }
}

/**
 * Executes a contract write with full AA error handling and receipt waiting
 * @param {Object} contract - The viem contract instance
 * @param {Object} client - The viem client for waiting for receipts
 * @param {string} functionName - The function name to call
 * @param {Array} args - Function arguments
 * @param {Object} options - Additional options
 * @returns {Promise<Object>} Transaction receipt
 */
export async function executeContractWithRetry(contract, client, functionName, args, options = {}) {
  const txHash = await executeWithRetry(contract, functionName, args, options);
  const receipt = await waitForTransactionWithTimeout(client, txHash, options.timeout);
  return receipt;
}

/**
 * Adds a delay between transactions to help with nonce synchronization
 * @param {number} ms - Milliseconds to wait
 */
export async function addTransactionDelay(ms = 1000) {
  console.log(`⏳ Adding ${ms}ms delay for nonce synchronization...`);
  await new Promise(resolve => setTimeout(resolve, ms));
}
