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
  const silent = options.silent || false;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      // Only show attempt info if it's a retry or not silent
      if (attempt > 1 && !silent) {
        console.log(`🔄 Retrying ${functionName} (attempt ${attempt}/${maxRetries})...`);
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      }
      
      const txHash = await contract.write[functionName](args);
      
      // Only show success message if it took multiple attempts or not silent
      if ((attempt > 1 || !silent) && options.showSuccess !== false) {
        console.log(`✅ ${txHash}`);
      }
      
      return txHash;
      
    } catch (error) {
      const isNonceError = error.message.includes('AA25 invalid account nonce') || 
                          error.message.includes('nonce') ||
                          error.details?.includes('AA25 invalid account nonce');
      
      const isLastAttempt = attempt === maxRetries;
      
      if (isNonceError && !isLastAttempt) {
        if (!silent) {
          console.log(`⚠️  Nonce issue, retrying...`);
        }
        continue;
      }
      
      // If it's not a nonce error or we've exhausted retries, throw the error
      if (!silent) {
        console.error(`❌ Transaction failed: ${error.message}`);
      }
      throw error;
    }
  }
}

/**
 * Waits for a transaction receipt with timeout
 * @param {Object} client - The viem client
 * @param {string} hash - Transaction hash
 * @param {number} timeout - Timeout in milliseconds (default 60s)
 * @param {Object} options - Additional options
 * @returns {Promise<Object>} Transaction receipt
 */
export async function waitForTransactionWithTimeout(client, hash, timeout = 60000, options = {}) {
  const silent = options.silent || false;
  
  if (!silent) {
    console.log(`⏳ Confirming transaction...`);
  }
  
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => reject(new Error('Transaction receipt timeout')), timeout);
  });
  
  try {
    const receipt = await Promise.race([
      client.waitForTransactionReceipt({ hash }),
      timeoutPromise
    ]);
    
    return receipt;
  } catch (error) {
    if (error.message === 'Transaction receipt timeout') {
      if (!silent) {
        console.log(`⚠️  Transaction timeout, but may still be processing`);
      }
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
  const receipt = await waitForTransactionWithTimeout(client, txHash, options.timeout, options);
  return receipt;
}

/**
 * Adds a delay between transactions to help with nonce synchronization
 * @param {number} ms - Milliseconds to wait
 * @param {Object} options - Additional options
 */
export async function addTransactionDelay(ms = 1000, options = {}) {
  const silent = options.silent || false;
  
  if (!silent) {
    console.log(`⏳ Syncing...`);
  }
  await new Promise(resolve => setTimeout(resolve, ms));
}
