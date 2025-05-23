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
 * Type definitions for structs used in the GatewayWallet contract.
 */

const EIP712Domain = [
  { name: 'name', type: 'string' },
  { name: 'version', type: 'string' }
];

const TransferSpec = [
  { name: 'version', type: 'uint32' },
  { name: 'sourceDomain', type: 'uint32' },
  { name: 'destinationDomain', type: 'uint32' },
  { name: 'sourceContract', type: 'bytes32' },
  { name: 'destinationContract', type: 'bytes32' },
  { name: 'sourceToken', type: 'bytes32' },
  { name: 'destinationToken', type: 'bytes32' },
  { name: 'sourceDepositor', type: 'bytes32' },
  { name: 'destinationRecipient', type: 'bytes32' },
  { name: 'sourceSigner', type: 'bytes32' },
  { name: 'destinationCaller', type: 'bytes32' },
  { name: 'value', type: 'uint256' },
  { name: 'salt', type: 'bytes32' },
  { name: 'metadata', type: 'bytes' }
];

const BurnIntent = [
  { name: 'maxBlockHeight', type: 'uint256' },
  { name: 'maxFee', type: 'uint256' },
  { name: 'spec', type: 'TransferSpec' }
];

const BurnIntentSet = [{ name: 'intents', type: 'BurnIntent[]' }];

/**
 * Helpers for generating test data
 */

// Generate random bytes and convert to hex string
function generateRandomBytes(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return (
    '0x' +
    Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  );
}

// Generate a random TransferSpec
const generateTransferSpec = () => ({
  version: 1,
  sourceDomain: 0,
  destinationDomain: 1,
  sourceContract: generateRandomBytes(32),
  destinationContract: generateRandomBytes(32),
  sourceToken: generateRandomBytes(32),
  destinationToken: generateRandomBytes(32),
  sourceDepositor: generateRandomBytes(32),
  destinationRecipient: generateRandomBytes(32),
  sourceSigner: generateRandomBytes(32),
  destinationCaller: generateRandomBytes(32),
  value: Math.floor(Math.random() * 1000000),
  salt: generateRandomBytes(32),
  // random 100 bytes of metadata
  metadata: generateRandomBytes(100)
});

/**
 * Generated test data
 */
export const domain = {
  name: 'GatewayWallet',
  version: '1'
};
export const transferSpec1 = generateTransferSpec();
export const transferSpec2 = generateTransferSpec();
export const burnIntent1 = {
  spec: transferSpec1,
  maxBlockHeight: 1000000,
  maxFee: 1000000
};
export const burnIntent2 = {
  spec: transferSpec2,
  maxBlockHeight: 1000001,
  maxFee: 1000001
};
export const burnIntentSet = {
  intents: [burnIntent1, burnIntent2]
};

/**
 * Assembled test data with types for signing
 */

export const burnIntentTypedData = {
  types: {
    EIP712Domain,
    TransferSpec,
    BurnIntent
  },
  domain,
  primaryType: 'BurnIntent',
  message: burnIntent1
};

export const burnIntentSetTypedData = {
  types: {
    EIP712Domain,
    TransferSpec,
    BurnIntent,
    BurnIntentSet
  },
  domain,
  primaryType: 'BurnIntentSet',
  message: burnIntentSet
};
