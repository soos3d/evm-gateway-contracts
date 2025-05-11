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

import assert from "assert";
import { ethers } from "ethers";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import {
  burnAuthorizationTypedData,
  burnAuthorizationSetTypedData,
  burnAuthorization1,
  burnAuthorization2,
} from "./eip712TestData.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Constants
const RPC_URL = "http://localhost:8545";
const TEST_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // Default anvil private key

// Deploys the GatewayWallet contract
async function deployGatewayWallet(deployer) {
  const artifactPath = path.join(__dirname, "../../out/GatewayWallet.sol/GatewayWallet.json");
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));

  const GatewayWalletFactory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, deployer);
  return await GatewayWalletFactory.deploy();
}

// Computes the EIP-712 digest
function calculateDigest(domainSeparator, structHash) {
  return ethers.keccak256(
    ethers.concat([
      Uint8Array.from([0x19, 0x01]), // EIP-712 prefix
      domainSeparator,
      structHash
    ])
  );
}

describe("GatewayWallet Contract", function () {
  let gatewayWallet;
  let provider;
  let signer;
  let domainSeparator;

  before(async function () {
    // Setup provider and signer
    provider = new ethers.JsonRpcProvider(RPC_URL);
    signer = new ethers.Wallet(TEST_PRIVATE_KEY, provider);

    // Deploy contract
    const [deployer] = await provider.listAccounts();
    gatewayWallet = await deployGatewayWallet(deployer);

    // Cache domain separator
    domainSeparator = await gatewayWallet.domainSeparator();
  });

  describe("Single Burn Authorization", function() {
    it("should sign and verify a single burn authorization", async function () {
      // Get signature from eth_signTypedData_v4
      const signatureFromEthSignTypedData = await provider.send(
        "eth_signTypedData_v4",
        [signer.address, JSON.stringify(burnAuthorizationTypedData)]
      );

      // Get signature from direct signing
      const encodedBurnAuth = await gatewayWallet.encodeBurnAuthorization(burnAuthorization1);
      const structHashFromGatewayWallet = await gatewayWallet.getTypedDataHash(encodedBurnAuth);
      const digest = calculateDigest(domainSeparator, structHashFromGatewayWallet);

      const signingKey = new ethers.SigningKey(signer.privateKey);
      const signatureFromGatewayWallet = signingKey.sign(ethers.getBytes(digest)).serialized;

      // Verify signatures match
      assert.equal(signatureFromEthSignTypedData, signatureFromGatewayWallet);
    });
  });

  describe("Burn Authorization Set", function() {
    it("should sign and verify a burn authorization set", async function () {
      // Get signature from eth_signTypedData_v4
      const signatureFromEthSignTypedData = await provider.send(
        "eth_signTypedData_v4",
        [signer.address, JSON.stringify(burnAuthorizationSetTypedData)]
      );

      // Get signature from direct signing
      const encodedBurnAuthSet = await gatewayWallet.encodeBurnAuthorizations([
        burnAuthorization1,
        burnAuthorization2
      ]);
      const structHashFromGatewayWallet = await gatewayWallet.getTypedDataHash(encodedBurnAuthSet);
      const digest = calculateDigest(domainSeparator, structHashFromGatewayWallet);

      const signingKey = new ethers.SigningKey(signer.privateKey);
      const signatureFromGatewayWallet = signingKey.sign(ethers.getBytes(digest)).serialized;

      // Verify signatures match
      assert.equal(signatureFromEthSignTypedData, signatureFromGatewayWallet);
    });
  });
});
