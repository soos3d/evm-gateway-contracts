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
pragma solidity ^0.8.29;

import {BurnIntent} from "src/lib/BurnIntents.sol";
import {TransferSpec} from "src/lib/TransferSpec.sol";
import {MultichainTestUtils} from "test/util/MultichainTestUtils.sol";

contract MultiDepositAndMintFlowTest is MultichainTestUtils {
    ChainSetup private ethereum;
    ChainSetup private arbitrum;
    ChainSetup private base;

    function setUp() public {
        // Setup Ethereum fork
        ethereum = _initializeGatewayContracts("ethereum");

        // Setup Arbitrum fork
        arbitrum = _initializeGatewayContracts("arbitrum");

        // Setup Base fork
        base = _initializeGatewayContracts("base");
    }

    function test_depositFromMultipleChainsAndMintOnOne() public {
        // On each fork: Deposit USDC
        _depositToChain(ethereum, depositor, DEPOSIT_AMOUNT);
        _depositToChain(arbitrum, depositor, DEPOSIT_AMOUNT);
        _depositToChain(base, depositor, DEPOSIT_AMOUNT);

        // Offchain: Generate burn intent
        TransferSpec[] memory transferSpecs = new TransferSpec[](3);
        transferSpecs[0] =
            _createTransferSpec(arbitrum, ethereum, MINT_AMOUNT, depositor, recipient, depositor, address(0));
        transferSpecs[1] = _createTransferSpec(base, ethereum, MINT_AMOUNT, depositor, recipient, depositor, address(0));
        transferSpecs[2] =
            _createTransferSpec(ethereum, ethereum, MINT_AMOUNT, depositor, recipient, depositor, address(0));

        BurnIntent[] memory burnIntents = new BurnIntent[](3);
        vm.selectFork(arbitrum.forkId);
        burnIntents[0] = _createBurnIntent(transferSpecs[0]);
        vm.selectFork(base.forkId);
        burnIntents[1] = _createBurnIntent(transferSpecs[1]);
        vm.selectFork(ethereum.forkId);
        burnIntents[2] = _createBurnIntent(transferSpecs[2]);

        (bytes memory encodedBurnIntent, bytes memory burnSignature) =
            _signBurnIntents(burnIntents, ethereum.wallet, depositorPrivateKey);

        // Offchain: Generate attestation given burn intent
        (bytes memory encodedAttestation, bytes memory attestationSignature) =
            _signAttestationSetWithTransferSpec(transferSpecs, ethereum.minterAttestationSignerKey);

        // On Ethereum: Mint using attestation
        _mintFromChain(
            ethereum, encodedAttestation, attestationSignature, MINT_AMOUNT * 3 /* expected total minted amount */
        );

        // On each fork: Burn used amount
        _burnFromChain(
            arbitrum,
            encodedBurnIntent,
            burnSignature,
            MINT_AMOUNT, /* expected total burnt amount */
            FEE_AMOUNT /* expected total fee amount */
        );
        _burnFromChain(
            base,
            encodedBurnIntent,
            burnSignature,
            MINT_AMOUNT, /* expected total burnt amount */
            FEE_AMOUNT /* expected total fee amount */
        );
        _burnFromChain(
            ethereum,
            encodedBurnIntent,
            burnSignature,
            MINT_AMOUNT, /* expected total burnt amount */
            FEE_AMOUNT /* expected total fee amount */
        );
    }

    function test_depositOnOneChainAndMintOnMultiple() public {
        // On Ethereum: Deposit USDC
        _depositToChain(ethereum, depositor, DEPOSIT_AMOUNT);

        // Offchain: Generate multiple attestations
        vm.selectFork(ethereum.forkId);
        TransferSpec[] memory transferSpecs = new TransferSpec[](3);
        transferSpecs[0] =
            _createTransferSpec(ethereum, arbitrum, MINT_AMOUNT, depositor, recipient, depositor, address(0));
        transferSpecs[1] = _createTransferSpec(ethereum, base, MINT_AMOUNT, depositor, recipient, depositor, address(0));
        transferSpecs[2] =
            _createTransferSpec(ethereum, ethereum, MINT_AMOUNT, depositor, recipient, depositor, address(0));
        (bytes memory encodedBurnIntent, bytes memory burnSignature) =
            _signBurnIntentSetWithTransferSpec(transferSpecs, ethereum.wallet, depositorPrivateKey);

        // Offchain: Generate attestation given burn intent
        vm.selectFork(arbitrum.forkId);
        (bytes memory encodedAttestation0, bytes memory attestationSignature0) =
            _signAttestationWithTransferSpec(transferSpecs[0], arbitrum.minterAttestationSignerKey);
        vm.selectFork(base.forkId);
        (bytes memory encodedAttestation1, bytes memory attestationSignature1) =
            _signAttestationWithTransferSpec(transferSpecs[1], base.minterAttestationSignerKey);
        vm.selectFork(ethereum.forkId);
        (bytes memory encodedAttestation2, bytes memory attestationSignature2) =
            _signAttestationWithTransferSpec(transferSpecs[2], ethereum.minterAttestationSignerKey);

        // On each fork: Use attestation
        _mintFromChain(
            arbitrum, encodedAttestation0, attestationSignature0, MINT_AMOUNT /* expected total minted amount */
        );
        _mintFromChain(
            base, encodedAttestation1, attestationSignature1, MINT_AMOUNT /* expected total minted amount */
        );
        _mintFromChain( // same chain transfer
        ethereum, encodedAttestation2, attestationSignature2, MINT_AMOUNT /* expected total minted amount */ );

        // On Ethereum: Burn used amount
        _burnFromChain(
            ethereum,
            encodedBurnIntent,
            burnSignature,
            MINT_AMOUNT * 3, /* expected total burnt amount */
            FEE_AMOUNT * 3 /* expected total fee amount */
        );
    }
}
