/*
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.

 * SPDX-License-Identifier: Apache-2.0

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
pragma solidity ^0.8.28;

import {BurnAuthorization} from "src/lib/authorizations/BurnAuthorizations.sol";
import {MultichainTestUtils} from "../util/MultichainTestUtils.sol";
import {TransferSpec} from "src/lib/authorizations/TransferSpec.sol";

contract MultiDepositAndSpendFlowTest is MultichainTestUtils {
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

        // Offchain: Generate burn authorization and validate
        TransferSpec[] memory transferSpecs = new TransferSpec[](3);
        transferSpecs[0] =
            _createTransferSpec(arbitrum, ethereum, SPEND_AMOUNT, depositor, recipient, depositor, address(0));
        transferSpecs[1] =
            _createTransferSpec(base, ethereum, SPEND_AMOUNT, depositor, recipient, depositor, address(0));
        transferSpecs[2] =
            _createTransferSpec(ethereum, ethereum, SPEND_AMOUNT, depositor, recipient, depositor, address(0));

        BurnAuthorization[] memory burnAuths = new BurnAuthorization[](3);
        vm.selectFork(arbitrum.forkId);
        burnAuths[0] = _createBurnAuth(transferSpecs[0]);
        vm.selectFork(base.forkId);
        burnAuths[1] = _createBurnAuth(transferSpecs[1]);
        vm.selectFork(ethereum.forkId);
        burnAuths[2] = _createBurnAuth(transferSpecs[2]);

        (bytes memory encodedBurnAuth, bytes memory burnSignature) =
            _signBurnAuths(burnAuths, ethereum.wallet, depositorPrivateKey);

        // On each fork, validate burn authorization
        vm.selectFork(ethereum.forkId);
        bool isValidBurnAuthEthereum = ethereum.wallet.validateBurnAuthorizations(encodedBurnAuth, burnSignature);
        vm.selectFork(arbitrum.forkId);
        bool isValidBurnAuthArbitrum = arbitrum.wallet.validateBurnAuthorizations(encodedBurnAuth, burnSignature);
        vm.selectFork(base.forkId);
        bool isValidBurnAuthBase = base.wallet.validateBurnAuthorizations(encodedBurnAuth, burnSignature);
        assertTrue(isValidBurnAuthEthereum && isValidBurnAuthArbitrum && isValidBurnAuthBase);

        // Offchain: Generate mint authorization given valid burn authorization
        (bytes memory encodedMintAuth, bytes memory mintSignature) =
            _signMintAuthSetWithTransferSpec(transferSpecs, ethereum.minterMintSignerKey);

        // On Ethereum: Mint using mint authorization
        uint256 expectedTotalSupplyIncrement = SPEND_AMOUNT * 2; // 2 cross chain spends
        uint256 expectedRecipientBalanceIncrement = SPEND_AMOUNT * 3; // 3 spends total
        uint256 expectedDepositorBalanceDecrement = SPEND_AMOUNT; // depositor balance reduces due to same chain spend
        _mintFromChain(
            ethereum,
            encodedMintAuth,
            mintSignature,
            expectedTotalSupplyIncrement,
            expectedRecipientBalanceIncrement,
            expectedDepositorBalanceDecrement
        );

        // On each fork: Burn spent amount
        _burnFromChain(
            arbitrum,
            encodedBurnAuth,
            burnSignature,
            SPEND_AMOUNT, /* expected total supply decrement */
            SPEND_AMOUNT + FEE_AMOUNT /* expected depositor balance decrement */
        );
        _burnFromChain(
            base,
            encodedBurnAuth,
            burnSignature,
            SPEND_AMOUNT, /* expected total supply decrement */
            SPEND_AMOUNT + FEE_AMOUNT /* expected depositor balance decrement */
        );
        // Skip burn on Ethereum due to same chain spend
    }

    function test_depositOnOneChainAndMintOnMultiple() public {
        // On Ethereum: Deposit USDC
        _depositToChain(ethereum, depositor, DEPOSIT_AMOUNT);

        // Offchain: Generate multiple mint authorizations
        vm.selectFork(ethereum.forkId);
        TransferSpec[] memory transferSpecs = new TransferSpec[](3);
        transferSpecs[0] =
            _createTransferSpec(ethereum, arbitrum, SPEND_AMOUNT, depositor, recipient, depositor, address(0));
        transferSpecs[1] =
            _createTransferSpec(ethereum, base, SPEND_AMOUNT, depositor, recipient, depositor, address(0));
        transferSpecs[2] =
            _createTransferSpec(ethereum, ethereum, SPEND_AMOUNT, depositor, recipient, depositor, address(0));
        (bytes memory encodedBurnAuth, bytes memory burnSignature) =
            _signBurnAuthSetWithTransferSpec(transferSpecs, ethereum.wallet, depositorPrivateKey);

        // On each fork, validate burn authorization
        vm.selectFork(arbitrum.forkId);
        bool isValidBurnAuthArbitrum = arbitrum.wallet.validateBurnAuthorizations(encodedBurnAuth, burnSignature);
        vm.selectFork(base.forkId);
        bool isValidBurnAuthBase = base.wallet.validateBurnAuthorizations(encodedBurnAuth, burnSignature);
        vm.selectFork(ethereum.forkId);
        bool isValidBurnAuthEthereum = ethereum.wallet.validateBurnAuthorizations(encodedBurnAuth, burnSignature);
        assertTrue(isValidBurnAuthEthereum && isValidBurnAuthArbitrum && isValidBurnAuthBase);

        // Offchain: Generate mint authorization given valid burn authorization
        vm.selectFork(arbitrum.forkId);
        (bytes memory encodedMintAuth0, bytes memory mintSignature0) =
            _signMintAuthWithTransferSpec(transferSpecs[0], arbitrum.minterMintSignerKey);
        vm.selectFork(base.forkId);
        (bytes memory encodedMintAuth1, bytes memory mintSignature1) =
            _signMintAuthWithTransferSpec(transferSpecs[1], base.minterMintSignerKey);
        vm.selectFork(ethereum.forkId);
        (bytes memory encodedMintAuth2, bytes memory mintSignature2) =
            _signMintAuthWithTransferSpec(transferSpecs[2], ethereum.minterMintSignerKey);

        // On each fork: Spend mint authorization
        _mintFromChain(
            arbitrum,
            encodedMintAuth0,
            mintSignature0,
            SPEND_AMOUNT, /* expected supply increment */
            SPEND_AMOUNT, /* expected recipient balance increment */
            0 /* expected depositor balance decrement */
        );
        _mintFromChain(
            base,
            encodedMintAuth1,
            mintSignature1,
            SPEND_AMOUNT, /* expected supply increment */
            SPEND_AMOUNT, /* expected recipient balance increment */
            0 /* expected depositor balance decrement */
        );
        _mintFromChain( // same chain spend
            ethereum,
            encodedMintAuth2,
            mintSignature2,
            0, /* expected supply increment */
            SPEND_AMOUNT, /* expected recipient balance increment */
            SPEND_AMOUNT /* expected depositor balance decrement */
        );

        // On Ethereum: Burn spent amount
        _burnFromChain(
            ethereum,
            encodedBurnAuth,
            burnSignature,
            SPEND_AMOUNT * 2, /* expected total supply to decrement for 2 cross chain spends */
            (SPEND_AMOUNT + FEE_AMOUNT) * 2 /* expected depositor balance to decrement for 2 spends plus fees */
        );
    }
}
