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

import {BurnAuthorization} from "src/lib/authorizations/BurnAuthorizations.sol";
import {TransferSpec} from "src/lib/authorizations/TransferSpec.sol";
import {MultichainTestUtils} from "./../util/MultichainTestUtils.sol";

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

        // Offchain: Generate burn authorization and validate
        TransferSpec[] memory transferSpecs = new TransferSpec[](3);
        transferSpecs[0] =
            _createTransferSpec(arbitrum, ethereum, MINT_AMOUNT, depositor, recipient, depositor, address(0));
        transferSpecs[1] = _createTransferSpec(base, ethereum, MINT_AMOUNT, depositor, recipient, depositor, address(0));
        transferSpecs[2] =
            _createTransferSpec(ethereum, ethereum, MINT_AMOUNT, depositor, recipient, depositor, address(0));

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
        bool isValidBurnAuthEthereum = ethereum.wallet.validateBurnAuthorizations(encodedBurnAuth, depositor);
        vm.selectFork(arbitrum.forkId);
        bool isValidBurnAuthArbitrum = arbitrum.wallet.validateBurnAuthorizations(encodedBurnAuth, depositor);
        vm.selectFork(base.forkId);
        bool isValidBurnAuthBase = base.wallet.validateBurnAuthorizations(encodedBurnAuth, depositor);
        assertTrue(isValidBurnAuthEthereum && isValidBurnAuthArbitrum && isValidBurnAuthBase);

        // Offchain: Generate mint authorization given valid burn authorization
        (bytes memory encodedMintAuth, bytes memory mintSignature) =
            _signMintAuthSetWithTransferSpec(transferSpecs, ethereum.minterMintSignerKey);

        // On Ethereum: Mint using mint authorization
        uint256 expectedTotalSupplyIncrement = MINT_AMOUNT * 2; // 2 cross chain transfers
        uint256 expectedRecipientBalanceIncrement = MINT_AMOUNT * 3; // 3 transfers total
        uint256 expectedDepositorBalanceDecrement = MINT_AMOUNT; // depositor balance reduces due to same chain transfer
        _mintFromChain(
            ethereum,
            encodedMintAuth,
            mintSignature,
            expectedTotalSupplyIncrement,
            expectedRecipientBalanceIncrement,
            expectedDepositorBalanceDecrement
        );

        // On each fork: Burn used amount
        _burnFromChain(
            arbitrum,
            encodedBurnAuth,
            burnSignature,
            MINT_AMOUNT, /* expected total supply decrement */
            MINT_AMOUNT + FEE_AMOUNT /* expected depositor balance decrement */
        );
        _burnFromChain(
            base,
            encodedBurnAuth,
            burnSignature,
            MINT_AMOUNT, /* expected total supply decrement */
            MINT_AMOUNT + FEE_AMOUNT /* expected depositor balance decrement */
        );
        // Skip burn on Ethereum due to same chain transfer
    }

    function test_depositOnOneChainAndMintOnMultiple() public {
        // On Ethereum: Deposit USDC
        _depositToChain(ethereum, depositor, DEPOSIT_AMOUNT);

        // Offchain: Generate multiple mint authorizations
        vm.selectFork(ethereum.forkId);
        TransferSpec[] memory transferSpecs = new TransferSpec[](3);
        transferSpecs[0] =
            _createTransferSpec(ethereum, arbitrum, MINT_AMOUNT, depositor, recipient, depositor, address(0));
        transferSpecs[1] = _createTransferSpec(ethereum, base, MINT_AMOUNT, depositor, recipient, depositor, address(0));
        transferSpecs[2] =
            _createTransferSpec(ethereum, ethereum, MINT_AMOUNT, depositor, recipient, depositor, address(0));
        (bytes memory encodedBurnAuth, bytes memory burnSignature) =
            _signBurnAuthSetWithTransferSpec(transferSpecs, ethereum.wallet, depositorPrivateKey);

        // On each fork, validate burn authorization
        vm.selectFork(arbitrum.forkId);
        bool isValidBurnAuthArbitrum = arbitrum.wallet.validateBurnAuthorizations(encodedBurnAuth, depositor);
        vm.selectFork(base.forkId);
        bool isValidBurnAuthBase = base.wallet.validateBurnAuthorizations(encodedBurnAuth, depositor);
        vm.selectFork(ethereum.forkId);
        bool isValidBurnAuthEthereum = ethereum.wallet.validateBurnAuthorizations(encodedBurnAuth, depositor);
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

        // On each fork: Use mint authorization
        _mintFromChain(
            arbitrum,
            encodedMintAuth0,
            mintSignature0,
            MINT_AMOUNT, /* expected supply increment */
            MINT_AMOUNT, /* expected recipient balance increment */
            0 /* expected depositor balance decrement */
        );
        _mintFromChain(
            base,
            encodedMintAuth1,
            mintSignature1,
            MINT_AMOUNT, /* expected supply increment */
            MINT_AMOUNT, /* expected recipient balance increment */
            0 /* expected depositor balance decrement */
        );
        _mintFromChain( // same chain transfer
            ethereum,
            encodedMintAuth2,
            mintSignature2,
            0, /* expected supply increment */
            MINT_AMOUNT, /* expected recipient balance increment */
            MINT_AMOUNT /* expected depositor balance decrement */
        );

        // On Ethereum: Burn used amount
        _burnFromChain(
            ethereum,
            encodedBurnAuth,
            burnSignature,
            MINT_AMOUNT * 2, /* expected total supply to decrement for 2 cross chain transfers */
            (MINT_AMOUNT + FEE_AMOUNT) * 2 /* expected depositor balance to decrement for 2 transfers plus fees */
        );
    }
}
