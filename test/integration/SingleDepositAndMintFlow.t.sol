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

import {MultichainTestUtils} from "../util/MultichainTestUtils.sol";
import {TransferSpec} from "src/lib/authorizations/TransferSpec.sol";
import {Burns} from "src/lib/wallet/Burns.sol";

contract SingleDepositAndSpendFlowTest is MultichainTestUtils {
    ChainSetup private ethereum;
    ChainSetup private arbitrum;

    function setUp() public {
        // Setup Ethereum fork
        ethereum = _initializeGatewayContracts("ethereum");

        // Setup Arbitrum fork
        arbitrum = _initializeGatewayContracts("arbitrum");

        // Give depositor some USDC on Ethereum
        vm.selectFork(ethereum.forkId);
        deal(address(ethereum.usdc), depositor, DEPOSIT_AMOUNT);
    }

    function test_depositAndSpendFlow() public {
        // On Ethereum: Deposit USDC
        _depositToChain(ethereum, depositor, DEPOSIT_AMOUNT);

        // Offchain: Generate burn authorization and validate
        TransferSpec memory transferSpec =
            _createTransferSpec(ethereum, arbitrum, SPEND_AMOUNT, depositor, recipient, depositor, address(0));
        (bytes memory encodedBurnAuth, bytes memory burnSignature) =
            _signBurnAuthWithTransferSpec(transferSpec, ethereum.wallet, depositorPrivateKey);
        bool isValidBurnAuth = ethereum.wallet.validateBurnAuthorizations(encodedBurnAuth, burnSignature);
        assertTrue(isValidBurnAuth);

        // Offchain: Generate mint authorization given valid burn authorization
        vm.selectFork(arbitrum.forkId);
        (bytes memory encodedMintAuth, bytes memory mintSignature) =
            _signMintAuthWithTransferSpec(transferSpec, arbitrum.minterMintSignerKey);

        // On Arbitrum: Mint using mint authorization
        _mintFromChain(
            arbitrum,
            encodedMintAuth,
            mintSignature,
            SPEND_AMOUNT, /* expected supply increment */
            SPEND_AMOUNT, /* expected recipient balance increment */
            0 /* expected depositor balance decrement */
        );

        // On Ethereum: Burn spent amount
        _burnFromChain(
            ethereum,
            encodedBurnAuth,
            burnSignature,
            SPEND_AMOUNT, /* expected total supply decrement */
            SPEND_AMOUNT + FEE_AMOUNT /* expected depositor balance decrement */
        );
    }

    function test_depositAndSpendByDelegate() public {
        // On Ethereum:
        vm.selectFork(ethereum.forkId);

        // Depositor sets up delegate
        vm.startPrank(depositor);
        ethereum.wallet.addDelegate(address(ethereum.usdc), delegate);
        vm.stopPrank();
        assertTrue(ethereum.wallet.isAuthorizedForBalance(address(ethereum.usdc), depositor, delegate));

        // Delegate deposits depositor's funds using with permit signature
        vm.startPrank(delegate);
        uint256 deadline = block.timestamp + 1000;
        (uint8 v, bytes32 r, bytes32 s) =
            _signPermit(address(ethereum.usdc), address(ethereum.wallet), DEPOSIT_AMOUNT, deadline, depositorPrivateKey);
        bytes memory permitSignature = abi.encodePacked(r, s, v);
        ethereum.wallet.depositWithPermit(address(ethereum.usdc), depositor, DEPOSIT_AMOUNT, deadline, permitSignature);
        vm.stopPrank();
        assertEq(ethereum.usdc.balanceOf(address(ethereum.wallet)), DEPOSIT_AMOUNT);
        assertEq(ethereum.wallet.spendableBalance(address(ethereum.usdc), depositor), DEPOSIT_AMOUNT);

        // Offchain: Generate burn authorization and validate
        TransferSpec memory transferSpec =
            _createTransferSpec(ethereum, arbitrum, SPEND_AMOUNT, depositor, recipient, delegate, destinationCaller);
        (bytes memory encodedBurnAuth, bytes memory burnSignature) =
            _signBurnAuthWithTransferSpec(transferSpec, ethereum.wallet, delegatePrivateKey);
        bool isValidBurnAuth = ethereum.wallet.validateBurnAuthorizations(encodedBurnAuth, burnSignature);
        assertTrue(isValidBurnAuth);

        // Offchain: Generate mint authorization given valid burn authorization
        vm.selectFork(arbitrum.forkId);
        (bytes memory encodedMintAuth, bytes memory mintSignature) =
            _signMintAuthWithTransferSpec(transferSpec, arbitrum.minterMintSignerKey);

        // On Arbitrum: Mint using mint authorization
        _mintFromChain(
            arbitrum,
            encodedMintAuth,
            mintSignature,
            SPEND_AMOUNT, /* expected supply increment */
            SPEND_AMOUNT, /* expected recipient balance increment */
            0 /* expected depositor balance decrement */
        );

        // On Ethereum: Burn spent amount
        _burnFromChain(
            ethereum,
            encodedBurnAuth,
            burnSignature,
            SPEND_AMOUNT, /* expected total supply decrement */
            SPEND_AMOUNT + FEE_AMOUNT /* expected depositor balance decrement */
        );
    }

    function test_depositAndSameChainSpend() public {
        // On Ethereum:
        vm.selectFork(ethereum.forkId);

        // Depositor deposits with authorization
        vm.startPrank(depositor);
        uint256 validAfter = block.timestamp - 1000;
        uint256 validBefore = block.timestamp + 1000;
        bytes32 nonce = keccak256(abi.encode(vm.randomUint()));
        (uint8 v, bytes32 r, bytes32 s) = _signReceiveWithAuthorization(
            address(ethereum.usdc),
            address(ethereum.wallet),
            validAfter,
            validBefore,
            nonce,
            DEPOSIT_AMOUNT,
            depositorPrivateKey
        );
        bytes memory receiveAuthorization = abi.encodePacked(r, s, v);

        ethereum.wallet.depositWithAuthorization(
            address(ethereum.usdc), depositor, DEPOSIT_AMOUNT, validAfter, validBefore, nonce, receiveAuthorization
        );
        vm.stopPrank();
        assertEq(ethereum.usdc.balanceOf(address(ethereum.wallet)), DEPOSIT_AMOUNT);
        assertEq(ethereum.wallet.spendableBalance(address(ethereum.usdc), depositor), DEPOSIT_AMOUNT);

        // Offchain: Generate burn authorization and validate
        TransferSpec memory transferSpec =
            _createTransferSpec(ethereum, ethereum, SPEND_AMOUNT, depositor, recipient, depositor, address(0));
        (bytes memory encodedBurnAuth, bytes memory burnSignature) =
            _signBurnAuthWithTransferSpec(transferSpec, ethereum.wallet, depositorPrivateKey);
        bool isValidBurnAuth = ethereum.wallet.validateBurnAuthorizations(encodedBurnAuth, burnSignature);
        assertTrue(isValidBurnAuth);

        // Offchain: Generate mint authorization given valid burn authorization
        (bytes memory encodedMintAuth, bytes memory mintSignature) =
            _signMintAuthWithTransferSpec(transferSpec, ethereum.minterMintSignerKey);

        // On Ethereum: mint on the same chain using mint authorization
        _mintFromChain( // same chain spend
            ethereum,
            encodedMintAuth,
            mintSignature,
            0, /* no supply increment for same chain spend */
            SPEND_AMOUNT, /* expected recipient balance increment */
            SPEND_AMOUNT /* expected depositor balance decrement */
        );

        // On Ethereum: Burn spent amount
        uint256 numAuths = 1;
        bytes[] memory allBurnAuths = new bytes[](numAuths);
        allBurnAuths[0] = encodedBurnAuth;
        bytes[] memory allSignatures = new bytes[](numAuths);
        allSignatures[0] = burnSignature;
        uint256[][] memory fees = _createFees(allBurnAuths, FEE_AMOUNT);

        vm.expectRevert(Burns.NoRelevantBurnAuthorizations.selector);
        bytes memory burnSignerSignature =
            _signBurnAuthorizations(allBurnAuths, allSignatures, fees, ethereum.walletBurnSignerKey);
        ethereum.wallet.burnSpent(allBurnAuths, allSignatures, fees, burnSignerSignature);
    }
}
