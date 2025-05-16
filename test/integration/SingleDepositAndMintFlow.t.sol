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

import {TransferSpec} from "src/lib/TransferSpec.sol";
import {MultichainTestUtils} from "test/util/MultichainTestUtils.sol";

contract SingleDepositAndMintFlowTest is MultichainTestUtils {
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

    function test_depositAndMintFlow() public {
        // On Ethereum: Deposit USDC
        _depositToChain(ethereum, depositor, DEPOSIT_AMOUNT);

        // Offchain: Generate burn intent and validate
        TransferSpec memory transferSpec =
            _createTransferSpec(ethereum, arbitrum, MINT_AMOUNT, depositor, recipient, depositor, address(0));
        (bytes memory encodedBurnIntent, bytes memory burnSignature) =
            _signBurnIntentWithTransferSpec(transferSpec, ethereum.wallet, depositorPrivateKey);
        bool isValidBurnIntent = ethereum.wallet.validateBurnIntents(encodedBurnIntent, depositor);
        assertTrue(isValidBurnIntent);

        // Offchain: Generate attestation given valid burn intent
        vm.selectFork(arbitrum.forkId);
        (bytes memory encodedAttestation, bytes memory attestationSignature) =
            _signAttestationWithTransferSpec(transferSpec, arbitrum.minterAttestationSignerKey);

        // On Arbitrum: Mint using attestation
        _mintFromChain(arbitrum, encodedAttestation, attestationSignature, MINT_AMOUNT /* expected minted amount */ );

        // On Ethereum: Burn used amount
        _burnFromChain(
            ethereum,
            encodedBurnIntent,
            burnSignature,
            MINT_AMOUNT, /* expected total burnt amount */
            FEE_AMOUNT /* expected total fee amount */
        );
    }

    function test_depositAndMintByDelegate() public {
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
        assertEq(ethereum.wallet.availableBalance(address(ethereum.usdc), depositor), DEPOSIT_AMOUNT);

        // Offchain: Generate burn intent and validate
        TransferSpec memory transferSpec =
            _createTransferSpec(ethereum, arbitrum, MINT_AMOUNT, depositor, recipient, delegate, destinationCaller);
        (bytes memory encodedBurnIntent, bytes memory burnSignature) =
            _signBurnIntentWithTransferSpec(transferSpec, ethereum.wallet, delegatePrivateKey);
        bool isValidBurnIntent = ethereum.wallet.validateBurnIntents(encodedBurnIntent, delegate);
        assertTrue(isValidBurnIntent);

        // Offchain: Generate attestation given valid burn intent
        vm.selectFork(arbitrum.forkId);
        (bytes memory encodedAttestation, bytes memory attestationSignature) =
            _signAttestationWithTransferSpec(transferSpec, arbitrum.minterAttestationSignerKey);

        // On Arbitrum: Mint using attestation
        _mintFromChain(arbitrum, encodedAttestation, attestationSignature, MINT_AMOUNT /* expected minted amount */ );

        // On Ethereum: Burn used amount
        _burnFromChain(
            ethereum,
            encodedBurnIntent,
            burnSignature,
            MINT_AMOUNT, /* expected total burnt amount */
            FEE_AMOUNT /* expected total fee amount */
        );
    }

    function test_depositAndSameChainMintAndBurn() public {
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
        assertEq(ethereum.wallet.availableBalance(address(ethereum.usdc), depositor), DEPOSIT_AMOUNT);

        // Offchain: Generate burn intent and validate
        TransferSpec memory transferSpec =
            _createTransferSpec(ethereum, ethereum, MINT_AMOUNT, depositor, recipient, depositor, address(0));
        (bytes memory encodedBurnIntent, bytes memory burnSignature) =
            _signBurnIntentWithTransferSpec(transferSpec, ethereum.wallet, depositorPrivateKey);
        bool isValidBurnIntent = ethereum.wallet.validateBurnIntents(encodedBurnIntent, depositor);
        assertTrue(isValidBurnIntent);

        // Offchain: Generate attestation given valid burn intent
        (bytes memory encodedAttestation, bytes memory attestationSignature) =
            _signAttestationWithTransferSpec(transferSpec, ethereum.minterAttestationSignerKey);

        // On Ethereum: mint on the same chain using attestation
        _mintFromChain( // same chain transfer
        ethereum, encodedAttestation, attestationSignature, MINT_AMOUNT /* expected minted amount */ );

        // On Ethereum: Burn used amount
        _burnFromChain(
            ethereum,
            encodedBurnIntent,
            burnSignature,
            MINT_AMOUNT, /* expected total burnt amount */
            FEE_AMOUNT /* expected total fee amount */
        );
    }
}
