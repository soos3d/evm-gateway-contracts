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

import {TransferSpec} from "src/lib/authorizations/TransferSpec.sol";
import {MultichainTestUtils} from "./../util/MultichainTestUtils.sol";

contract AttemptedDoubleSpendTest is MultichainTestUtils {
    ChainSetup private ethereum;
    ChainSetup private arbitrum;

    function setUp() public {
        // Setup Ethereum fork
        ethereum = _initializeGatewayContracts("ethereum");

        // Setup Arbitrum fork
        arbitrum = _initializeGatewayContracts("arbitrum");
    }

    function test_attemptedDoubleSpend_allowWithdrawingRemainingBalance() public {
        // On Ethereum: Deposit USDC
        _depositToChain(ethereum, depositor, DEPOSIT_AMOUNT);

        // On Ethereum: Initiate USDC withdrawal
        vm.startPrank(depositor);
        uint256 blockHeightWhenInitiatingWithdrawal = block.number;
        ethereum.wallet.initiateWithdrawal(address(ethereum.usdc), DEPOSIT_AMOUNT);
        vm.stopPrank();
        assertEq(ethereum.wallet.availableBalance(address(ethereum.usdc), depositor), 0);
        assertEq(ethereum.wallet.withdrawingBalance(address(ethereum.usdc), depositor), DEPOSIT_AMOUNT);
        assertEq(ethereum.wallet.withdrawableBalance(address(ethereum.usdc), depositor), 0);

        // Offchain: Generate burn authorization and validate
        TransferSpec memory transferSpec =
            _createTransferSpec(ethereum, arbitrum, MINT_AMOUNT, depositor, recipient, depositor, address(0));
        (bytes memory encodedBurnAuth, bytes memory burnSignature) =
            _signBurnAuthWithTransferSpec(transferSpec, ethereum.wallet, depositorPrivateKey);
        bool isValidBurnAuth = ethereum.wallet.validateBurnAuthorizations(encodedBurnAuth, depositor);
        assertTrue(isValidBurnAuth);

        // Offchain: Generate mint authorization given valid burn authorization
        vm.selectFork(arbitrum.forkId);
        (bytes memory encodedMintAuth, bytes memory mintSignature) =
            _signMintAuthWithTransferSpec(transferSpec, arbitrum.minterMintSignerKey);

        // On Arbitrum: Mint using mint authorization
        _mintFromChain(arbitrum, encodedMintAuth, mintSignature, MINT_AMOUNT /* expected total minted amount */ );

        // On Ethereum: Burn used amount
        _burnFromChain(
            ethereum,
            encodedBurnAuth,
            burnSignature,
            MINT_AMOUNT, /* expected total burnt amount */
            FEE_AMOUNT /* expected total fee amount */
        );

        uint256 expectedRemainingBalance = DEPOSIT_AMOUNT - MINT_AMOUNT - FEE_AMOUNT;
        assertEq(ethereum.wallet.availableBalance(address(ethereum.usdc), depositor), 0);
        assertEq(ethereum.wallet.withdrawingBalance(address(ethereum.usdc), depositor), expectedRemainingBalance);
        assertEq(ethereum.wallet.withdrawableBalance(address(ethereum.usdc), depositor), 0);

        // Fast forward to 3 days later
        vm.roll(blockHeightWhenInitiatingWithdrawal + WITHDRAW_DELAY + 1000);
        assertEq(ethereum.wallet.availableBalance(address(ethereum.usdc), depositor), 0);
        assertEq(ethereum.wallet.withdrawingBalance(address(ethereum.usdc), depositor), expectedRemainingBalance);
        assertEq(ethereum.wallet.withdrawableBalance(address(ethereum.usdc), depositor), expectedRemainingBalance);

        // On Ethereum: Withdraw succeeds but only the remaining balance is withdrawn
        vm.prank(depositor);
        ethereum.wallet.withdraw(address(ethereum.usdc));
        assertEq(ethereum.usdc.balanceOf(depositor), expectedRemainingBalance);
        assertEq(ethereum.wallet.availableBalance(address(ethereum.usdc), depositor), 0);
        assertEq(ethereum.wallet.withdrawingBalance(address(ethereum.usdc), depositor), 0);
        assertEq(ethereum.wallet.withdrawableBalance(address(ethereum.usdc), depositor), 0);
    }
}
