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
pragma solidity ^0.8.29;

import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Test} from "forge-std/Test.sol";
import {Counterpart} from "src/modules/common/Counterpart.sol";
import {Denylistable} from "src/modules/common/Denylistable.sol";
import {TokenSupport} from "src/modules/common/TokenSupport.sol";
import {Burns} from "src/modules/wallet/Burns.sol";
import {Delegation} from "src/modules/wallet/Delegation.sol";
import {SpendWallet} from "src/SpendWallet.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";
import {FiatTokenV2_2} from "./../mock_fiattoken/contracts/v2/FiatTokenV2_2.sol";

contract TestSameChainSpend is Test, DeployUtils {
    using MessageHashUtils for bytes32;

    SpendWallet private wallet;
    address private owner = makeAddr("owner");
    address private denylister = makeAddr("denylister");
    address private pauser = makeAddr("pauser");
    address private depositor = makeAddr("depositor");
    address private recipient = makeAddr("recipient");
    address private authorizer = makeAddr("authorizer");
    address private usdc;
    address private minterContract = makeAddr("minterContract");
    uint256 private spendValue = 100;
    bytes private emptyAuthorization = new bytes(0);

    function setUp() public {
        wallet = deployWalletOnly(owner, ForkTestUtils.forkVars().domain);
        usdc = ForkTestUtils.forkVars().usdc;

        vm.startPrank(owner);
        {
            wallet.updateCounterpart(minterContract);
            wallet.addSupportedToken(usdc);
            wallet.updateDenylister(denylister);
            wallet.updatePauser(pauser);
        }
        vm.stopPrank();

        vm.startPrank(depositor);
        {
            deal(usdc, depositor, spendValue);
            FiatTokenV2_2(usdc).approve(address(wallet), type(uint256).max);
            wallet.addDelegate(usdc, authorizer);
        }
        vm.stopPrank();
    }

    function test_sameChainSpend_revertsWhenPaused() public {
        vm.prank(pauser);
        wallet.pause();
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);

        vm.prank(minterContract);
        wallet.sameChainSpend(usdc, depositor, recipient, authorizer, spendValue, keccak256(emptyAuthorization));
    }

    function test_sameChainSpend_revertsWhenCallerIsNotCounterpart() public {
        address randomCaller = makeAddr("randomCaller");
        vm.expectRevert(abi.encodeWithSelector(Counterpart.UnauthorizedCounterpart.selector, address(randomCaller)));

        vm.prank(randomCaller);
        wallet.sameChainSpend(usdc, depositor, recipient, authorizer, spendValue, keccak256(emptyAuthorization));
    }

    function test_sameChainSpend_revertsWhenTokenNotSupported() public {
        address unsupportedToken = makeAddr("unsupportedToken");
        vm.expectRevert(abi.encodeWithSelector(TokenSupport.UnsupportedToken.selector, unsupportedToken));

        vm.prank(minterContract);
        wallet.sameChainSpend(
            unsupportedToken, depositor, recipient, authorizer, spendValue, keccak256(emptyAuthorization)
        );
    }

    function test_sameChainSpend_revertsWhenDepositorIsDenylisted() public {
        vm.prank(denylister);
        wallet.denylist(depositor);
        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, depositor));

        vm.prank(minterContract);
        wallet.sameChainSpend(usdc, depositor, recipient, authorizer, spendValue, keccak256(emptyAuthorization));
    }

    function test_sameChainSpend_revertsWhenAuthorizerIsDenylisted() public {
        vm.prank(denylister);
        wallet.denylist(authorizer);
        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, authorizer));

        vm.prank(minterContract);
        wallet.sameChainSpend(usdc, depositor, recipient, authorizer, spendValue, keccak256(emptyAuthorization));
    }

    function test_sameChainSpend_revertsWhenAuthorizerIsNotDelegate() public {
        address notDelegate = makeAddr("notDelegate");
        vm.expectRevert(Delegation.NotAuthorized.selector);

        vm.prank(minterContract);
        wallet.sameChainSpend(usdc, depositor, recipient, notDelegate, spendValue, keccak256(emptyAuthorization));
    }

    function test_sameChainSpend_revertsIfBalanceInsufficient() public {
        bytes32 spendHash = keccak256(emptyAuthorization);
        vm.prank(depositor);
        wallet.deposit(usdc, spendValue - 1); // Deposit less than spend amount
        vm.expectRevert(Burns.InsufficientBalanceForSameChainSpend.selector);

        vm.prank(minterContract);
        wallet.sameChainSpend(usdc, depositor, recipient, authorizer, spendValue, spendHash);
    }

    function test_sameChainSpend_succeedsWithSpendableBalanceOnly() public {
        bytes32 spendHash = keccak256(emptyAuthorization);
        vm.prank(depositor);
        wallet.deposit(usdc, spendValue);
        vm.expectEmit(true, true, true, true);
        emit Burns.TransferredSpent(usdc, depositor, spendHash, recipient, authorizer, spendValue, spendValue, 0);

        vm.prank(minterContract);
        wallet.sameChainSpend(usdc, depositor, recipient, authorizer, spendValue, spendHash);
        assertEq(FiatTokenV2_2(usdc).balanceOf(recipient), spendValue);
        assertEq(wallet.spendableBalance(usdc, depositor), 0);
        assertEq(wallet.withdrawingBalance(usdc, depositor), 0);
        assertEq(wallet.totalBalance(usdc, depositor), 0);
    }

    function test_sameChainSpend_succeedsWithWithdrawingBalanceOnly() public {
        bytes32 spendHash = keccak256(emptyAuthorization);
        vm.startPrank(depositor);
        {
            wallet.deposit(usdc, spendValue);
            wallet.initiateWithdrawal(usdc, spendValue);
        }
        vm.stopPrank();
        vm.expectEmit(true, true, true, true);
        emit Burns.TransferredSpent(usdc, depositor, spendHash, recipient, authorizer, spendValue, 0, spendValue);

        vm.prank(minterContract);
        wallet.sameChainSpend(usdc, depositor, recipient, authorizer, spendValue, spendHash);
        assertEq(FiatTokenV2_2(usdc).balanceOf(recipient), spendValue);
        assertEq(wallet.spendableBalance(usdc, depositor), 0);
        assertEq(wallet.withdrawingBalance(usdc, depositor), 0);
        assertEq(wallet.totalBalance(usdc, depositor), 0);
    }

    function test_sameChainSpend_succeedsWithBothBalances() public {
        bytes32 spendHash = keccak256(emptyAuthorization);
        uint256 withdrawingAmount = 10;
        uint256 spendableAmount = spendValue - withdrawingAmount;

        vm.startPrank(depositor);
        {
            wallet.deposit(usdc, spendValue);
            wallet.initiateWithdrawal(usdc, withdrawingAmount);
        }
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit Burns.TransferredSpent(
            usdc, depositor, spendHash, recipient, authorizer, spendValue, spendableAmount, withdrawingAmount
        );

        vm.prank(minterContract);
        wallet.sameChainSpend(usdc, depositor, recipient, authorizer, spendValue, spendHash);

        assertEq(FiatTokenV2_2(usdc).balanceOf(recipient), spendValue);
        assertEq(wallet.spendableBalance(usdc, depositor), 0);
        assertEq(wallet.withdrawingBalance(usdc, depositor), 0);
        assertEq(wallet.totalBalance(usdc, depositor), 0);
    }
}
