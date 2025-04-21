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

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {Counterpart} from "src/lib/common/Counterpart.sol";
import {DelegationStorage} from "src/lib/wallet/Delegation.sol";
import {Denylistable} from "src/lib/common/Denylistable.sol";
import {TokenSupport} from "src/lib/common/TokenSupport.sol";
import {SpendWallet} from "src/SpendWallet.sol";
import {BurnLib} from "src/lib/wallet/BurnLib.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";
import {FiatTokenV2_2} from "../mock_fiattoken/contracts/v2/FiatTokenV2_2.sol";
import {Test} from "forge-std/Test.sol";

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
        wallet = deployWalletOnly(owner);
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

    function test_sameChainSpend_revertsWhenPaused() external {
        vm.prank(pauser);
        wallet.pause();
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);

        vm.prank(minterContract);
        wallet.sameChainSpend(
            usdc, depositor, recipient, authorizer, spendValue, keccak256(emptyAuthorization), emptyAuthorization
        );
    }

    function test_sameChainSpend_revertsWhenCallerIsNotCounterpart() external {
        address randomCaller = makeAddr("randomCaller");
        vm.expectRevert(abi.encodeWithSelector(Counterpart.UnauthorizedCounterpart.selector, address(randomCaller)));

        vm.prank(randomCaller);
        wallet.sameChainSpend(
            usdc, depositor, recipient, authorizer, spendValue, keccak256(emptyAuthorization), emptyAuthorization
        );
    }

    function test_sameChainSpend_revertsWhenTokenNotSupported() external {
        address unsupportedToken = makeAddr("unsupportedToken");
        vm.expectRevert(abi.encodeWithSelector(TokenSupport.UnsupportedToken.selector, unsupportedToken));

        vm.prank(minterContract);
        wallet.sameChainSpend(
            unsupportedToken,
            depositor,
            recipient,
            authorizer,
            spendValue,
            keccak256(emptyAuthorization),
            emptyAuthorization
        );
    }

    function test_sameChainSpend_revertsWhenDepositorIsDenylisted() external {
        vm.prank(denylister);
        wallet.denylist(depositor);
        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, depositor));

        vm.prank(minterContract);
        wallet.sameChainSpend(
            usdc, depositor, recipient, authorizer, spendValue, keccak256(emptyAuthorization), emptyAuthorization
        );
    }

    function test_sameChainSpend_revertsWhenAuthorizerIsDenylisted() external {
        vm.prank(denylister);
        wallet.denylist(authorizer);
        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, authorizer));

        vm.prank(minterContract);
        wallet.sameChainSpend(
            usdc, depositor, recipient, authorizer, spendValue, keccak256(emptyAuthorization), emptyAuthorization
        );
    }

    function test_sameChainSpend_revertsWhenAuthorizerIsNotDelegate() external {
        address notDelegate = makeAddr("notDelegate");
        vm.expectRevert(DelegationStorage.NotAuthorized.selector);

        vm.prank(minterContract);
        wallet.sameChainSpend(
            usdc, depositor, recipient, notDelegate, spendValue, keccak256(emptyAuthorization), emptyAuthorization
        );
    }

    function test_sameChainSpend_revertsIfBalanceInsufficient() external {
        bytes32 spendHash = keccak256(emptyAuthorization);
        vm.prank(depositor);
        wallet.deposit(usdc, spendValue - 1); // Deposit less than spend amount
        vm.expectRevert(BurnLib.InsufficientBalanceForSameChainSpend.selector);

        vm.prank(minterContract);
        wallet.sameChainSpend(usdc, depositor, recipient, authorizer, spendValue, spendHash, emptyAuthorization);
    }

    function test_sameChainSpend_succeedsWithSpendableBalanceOnly() external {
        bytes32 spendHash = keccak256(emptyAuthorization);
        vm.prank(depositor);
        wallet.deposit(usdc, spendValue);
        vm.expectEmit(true, true, true, true);
        emit BurnLib.TransferredSpent(
            usdc, depositor, spendHash, recipient, authorizer, spendValue, spendValue, 0, emptyAuthorization
        );

        vm.prank(minterContract);
        wallet.sameChainSpend(usdc, depositor, recipient, authorizer, spendValue, spendHash, emptyAuthorization);
        assertEq(FiatTokenV2_2(usdc).balanceOf(recipient), spendValue);
        assertEq(wallet.spendableBalance(usdc, depositor), 0);
        assertEq(wallet.withdrawingBalance(usdc, depositor), 0);
        assertEq(wallet.totalBalance(usdc, depositor), 0);
    }

    function test_sameChainSpend_succeedsWithWithdrawingBalanceOnly() external {
        bytes32 spendHash = keccak256(emptyAuthorization);
        vm.startPrank(depositor);
        {
            wallet.deposit(usdc, spendValue);
            wallet.initiateWithdrawal(usdc, spendValue);
        }
        vm.stopPrank();
        vm.expectEmit(true, true, true, true);
        emit BurnLib.TransferredSpent(
            usdc, depositor, spendHash, recipient, authorizer, spendValue, 0, spendValue, emptyAuthorization
        );

        vm.prank(minterContract);
        wallet.sameChainSpend(usdc, depositor, recipient, authorizer, spendValue, spendHash, emptyAuthorization);
        assertEq(FiatTokenV2_2(usdc).balanceOf(recipient), spendValue);
        assertEq(wallet.spendableBalance(usdc, depositor), 0);
        assertEq(wallet.withdrawingBalance(usdc, depositor), 0);
        assertEq(wallet.totalBalance(usdc, depositor), 0);
    }

    function test_sameChainSpend_succeedsWithBothBalances() external {
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
        emit BurnLib.TransferredSpent(
            usdc,
            depositor,
            spendHash,
            recipient,
            authorizer,
            spendValue,
            spendableAmount,
            withdrawingAmount,
            emptyAuthorization
        );

        vm.prank(minterContract);
        wallet.sameChainSpend(usdc, depositor, recipient, authorizer, spendValue, spendHash, emptyAuthorization);

        assertEq(FiatTokenV2_2(usdc).balanceOf(recipient), spendValue);
        assertEq(wallet.spendableBalance(usdc, depositor), 0);
        assertEq(wallet.withdrawingBalance(usdc, depositor), 0);
        assertEq(wallet.totalBalance(usdc, depositor), 0);
    }
}
