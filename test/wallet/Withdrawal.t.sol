/*
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.

 * SPDX-License-Identifier: GPL-3.0-or-later

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
pragma solidity ^0.8.28;

import {SpendWallet} from "src/SpendWallet.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Test} from "forge-std/Test.sol";

/// Tests withdrawal functionality of SpendWallet
contract SpendWalletWithdrawalTest is Test, DeployUtils {
    address private owner = makeAddr("owner");
    address private depositor = makeAddr("depositor");
    address private spender = makeAddr("spender");
    address private usdc;

    uint256 private initialUsdcBalance = 1000 * 10 ** 6;
    uint256 private initialWithdrawalDelay = 100;
    SpendWallet private wallet;

    enum WithdrawalType {
        Direct,
        Authorized
    }

    WithdrawalType private withdrawalType;

    function setUp() public {
        wallet = deployWalletOnly(owner);

        usdc = ForkTestUtils.forkVars().usdc;
        // Mint initial USDC balance to depositor
        deal(usdc, depositor, initialUsdcBalance);

        vm.startPrank(owner);
        wallet.addSupportedToken(usdc);
        wallet.updateWithdrawalDelay(initialWithdrawalDelay);
        vm.stopPrank();

        vm.startPrank(depositor);
        IERC20(usdc).approve(address(wallet), initialUsdcBalance);
        wallet.deposit(usdc, initialUsdcBalance);
        vm.stopPrank();
    }

    // Modifier to run tests for both direct and authorized withdrawals
    modifier testWithdrawalTypes() {
        // Run test for direct withdrawal
        withdrawalType = WithdrawalType.Direct;
        _;
        
        // Run test for authorized withdrawal
        setUp();
        withdrawalType = WithdrawalType.Authorized;
        vm.startPrank(depositor);
        wallet.addSpender(usdc, spender);
        vm.stopPrank();
        _;
    }

    // ===== Helper Functions =====

    // Helper function to verify initial state for a depositor
    function _assertInitialState(address depositorAddress) internal view {
        assertEq(IERC20(usdc).balanceOf(depositorAddress), 0);
        assertEq(wallet.spendableBalance(usdc, depositorAddress), initialUsdcBalance);
        assertEq(wallet.withdrawingBalance(usdc, depositorAddress), 0);
        assertEq(wallet.withdrawableBalance(usdc, depositorAddress), 0);
        assertEq(wallet.withdrawalBlock(usdc, depositorAddress), 0);
    }

    // Helper function to verify state after withdrawal initiation for a depositor
    function _initiateWithdrawalAndVerifyState(
        WithdrawalType withdrawalType_,
        address actor,
        address depositorAddress,
        uint256 withdrawalAmount,
        uint256 expectedTotalWithdrawalAmount,
        uint256 expectedSpendableBalance, 
        uint256 expectedWithdrawingBalance, 
        uint256 expectedWithdrawableBalance, 
        uint256 expectedWithdrawalBlock) internal {
        vm.startPrank(actor);
        vm.expectEmit(true, true, false, true);
        emit SpendWallet.WithdrawalInitiated(
            usdc, 
            depositorAddress,
            actor,
            withdrawalAmount, 
            expectedTotalWithdrawalAmount, 
            expectedWithdrawalBlock
        );
        
        if (withdrawalType_ == WithdrawalType.Direct) {
            wallet.initiateWithdrawal(usdc, withdrawalAmount);
        } else {
            wallet.initiateWithdrawal(usdc, depositorAddress, withdrawalAmount);
        }
        vm.stopPrank();

        assertEq(wallet.spendableBalance(usdc, depositorAddress), expectedSpendableBalance);
        assertEq(wallet.withdrawingBalance(usdc, depositorAddress), expectedWithdrawingBalance);
        assertEq(wallet.withdrawableBalance(usdc, depositorAddress), expectedWithdrawableBalance);
        assertEq(wallet.withdrawalBlock(usdc, depositorAddress), expectedWithdrawalBlock);
    }

    // Helper function to verify state after withdrawal completion for a depositor
    function _completeWithdrawalAndVerifyState(
        WithdrawalType withdrawalType_,
        address actor,
        address depositorAddress,
        uint256 expectedWithdrawalAmount, 
        uint256 expectedSpendableBalance, 
        uint256 expectedWithdrawingBalance, 
        uint256 expectedWithdrawableBalance) internal {
        vm.startPrank(actor);
        vm.expectEmit(true, true, false, true);
        emit SpendWallet.WithdrawalCompleted(
            usdc, 
            depositorAddress,
            actor, 
            expectedWithdrawalAmount
        );
        if (withdrawalType_ == WithdrawalType.Direct) {
            wallet.withdraw(usdc);
        } else {
            wallet.withdraw(usdc, depositorAddress);
        }
        vm.stopPrank();

        assertEq(wallet.spendableBalance(usdc, depositorAddress), expectedSpendableBalance);
        assertEq(wallet.withdrawingBalance(usdc, depositorAddress), expectedWithdrawingBalance);
        assertEq(wallet.withdrawableBalance(usdc, depositorAddress), expectedWithdrawableBalance);
        assertEq(wallet.withdrawalBlock(usdc, depositorAddress), 0);
    }

    // ===== Basic Error Tests - Withdrawal Initiation =====

    function test_directInitiateWithdrawal_revertIfValueIsZero() public {
        vm.startPrank(depositor);
        vm.expectRevert(SpendWallet.WithdrawalValueMustBePositive.selector);
        wallet.initiateWithdrawal(usdc, 0);
        vm.stopPrank();
    }

    function test_authorizedInitiateWithdrawal_revertIfValueIsZero() public {
        vm.startPrank(depositor);
        wallet.addSpender(usdc, spender);
        vm.stopPrank();
        
        vm.startPrank(spender);
        vm.expectRevert(SpendWallet.WithdrawalValueMustBePositive.selector);
        wallet.initiateWithdrawal(usdc, depositor, 0);
        vm.stopPrank();
    }

    function test_directInitiateWithdrawal_revertIfValueExceedsSpendableBalance() public {
        vm.startPrank(depositor);
        vm.expectRevert(SpendWallet.WithdrawalValueExceedsSpendableBalance.selector);
        wallet.initiateWithdrawal(usdc, 2 * initialUsdcBalance);
        vm.stopPrank();
    }

    function test_authorizedInitiateWithdrawal_revertIfValueExceedsSpendableBalance() public {
        vm.startPrank(depositor);
        wallet.addSpender(usdc, spender);
        vm.stopPrank();
        
        vm.startPrank(spender);
        vm.expectRevert(SpendWallet.WithdrawalValueExceedsSpendableBalance.selector);
        wallet.initiateWithdrawal(usdc, depositor, 2 * initialUsdcBalance);
        vm.stopPrank();
    }

    function test_initiateWithdrawal_revertIfNotAuthorized() public {
        address unauthorizedSpender = makeAddr("unauthorized");
        vm.startPrank(unauthorizedSpender);
        vm.expectRevert(SpendWallet.UnauthorizedSpender.selector);
        wallet.initiateWithdrawal(usdc, depositor, initialUsdcBalance / 4);
        vm.stopPrank();
    }

    // ===== Basic Error Tests - Withdrawal Completion =====

    function test_withdrawal_revertIfNotAuthorized() public {
        // First initiate withdrawal as depositor
        uint256 withdrawalAmount = initialUsdcBalance / 4;
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(usdc, withdrawalAmount);
        vm.stopPrank();

        // Try to complete withdrawal as unauthorized spender
        address unauthorizedSpender = makeAddr("unauthorized");
        vm.startPrank(unauthorizedSpender);
        vm.expectRevert(SpendWallet.UnauthorizedSpender.selector);
        wallet.withdraw(usdc, depositor);
        vm.stopPrank();
    }

    function test_directWithdrawal_revertIfNoWithdrawingBalance() public {
        vm.startPrank(depositor);
        vm.expectRevert(SpendWallet.NoWithdrawingBalance.selector);
        wallet.withdraw(usdc);
        vm.stopPrank();
    }

    function test_authorizedWithdrawal_revertIfNoWithdrawingBalance() public {
        vm.startPrank(depositor);
        wallet.addSpender(usdc, spender);
        vm.stopPrank();
        
        vm.startPrank(spender);
        vm.expectRevert(SpendWallet.NoWithdrawingBalance.selector);
        wallet.withdraw(usdc, depositor);
        vm.stopPrank();
    }

    // ===== Full Withdrawal Flow Tests =====

    /// Tests that withdrawal cannot be completed before the delay period
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in spendable balance
    /// 2. Initiate withdrawal of 1/4 initialUsdcBalance:
    ///    - spendable balance decreases by withdrawal amount
    ///    - withdrawing balance increases by withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. Attempt immediate withdrawal -> reverts with WithdrawalNotYetAvailable
    /// 4. Attempt withdrawal one block before delay -> reverts with WithdrawalNotYetAvailable
    function test_withdrawal_revertIfWithdrawalNotYetAvailable() public testWithdrawalTypes {
        _assertInitialState(depositor);

        uint256 withdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = withdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - withdrawalAmount;
        uint256 expectedWithdrawingBalance = withdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            withdrawalType,
            withdrawalType == WithdrawalType.Direct ? depositor : spender,
            depositor,
            withdrawalAmount,
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance,
            expectedBlockHeightWhenWithdrawable);

        // Attempt to withdraw immediately
        address actor = withdrawalType == WithdrawalType.Direct ? depositor : spender;
        vm.startPrank(actor);
        vm.expectRevert(SpendWallet.WithdrawalNotYetAvailable.selector);
        if (withdrawalType == WithdrawalType.Direct) {
            wallet.withdraw(usdc);
        } else {
            wallet.withdraw(usdc, depositor);
        }
        vm.stopPrank();

        // Jump to one block before the withdrawal is available
        vm.roll(expectedBlockHeightWhenWithdrawable - 1);

        // Attempt to withdraw again
        vm.startPrank(actor);
        vm.expectRevert(SpendWallet.WithdrawalNotYetAvailable.selector);
        if (withdrawalType == WithdrawalType.Direct) {
            wallet.withdraw(usdc);
        } else {
            wallet.withdraw(usdc, depositor);
        }
        vm.stopPrank();
    }

    /// Tests a simple withdrawal flow with state transitions
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in spendable balance
    /// 2. Initiate withdrawal of 1/4 initialUsdcBalance:
    ///    - spendable balance decreases by withdrawal amount
    ///    - withdrawing balance increases by withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. After delay:
    ///    - withdrawing balance transfers to actor (depositor for direct, spender for authorized)
    ///    - withdrawing balance and withdrawal block reset to 0
    function test_withdrawal_balancesUpdatedAfterSimpleWithdrawal() public testWithdrawalTypes {
        _assertInitialState(depositor);
        uint256 withdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = withdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - withdrawalAmount;
        uint256 expectedWithdrawingBalance = withdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            withdrawalType,
            withdrawalType == WithdrawalType.Direct ? depositor : spender,
            depositor,
            withdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance, 
            expectedBlockHeightWhenWithdrawable
        );
        
        // Jump to block height when the withdrawal should be withdrawable
        vm.roll(expectedBlockHeightWhenWithdrawable);
        expectedWithdrawingBalance = 0;
        expectedWithdrawableBalance = 0;
        
        address actor = withdrawalType == WithdrawalType.Direct ? depositor : spender;
        _completeWithdrawalAndVerifyState(
            withdrawalType,
            actor,
            depositor,
            withdrawalAmount,
            expectedSpendableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance
        );
        assertEq(IERC20(usdc).balanceOf(actor), withdrawalAmount);
    }

    // ===== Multiple Withdrawals Tests =====

    /// Tests initiating a second withdrawal before first withdrawal is ready
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in spendable balance
    /// 2. Initiate first withdrawal of 1/4 initialUsdcBalance:
    ///    - spendable balance decreases by first withdrawal amount
    ///    - withdrawing balance increases by first withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. At halfway point:
    ///    - Initiate second withdrawal of 1/2 initialUsdcBalance
    ///    - spendable balance decreases by second withdrawal amount
    ///    - withdrawing balance increases by second withdrawal amount
    ///    - withdrawal block resets to current block + withdrawalDelay (new delay starts from this point)
    /// 4. After delay:
    ///    - total withdrawing balance transfers to actor (depositor for direct, spender for authorized)
    ///    - withdrawing balance and withdrawal block reset to 0
    function test_withdrawal_secondWithdrawalBeforeFirstWithdrawalIsReadyUpdatesBalancesAndResetsTimer() public testWithdrawalTypes {
        _assertInitialState(depositor);
        
        // Initiate first withdrawal
        uint256 firstWithdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = firstWithdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount;
        uint256 expectedWithdrawingBalance = firstWithdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedFirstBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            withdrawalType,
            withdrawalType == WithdrawalType.Direct ? depositor : spender,
            depositor,
            firstWithdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance, 
            expectedFirstBlockHeightWhenWithdrawable);

        // Jump to halfway through the withdrawal delay
        vm.roll(vm.getBlockNumber() + wallet.withdrawalDelay() / 2);

        // Initiate second withdrawal
        uint256 secondWithdrawalAmount = initialUsdcBalance / 2;
        expectedTotalWithdrawalAmount = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount - secondWithdrawalAmount;
        expectedWithdrawingBalance = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedWithdrawableBalance = 0;
        uint256 expectedSecondBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            withdrawalType,
            withdrawalType == WithdrawalType.Direct ? depositor : spender,
            depositor,
            secondWithdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance,
            expectedSecondBlockHeightWhenWithdrawable);
        
        // Jump to block height when the second withdrawal should be withdrawable
        vm.roll(expectedSecondBlockHeightWhenWithdrawable);
        expectedWithdrawingBalance = 0;
        expectedWithdrawableBalance = 0;
        
        address actor = withdrawalType == WithdrawalType.Direct ? depositor : spender;
        _completeWithdrawalAndVerifyState(
            withdrawalType,
            actor,
            depositor,
            firstWithdrawalAmount + secondWithdrawalAmount,
            expectedSpendableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance
        );
        assertEq(IERC20(usdc).balanceOf(actor), firstWithdrawalAmount + secondWithdrawalAmount);
    }

    /// Tests initiating a second withdrawal after first withdrawal is ready
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in spendable balance
    /// 2. Initiate first withdrawal of 1/4 initialUsdcBalance:
    ///    - spendable balance decreases by first withdrawal amount
    ///    - withdrawing balance increases by first withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. After first withdrawal delay:
    ///    - Initiate second withdrawal of 1/2 initialUsdcBalance
    ///    - spendable balance decreases by second withdrawal amount
    ///    - withdrawing balance increases by second withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 4. After second delay:
    ///    - total withdrawing balance transfers to actor (depositor for direct, spender for authorized)
    ///    - withdrawing balance and withdrawal block reset to 0
    function test_withdrawal_secondWithdrawalAfterFirstWithdrawalIsReadyUpdatesBalancesAndResetsTimer() public testWithdrawalTypes {
        _assertInitialState(depositor);
        
        // Initiate first withdrawal
        uint256 firstWithdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = firstWithdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount;
        uint256 expectedWithdrawingBalance = firstWithdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedFirstBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            withdrawalType,
            withdrawalType == WithdrawalType.Direct ? depositor : spender,
            depositor,
            firstWithdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance, 
            expectedFirstBlockHeightWhenWithdrawable);

        // Jump to after first withdrawal is ready
        vm.roll(2 * expectedFirstBlockHeightWhenWithdrawable);

        // Initiate second withdrawal
        uint256 secondWithdrawalAmount = initialUsdcBalance / 2;
        expectedTotalWithdrawalAmount = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount - secondWithdrawalAmount;
        expectedWithdrawingBalance = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedWithdrawableBalance = 0;
        uint256 expectedSecondBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            withdrawalType,
            withdrawalType == WithdrawalType.Direct ? depositor : spender,
            depositor,
            secondWithdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance,
            expectedSecondBlockHeightWhenWithdrawable);
        
        // Jump to block height when the second withdrawal should be withdrawable
        vm.roll(expectedSecondBlockHeightWhenWithdrawable);
        expectedWithdrawingBalance = 0;
        expectedWithdrawableBalance = 0;
        
        address actor = withdrawalType == WithdrawalType.Direct ? depositor : spender;
        _completeWithdrawalAndVerifyState(
            withdrawalType,
            actor,
            depositor,
            firstWithdrawalAmount + secondWithdrawalAmount,
            expectedSpendableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance
        );
        assertEq(IERC20(usdc).balanceOf(actor), firstWithdrawalAmount + secondWithdrawalAmount);
    }

    /// Tests two concurrent withdrawals initiated at the same time
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in spendable balance
    /// 2. Initiate first withdrawal of 1/4 initialUsdcBalance:
    ///    - spendable balance decreases by first withdrawal amount
    ///    - withdrawing balance increases by first withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. Immediately initiate second withdrawal of 1/2 initialUsdcBalance:
    ///    - spendable balance decreases by second withdrawal amount
    ///    - withdrawing balance increases by second withdrawal amount
    ///    - withdrawal block remains at current block + withdrawalDelay (both withdrawals share same delay)
    /// 4. After delay:
    ///    - total withdrawing balance transfers to actor (depositor for direct, spender for authorized)
    ///    - withdrawing balance and withdrawal block reset to 0
    function test_withdrawal_twoConcurrentWithdrawalsUpdatesBalances() public testWithdrawalTypes {
        _assertInitialState(depositor);

        // Initiate first withdrawal
        uint256 firstWithdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = firstWithdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount;
        uint256 expectedWithdrawingBalance = firstWithdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedFirstBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            withdrawalType,
            withdrawalType == WithdrawalType.Direct ? depositor : spender,
            depositor,
            firstWithdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance, 
            expectedFirstBlockHeightWhenWithdrawable);
        
        // Initiate second withdrawal
        uint256 secondWithdrawalAmount = initialUsdcBalance / 2;
        expectedTotalWithdrawalAmount = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount - secondWithdrawalAmount;
        expectedWithdrawingBalance = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedWithdrawableBalance = 0;
        _initiateWithdrawalAndVerifyState(
            withdrawalType,
            withdrawalType == WithdrawalType.Direct ? depositor : spender,
            depositor,
            secondWithdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance,
            expectedFirstBlockHeightWhenWithdrawable /* Both withdrawals should be available at the same time */);

        // Jump to when both withdrawals are ready
        vm.roll(expectedFirstBlockHeightWhenWithdrawable);
        expectedWithdrawingBalance = 0;
        expectedWithdrawableBalance = 0;
        
        address actor = withdrawalType == WithdrawalType.Direct ? depositor : spender;
        _completeWithdrawalAndVerifyState(
            withdrawalType,
            actor,
            depositor,
            firstWithdrawalAmount + secondWithdrawalAmount,
            expectedSpendableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance
        );
        assertEq(IERC20(usdc).balanceOf(actor), firstWithdrawalAmount + secondWithdrawalAmount);
    }

    /// Tests updating withdrawal delay and initiating a new withdrawal
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in spendable balance
    /// 2. Initiate first withdrawal of 1/4 initialUsdcBalance:
    ///    - spendable balance decreases by first withdrawal amount
    ///    - withdrawing balance increases by first withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. Update withdrawal delay to half of original:
    ///    - withdrawalDelay updated to new value
    /// 4. Initiate second withdrawal of 1/2 initialUsdcBalance:
    ///    - spendable balance decreases by second withdrawal amount
    ///    - withdrawing balance increases by second withdrawal amount
    ///    - withdrawal block set to current block + new withdrawalDelay (uses updated delay)
    function test_withdrawal_updateWithdrawalDelayToShorterDelayThenInitiateWithdrawalAgain() public testWithdrawalTypes {
        _assertInitialState(depositor);

        // Initiate first withdrawal
        uint256 firstWithdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = firstWithdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount;
        uint256 expectedWithdrawingBalance = firstWithdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedFirstBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            withdrawalType,
            withdrawalType == WithdrawalType.Direct ? depositor : spender,
            depositor,
            firstWithdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance, 
            expectedFirstBlockHeightWhenWithdrawable);

        // Update withdrawal delay to shorter delay
        vm.startPrank(owner);
        wallet.updateWithdrawalDelay(wallet.withdrawalDelay() / 2);
        vm.stopPrank();

        // Initiate second withdrawal
        uint256 secondWithdrawalAmount = initialUsdcBalance / 2;
        expectedTotalWithdrawalAmount = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount - secondWithdrawalAmount;
        expectedWithdrawingBalance = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedWithdrawableBalance = 0;
        uint256 expectedSecondBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            withdrawalType,
            withdrawalType == WithdrawalType.Direct ? depositor : spender,
            depositor,
            secondWithdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance,
            expectedSecondBlockHeightWhenWithdrawable);
    }

    // ===== Multiple Actor Interaction Tests =====

    /// Tests direct withdrawal initiation followed by authorized completion
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in spendable balance
    /// 2. Depositor initiates withdrawal:
    ///    - spendable balance decreases by withdrawal amount
    ///    - withdrawing balance increases by withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. After delay:
    ///    - authorized spender completes withdrawal and receives funds
    ///    - withdrawing balance and withdrawal block reset to 0
    ///    - depositor receives nothing
    function test_withdrawal_directInitiationAuthorizedCompletion() public {
        _assertInitialState(depositor);
        
        // Add spender authorization
        vm.startPrank(depositor);
        wallet.addSpender(usdc, spender);
        vm.stopPrank();
        
        // Depositor initiates withdrawal directly
        uint256 withdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = withdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - withdrawalAmount;
        uint256 expectedWithdrawingBalance = withdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        
        _initiateWithdrawalAndVerifyState(
            WithdrawalType.Direct,  // Direct withdrawal by depositor
            depositor,
            depositor,
            withdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance, 
            expectedBlockHeightWhenWithdrawable
        );
        
        // Jump to block height when the withdrawal should be withdrawable
        vm.roll(expectedBlockHeightWhenWithdrawable);
        
        // Authorized spender completes the withdrawal
        expectedWithdrawingBalance = 0;
        expectedWithdrawableBalance = 0;
        
        // Spender receives the funds, not the depositor
        _completeWithdrawalAndVerifyState(
            WithdrawalType.Authorized,  // Authorized withdrawal completion by spender
            spender,
            depositor,
            withdrawalAmount,
            expectedSpendableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance
        );
        assertEq(IERC20(usdc).balanceOf(spender), withdrawalAmount);
        
        // Verify the depositor has no balance
        assertEq(IERC20(usdc).balanceOf(depositor), 0);
    }

    /// Tests authorized withdrawal initiation followed by direct completion
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in spendable balance
    /// 2. Authorized spender initiates withdrawal:
    ///    - spendable balance decreases by withdrawal amount
    ///    - withdrawing balance increases by withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. After delay:
    ///    - depositor completes withdrawal and receives funds
    ///    - withdrawing balance and withdrawal block reset to 0
    ///    - spender receives nothing
    function test_withdrawal_authorizedInitiationDirectCompletion() public {
        _assertInitialState(depositor);
        
        // Add spender authorization
        vm.startPrank(depositor);
        wallet.addSpender(usdc, spender);
        vm.stopPrank();
        
        // Spender initiates withdrawal on behalf of depositor
        uint256 withdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = withdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - withdrawalAmount;
        uint256 expectedWithdrawingBalance = withdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        
        _initiateWithdrawalAndVerifyState(
            WithdrawalType.Authorized,  // Authorized withdrawal initiation by spender
            spender,
            depositor,
            withdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance, 
            expectedBlockHeightWhenWithdrawable
        );
        
        // Jump to block height when the withdrawal should be withdrawable
        vm.roll(expectedBlockHeightWhenWithdrawable);
        
        // Depositor completes the withdrawal
        expectedWithdrawingBalance = 0;
        expectedWithdrawableBalance = 0;
        
        // Depositor receives the funds, not the spender
        _completeWithdrawalAndVerifyState(
            WithdrawalType.Direct,  // Direct withdrawal completion by depositor
            depositor,
            depositor,
            withdrawalAmount,
            expectedSpendableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance
        );
        assertEq(IERC20(usdc).balanceOf(depositor), withdrawalAmount);
        
        // Verify the spender has no balance
        assertEq(IERC20(usdc).balanceOf(spender), 0);
    }

    /// Tests withdrawal after spender authorization is revoked
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in spendable balance
    /// 2. Authorized spender initiates withdrawal:
    ///    - spendable balance decreases by withdrawal amount
    ///    - withdrawing balance increases by withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. Depositor revokes spender authorization
    /// 4. After delay:
    ///    - spender's attempt to withdraw fails with UnauthorizedSpender error
    ///    - depositor completes withdrawal and receives funds
    ///    - withdrawing balance and withdrawal block reset to 0
    function test_withdrawal_revokedSpenderAuthorizationDuringWithdrawal() public {
        _assertInitialState(depositor);
        
        // Add spender authorization
        vm.startPrank(depositor);
        wallet.addSpender(usdc, spender);
        vm.stopPrank();
        
        // Spender initiates withdrawal on behalf of depositor
        uint256 withdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = withdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - withdrawalAmount;
        uint256 expectedWithdrawingBalance = withdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        
        _initiateWithdrawalAndVerifyState(
            WithdrawalType.Authorized,  // Authorized withdrawal initiation by spender
            spender,
            depositor,
            withdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance, 
            expectedBlockHeightWhenWithdrawable
        );
        
        // Depositor revokes spender's authorization
        vm.startPrank(depositor);
        wallet.removeSpender(usdc, spender);
        vm.stopPrank();
        
        // Jump to block height when the withdrawal should be withdrawable
        vm.roll(expectedBlockHeightWhenWithdrawable);
        
        // Spender tries to complete the withdrawal but should fail
        vm.startPrank(spender);
        vm.expectRevert(SpendWallet.UnauthorizedSpender.selector);
        wallet.withdraw(usdc, depositor);
        vm.stopPrank();
        
        // Depositor completes the withdrawal and succeeds
        expectedWithdrawingBalance = 0;
        expectedWithdrawableBalance = 0;
        
        _completeWithdrawalAndVerifyState(
            WithdrawalType.Direct,  // Direct withdrawal completion by depositor
            depositor,
            depositor,
            withdrawalAmount,
            expectedSpendableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance
        );
        assertEq(IERC20(usdc).balanceOf(depositor), withdrawalAmount);
        
        // Verify the spender has no balance
        assertEq(IERC20(usdc).balanceOf(spender), 0);
    }

    /// Tests multiple spenders initiating and completing withdrawals for same depositor
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in spendable balance
    /// 2. First spender initiates withdrawal:
    ///    - spendable balance decreases by first withdrawal amount
    ///    - withdrawing balance increases by first withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. Second spender initiates withdrawal:
    ///    - spendable balance decreases by second withdrawal amount
    ///    - withdrawing balance increases by second withdrawal amount
    ///    - withdrawal block remains unchanged (both withdrawals share same delay)
    /// 4. After delay:
    ///    - first spender completes withdrawal and receives ENTIRE withdrawing balance
    ///    - withdrawing balance and withdrawal block reset to 0
    ///    - second spender's attempt to withdraw fails (NoWithdrawingBalance) as nothing is left
    function test_withdrawal_multipleSpendersForSameDepositor() public {
        _assertInitialState(depositor);
        
        // Create a second spender
        address spender2 = makeAddr("spender2");
        
        // Add both spenders as authorized
        vm.startPrank(depositor);
        wallet.addSpender(usdc, spender);
        wallet.addSpender(usdc, spender2);
        vm.stopPrank();
        
        // First spender initiates withdrawal
        uint256 firstWithdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = firstWithdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount;
        uint256 expectedWithdrawingBalance = firstWithdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        
        _initiateWithdrawalAndVerifyState(
            WithdrawalType.Authorized,
            spender,
            depositor,
            firstWithdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance, 
            expectedBlockHeightWhenWithdrawable
        );
        
        // Second spender initiates withdrawal
        uint256 secondWithdrawalAmount = initialUsdcBalance / 3;
        expectedTotalWithdrawalAmount = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount - secondWithdrawalAmount;
        expectedWithdrawingBalance = firstWithdrawalAmount + secondWithdrawalAmount;
        
        _initiateWithdrawalAndVerifyState(
            WithdrawalType.Authorized,
            spender2,
            depositor,
            secondWithdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance, 
            expectedBlockHeightWhenWithdrawable  // Both withdrawals are ready at the same time
        );
        
        // Jump to block height when the withdrawals should be withdrawable
        vm.roll(expectedBlockHeightWhenWithdrawable);
        
        // First spender completes the withdrawal and gets the ENTIRE withdrawing balance
        _completeWithdrawalAndVerifyState(
            WithdrawalType.Authorized,
            spender,
            depositor,
            expectedWithdrawingBalance,  // Gets the total of both withdrawals
            expectedSpendableBalance,
            0,  // expectedWithdrawingBalance is reset to 0
            0   // expectedWithdrawableBalance is 0
        );
        assertEq(IERC20(usdc).balanceOf(spender), expectedWithdrawingBalance);
        
        // Second spender tries to complete their withdrawal but should fail because nothing is left
        vm.startPrank(spender2);
        vm.expectRevert(SpendWallet.NoWithdrawingBalance.selector);
        wallet.withdraw(usdc, depositor);
        vm.stopPrank();
        
        // Verify second spender got nothing
        assertEq(IERC20(usdc).balanceOf(spender2), 0);
        
        // Verify the depositor still has no balance
        assertEq(IERC20(usdc).balanceOf(depositor), 0);
    }
    
    /// Tests same spender initiating withdrawals for multiple depositors
    /// State transitions:
    /// 1. Initial state: multiple depositors each have initialUsdcBalance in spendable balance
    /// 2. Spender initiates withdrawal for first depositor:
    ///    - first depositor's spendable balance decreases by withdrawal amount
    ///    - first depositor's withdrawing balance increases by withdrawal amount
    ///    - first depositor's withdrawal block set to current block + withdrawalDelay
    /// 3. Spender initiates withdrawal for second depositor:
    ///    - second depositor's spendable balance decreases by withdrawal amount
    ///    - second depositor's withdrawing balance increases by withdrawal amount
    ///    - second depositor's withdrawal block set to current block + withdrawalDelay
    /// 4. After delay:
    ///    - spender completes withdrawal for first depositor and receives those funds
    ///    - spender completes withdrawal for second depositor and receives those funds
    ///    - both depositors' withdrawing balances and withdrawal blocks reset to 0
    function test_withdrawal_sameSpenderForMultipleDepositors() public {
        // Setup a second depositor with the same initial balance
        address depositor2 = makeAddr("depositor2");
        deal(usdc, depositor2, initialUsdcBalance);
        
        // Have both depositors deposit funds
        vm.startPrank(depositor2);
        IERC20(usdc).approve(address(wallet), initialUsdcBalance);
        wallet.deposit(usdc, initialUsdcBalance);
        vm.stopPrank();
        
        // Verify initial state for both depositors
        _assertInitialState(depositor); 
        _assertInitialState(depositor2);
        
        // Add spender authorization for both depositors
        vm.startPrank(depositor);
        wallet.addSpender(usdc, spender);
        vm.stopPrank();
        
        vm.startPrank(depositor2);
        wallet.addSpender(usdc, spender);
        vm.stopPrank();
        
        // Spender initiates withdrawal for first depositor
        uint256 withdrawalAmount1 = initialUsdcBalance / 3;
        uint256 expectedSpendableBalance1 = initialUsdcBalance - withdrawalAmount1;
        uint256 expectedBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        
        _initiateWithdrawalAndVerifyState(
            WithdrawalType.Authorized,
            spender,
            depositor, 
            withdrawalAmount1,
            withdrawalAmount1,
            expectedSpendableBalance1,
            withdrawalAmount1,
            0, 
            expectedBlockHeightWhenWithdrawable
        );
        
        // Spender initiates withdrawal for second depositor
        uint256 withdrawalAmount2 = initialUsdcBalance / 2;
        uint256 expectedSpendableBalance2 = initialUsdcBalance - withdrawalAmount2;
        
        _initiateWithdrawalAndVerifyState(
            WithdrawalType.Authorized,
            spender,
            depositor2, 
            withdrawalAmount2,
            withdrawalAmount2,
            expectedSpendableBalance2,
            withdrawalAmount2,
            0, 
            expectedBlockHeightWhenWithdrawable
        );
        
        // Jump to block height when the withdrawals should be withdrawable
        vm.roll(expectedBlockHeightWhenWithdrawable);
        
        // Complete first withdrawal and check balance
        _completeWithdrawalAndVerifyState(
            WithdrawalType.Authorized,
            spender,
            depositor, 
            withdrawalAmount1,
            expectedSpendableBalance1,
            0, 
            0 
        );
        assertEq(IERC20(usdc).balanceOf(spender), withdrawalAmount1);
        
        // Complete second withdrawal and check balance
        _completeWithdrawalAndVerifyState(
            WithdrawalType.Authorized,
            spender,
            depositor2, 
            withdrawalAmount2,
            expectedSpendableBalance2,
            0, 
            0 
        );
        assertEq(IERC20(usdc).balanceOf(spender), withdrawalAmount1 + withdrawalAmount2);
        
        // Verify both depositors still have no balance
        assertEq(IERC20(usdc).balanceOf(depositor), 0);
        assertEq(IERC20(usdc).balanceOf(depositor2), 0);
    }
}
