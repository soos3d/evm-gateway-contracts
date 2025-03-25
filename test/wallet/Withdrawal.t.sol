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
    address private usdc;

    uint256 private initialUsdcBalance = 1000 * 10 ** 6;
    uint256 private initialWithdrawalDelay = 100;
    SpendWallet private wallet;

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

    // Helper function to verify initial state before any withdrawals
    function _assertInitialState() internal view {
        assertEq(IERC20(usdc).balanceOf(depositor), 0);
        assertEq(wallet.spendableBalance(usdc, depositor), initialUsdcBalance);
        assertEq(wallet.withdrawingBalance(usdc, depositor), 0);
        assertEq(wallet.withdrawableBalance(usdc, depositor), 0);
        assertEq(wallet.withdrawalBlock(usdc, depositor), 0);
    }

    // Helper function to initiate withdrawal and verify state
    function _initiateWithdrawalByDepositorAndVerifyState(
        uint256 withdrawalAmount,
        uint256 expectedTotalWithdrawalAmount,
        uint256 expectedSpendableBalance, 
        uint256 expectedWithdrawingBalance, 
        uint256 expectedWithdrawableBalance, 
        uint256 expectedWithdrawalBlock) internal {
        vm.startPrank(depositor);
        vm.expectEmit(true, true, false, true);
        emit SpendWallet.WithdrawalInitiated(usdc, depositor, depositor, withdrawalAmount, expectedTotalWithdrawalAmount, expectedWithdrawalBlock);
        wallet.initiateWithdrawal(usdc, withdrawalAmount);
        vm.stopPrank();

        assertEq(wallet.spendableBalance(usdc, depositor), expectedSpendableBalance);
        assertEq(wallet.withdrawingBalance(usdc, depositor), expectedWithdrawingBalance);
        assertEq(wallet.withdrawableBalance(usdc, depositor), expectedWithdrawableBalance);
        assertEq(wallet.withdrawalBlock(usdc, depositor), expectedWithdrawalBlock);
    }

    // Helper function to complete withdrawal and verify state
    function _completeWithdrawalByDepositorAndVerifyState(
        uint256 expectedTokenBalance, 
        uint256 expectedSpendableBalance, 
        uint256 expectedWithdrawingBalance, 
        uint256 expectedWithdrawableBalance) internal {
        vm.startPrank(depositor);
        vm.expectEmit(true, true, false, true);
        emit SpendWallet.WithdrawalCompleted(usdc, depositor, depositor, expectedTokenBalance);
        wallet.withdraw(usdc);
        vm.stopPrank();

        assertEq(IERC20(usdc).balanceOf(depositor), expectedTokenBalance);
        assertEq(wallet.spendableBalance(usdc, depositor), expectedSpendableBalance);
        assertEq(wallet.withdrawingBalance(usdc, depositor), expectedWithdrawingBalance);
        assertEq(wallet.withdrawableBalance(usdc, depositor), expectedWithdrawableBalance);
        assertEq(wallet.withdrawalBlock(usdc, depositor), 0);
    }

    function test_initiateWithdrawalByDepositor_revertIfValueIsZero() public {
        vm.startPrank(depositor);
        vm.expectRevert(SpendWallet.WithdrawalValueMustBePositive.selector);
        wallet.initiateWithdrawal(usdc, 0);
        vm.stopPrank();
    }

    function test_initiateWithdrawalByDepositor_revertIfValueExceedsSpendableBalance() public {
        vm.startPrank(depositor);
        vm.expectRevert(SpendWallet.WithdrawalValueExceedsSpendableBalance.selector);
        wallet.initiateWithdrawal(usdc, 2 * initialUsdcBalance);
        vm.stopPrank();
    }

    function test_withdrawalByDepositor_revertIfNoWithdrawingBalance() public {
        vm.startPrank(depositor);
        vm.expectRevert(SpendWallet.NoWithdrawingBalance.selector);
        wallet.withdraw(usdc);
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
    ///    - withdrawing balance transfers to depositor
    ///    - withdrawing balance and withdrawal block reset to 0
    function test_withdrawalByDepositor_balancesUpdatedAfterSimpleWithdrawal() public {
        _assertInitialState();
        
        uint256 withdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = withdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - withdrawalAmount;
        uint256 expectedWithdrawingBalance = withdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalByDepositorAndVerifyState(
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
        _completeWithdrawalByDepositorAndVerifyState(
            withdrawalAmount,
            expectedSpendableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance
        );
    }

    /// Tests that withdrawal cannot be completed before the delay period
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in spendable balance
    /// 2. Initiate withdrawal of 1/4 initialUsdcBalance:
    ///    - spendable balance decreases by withdrawal amount
    ///    - withdrawing balance increases by withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. Attempt immediate withdrawal -> reverts with WithdrawalNotYetAvailable
    /// 4. Attempt withdrawal one block before delay -> reverts with WithdrawalNotYetAvailable
    function test_withdrawalByDepositor_revertIfWithdrawalNotYetAvailable() public {
        _assertInitialState();

        uint256 withdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = withdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - withdrawalAmount;
        uint256 expectedWithdrawingBalance = withdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalByDepositorAndVerifyState(
            withdrawalAmount,
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance,
            expectedBlockHeightWhenWithdrawable);

        // Attempt to withdraw immediately
        vm.startPrank(depositor);
        vm.expectRevert(SpendWallet.WithdrawalNotYetAvailable.selector);
        wallet.withdraw(usdc);
        vm.stopPrank();

        // Jump to one block before the withdrawal is available
        vm.roll(expectedBlockHeightWhenWithdrawable - 1);

        // Attempt to withdraw again
        vm.startPrank(depositor);
        vm.expectRevert(SpendWallet.WithdrawalNotYetAvailable.selector);
        wallet.withdraw(usdc);
        vm.stopPrank();
    }

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
    ///    - total withdrawing balance transfers to depositor
    ///    - withdrawing balance and withdrawal block reset to 0
    function test_withdrawalByDepositor_secondWithdrawalBeforeFirstWithdrawalIsReadyUpdatesBalancesAndResetsTimer() public {
        _assertInitialState();
        
        // Initiate first withdrawal
        uint256 firstWithdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = firstWithdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount;
        uint256 expectedWithdrawingBalance = firstWithdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedFirstBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalByDepositorAndVerifyState(
            firstWithdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance, 
            expectedFirstBlockHeightWhenWithdrawable);

        // Jump to halfway through the withdrawal delay
        vm.roll(vm.getBlockNumber() + wallet.withdrawalDelay()  / 2);

        // Initiate second withdrawal
        uint256 secondWithdrawalAmount = initialUsdcBalance / 2;
        expectedTotalWithdrawalAmount = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount - secondWithdrawalAmount;
        expectedWithdrawingBalance = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedWithdrawableBalance = 0;
        uint256 expectedSecondBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalByDepositorAndVerifyState(
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
        _completeWithdrawalByDepositorAndVerifyState(
            firstWithdrawalAmount + secondWithdrawalAmount,
            expectedSpendableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance
        );
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
    ///    - total withdrawing balance transfers to depositor
    ///    - withdrawing balance and withdrawal block reset to 0
    function test_withdrawalByDepositor_secondWithdrawalAfterFirstWithdrawalIsReadyUpdatesBalancesAndResetsTimer() public {
        _assertInitialState();
        
        // Initiate first withdrawal
        uint256 firstWithdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = firstWithdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount;
        uint256 expectedWithdrawingBalance = firstWithdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedFirstBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalByDepositorAndVerifyState(
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
        _initiateWithdrawalByDepositorAndVerifyState(
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
        _completeWithdrawalByDepositorAndVerifyState(
            firstWithdrawalAmount + secondWithdrawalAmount,
            expectedSpendableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance
        );
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
    ///    - total withdrawing balance transfers to depositor
    ///    - withdrawing balance and withdrawal block reset to 0
    function test_withdrawalByDepositor_twoConcurrentWithdrawalsUpdatesBalances() public {
        _assertInitialState();

        // Initiate first withdrawal
        uint256 firstWithdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = firstWithdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount;
        uint256 expectedWithdrawingBalance = firstWithdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedFirstBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalByDepositorAndVerifyState(
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
        _initiateWithdrawalByDepositorAndVerifyState(
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
        _completeWithdrawalByDepositorAndVerifyState(
            firstWithdrawalAmount + secondWithdrawalAmount,
            expectedSpendableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance
        );
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
    function test_withdrawalByDepositor_updateWithdrawalDelayToShorterDelayThenInitiateWithdrawalAgain() public {
        _assertInitialState();

        // Initiate first withdrawal
        uint256 firstWithdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedTotalWithdrawalAmount = firstWithdrawalAmount;
        uint256 expectedSpendableBalance = initialUsdcBalance - firstWithdrawalAmount;
        uint256 expectedWithdrawingBalance = firstWithdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedFirstBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalByDepositorAndVerifyState(
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
        _initiateWithdrawalByDepositorAndVerifyState(
            secondWithdrawalAmount, 
            expectedTotalWithdrawalAmount,
            expectedSpendableBalance, 
            expectedWithdrawingBalance, 
            expectedWithdrawableBalance,
            expectedSecondBlockHeightWhenWithdrawable);
        
    }
}
