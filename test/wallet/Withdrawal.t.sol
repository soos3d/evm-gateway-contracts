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

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Test} from "forge-std/Test.sol";
import {GatewayWallet} from "src/GatewayWallet.sol";
import {Balances} from "src/modules/wallet/Balances.sol";
import {WithdrawalDelay} from "src/modules/wallet/WithdrawalDelay.sol";
import {Withdrawals} from "src/modules/wallet/Withdrawals.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";

/// Tests withdrawal functionality of GatewayWallet
contract GatewayWalletWithdrawalTest is Test, DeployUtils {
    address private owner = makeAddr("owner");
    address private depositor = makeAddr("depositor");
    address private otherUser = makeAddr("otherUser");
    address private usdc;

    uint256 private initialUsdcBalance = 1000 * 10 ** 6;
    uint256 private initialWithdrawalDelay = 100;
    GatewayWallet private wallet;

    function setUp() public {
        wallet = deployWalletOnly(owner, ForkTestUtils.forkVars().domain);

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

    // ===== Helper Functions =====

    // Helper function to verify initial state for a depositor
    function _assertInitialState(address depositorAddress) internal view {
        assertEq(IERC20(usdc).balanceOf(depositorAddress), 0);
        assertEq(wallet.availableBalance(usdc, depositorAddress), initialUsdcBalance);
        assertEq(wallet.withdrawingBalance(usdc, depositorAddress), 0);
        assertEq(wallet.withdrawableBalance(usdc, depositorAddress), 0);
        assertEq(wallet.withdrawalBlock(usdc, depositorAddress), 0);
        assertEq(wallet.totalBalance(usdc, depositorAddress), initialUsdcBalance);
    }

    // Helper function to verify state after withdrawal initiation for a depositor
    function _initiateWithdrawalAndVerifyState(
        address depositorAddress,
        uint256 withdrawalAmount,
        uint256 expectedAvailableBalance,
        uint256 expectedWithdrawingBalance,
        uint256 expectedWithdrawableBalance,
        uint256 expectedWithdrawalBlock
    ) internal {
        vm.startPrank(depositorAddress);
        vm.expectEmit(true, true, false, true);
        emit Withdrawals.WithdrawalInitiated(
            usdc,
            depositorAddress,
            withdrawalAmount,
            expectedAvailableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawalBlock
        );

        wallet.initiateWithdrawal(usdc, withdrawalAmount);
        vm.stopPrank();

        assertEq(wallet.availableBalance(usdc, depositorAddress), expectedAvailableBalance);
        assertEq(wallet.withdrawingBalance(usdc, depositorAddress), expectedWithdrawingBalance);
        assertEq(wallet.withdrawableBalance(usdc, depositorAddress), expectedWithdrawableBalance);
        assertEq(wallet.withdrawalBlock(usdc, depositorAddress), expectedWithdrawalBlock);
        assertEq(wallet.totalBalance(usdc, depositorAddress), expectedAvailableBalance + expectedWithdrawingBalance);
    }

    // Helper function to verify state after withdrawal completion for a depositor
    function _completeWithdrawalAndVerifyState(
        address depositorAddress,
        uint256 expectedWithdrawalAmount,
        uint256 expectedAvailableBalance
    ) internal {
        vm.startPrank(depositorAddress);
        vm.expectEmit(true, true, false, true);
        emit Withdrawals.WithdrawalCompleted(usdc, depositorAddress, expectedWithdrawalAmount);

        wallet.withdraw(usdc);
        vm.stopPrank();

        assertEq(wallet.availableBalance(usdc, depositorAddress), expectedAvailableBalance);
        assertEq(wallet.withdrawingBalance(usdc, depositorAddress), 0);
        assertEq(wallet.withdrawableBalance(usdc, depositorAddress), 0);
        assertEq(wallet.withdrawalBlock(usdc, depositorAddress), 0);
        assertEq(wallet.totalBalance(usdc, depositorAddress), expectedAvailableBalance);
    }

    // ===== Basic Error Tests - Withdrawal Initiation =====

    function test_initiateWithdrawal_revertIfValueIsZero() public {
        vm.startPrank(depositor);
        vm.expectRevert(Withdrawals.WithdrawalValueMustBePositive.selector);
        wallet.initiateWithdrawal(usdc, 0);
        vm.stopPrank();
    }

    function test_initiateWithdrawal_revertIfValueExceedsAvailableBalance() public {
        vm.startPrank(depositor);
        vm.expectRevert(Withdrawals.WithdrawalValueExceedsAvailableBalance.selector);
        wallet.initiateWithdrawal(usdc, 2 * initialUsdcBalance);
        vm.stopPrank();
    }

    /// Tests that users without a balance cannot initiate withdrawals
    function test_initiateWithdrawal_revertIfUserHasNoBalance() public {
        _assertInitialState(depositor);

        uint256 withdrawalAmount = initialUsdcBalance / 4;

        // Try to initiate withdrawal as otherUser who has no deposited balance - should fail
        vm.startPrank(otherUser);
        vm.expectRevert(Withdrawals.WithdrawalValueExceedsAvailableBalance.selector);
        wallet.initiateWithdrawal(usdc, withdrawalAmount);
        vm.stopPrank();

        // Verify depositor can still initiate withdrawal
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(usdc, withdrawalAmount);
        vm.stopPrank();
    }

    // ===== Basic Error Tests - Withdrawal Completion =====

    function test_withdraw_revertIfNoWithdrawingBalance() public {
        vm.startPrank(depositor);
        vm.expectRevert(Balances.NoWithdrawingBalance.selector);
        wallet.withdraw(usdc);
        vm.stopPrank();
    }

    /// Tests that users without a withdrawing balance cannot complete withdrawals
    function test_withdraw_revertIfUserHasNoWithdrawingBalance() public {
        _assertInitialState(depositor);

        uint256 withdrawalAmount = initialUsdcBalance / 4;

        // Depositor initiates withdrawal
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(usdc, withdrawalAmount);
        vm.stopPrank();

        // Fast forward past withdrawal delay
        vm.roll(vm.getBlockNumber() + wallet.withdrawalDelay());

        // Try to complete withdrawal as otherUser - should fail (no withdrawing balance)
        vm.startPrank(otherUser);
        vm.expectRevert(Balances.NoWithdrawingBalance.selector);
        wallet.withdraw(usdc);
        vm.stopPrank();

        // Verify depositor can complete withdrawal
        uint256 depositorBalanceBefore = IERC20(usdc).balanceOf(depositor);
        vm.startPrank(depositor);
        wallet.withdraw(usdc);
        vm.stopPrank();

        // Verify funds went to the depositor
        assertEq(IERC20(usdc).balanceOf(depositor), depositorBalanceBefore + withdrawalAmount);
    }

    // ===== Full Withdrawal Flow Tests =====

    /// Tests that withdrawal cannot be completed before the delay period
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in available balance
    /// 2. Initiate withdrawal of 1/4 initialUsdcBalance:
    ///    - available balance decreases by withdrawal amount
    ///    - withdrawing balance increases by withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. Attempt immediate withdrawal -> reverts with WithdrawalNotYetAvailable
    /// 4. Attempt withdrawal one block before delay -> reverts with WithdrawalNotYetAvailable
    function test_withdrawal_revertIfWithdrawalNotYetAvailable() public {
        _assertInitialState(depositor);

        uint256 withdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedAvailableBalance = initialUsdcBalance - withdrawalAmount;
        uint256 expectedWithdrawingBalance = withdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            depositor,
            withdrawalAmount,
            expectedAvailableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance,
            expectedBlockHeightWhenWithdrawable
        );

        // Attempt to withdraw immediately
        vm.startPrank(depositor);
        vm.expectRevert(WithdrawalDelay.WithdrawalNotYetAvailable.selector);
        wallet.withdraw(usdc);
        vm.stopPrank();

        // Jump to one block before the withdrawal is available
        vm.roll(expectedBlockHeightWhenWithdrawable - 1);

        // Attempt to withdraw again
        vm.startPrank(depositor);
        vm.expectRevert(WithdrawalDelay.WithdrawalNotYetAvailable.selector);
        wallet.withdraw(usdc);
        vm.stopPrank();
    }

    /// Tests a simple withdrawal flow
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in available balance
    /// 2. Initiate withdrawal of 1/4 initialUsdcBalance:
    ///    - available balance decreases by withdrawal amount
    ///    - withdrawing balance increases by withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. After delay:
    ///    - withdrawing balance transfers to depositor
    ///    - withdrawing balance and withdrawal block reset to 0
    function test_withdrawal_balancesUpdatedAfterSimpleWithdrawal() public {
        _assertInitialState(depositor);
        uint256 withdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedAvailableBalance = initialUsdcBalance - withdrawalAmount;
        uint256 expectedWithdrawingBalance = withdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            depositor,
            withdrawalAmount,
            expectedAvailableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance,
            expectedBlockHeightWhenWithdrawable
        );

        // Jump to block height when the withdrawal should be withdrawable
        vm.roll(expectedBlockHeightWhenWithdrawable);

        _completeWithdrawalAndVerifyState(depositor, withdrawalAmount, expectedAvailableBalance);
        assertEq(IERC20(usdc).balanceOf(depositor), withdrawalAmount);
    }

    // ===== Multiple Withdrawals Tests =====

    /// Tests initiating a second withdrawal before first withdrawal is ready
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in available balance
    /// 2. Initiate first withdrawal of 1/4 initialUsdcBalance:
    ///    - available balance decreases by first withdrawal amount
    ///    - withdrawing balance increases by first withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. At halfway point:
    ///    - Initiate second withdrawal of 1/2 initialUsdcBalance
    ///    - available balance decreases by second withdrawal amount
    ///    - withdrawing balance increases by second withdrawal amount
    ///    - withdrawal block resets to current block + withdrawalDelay (new delay starts from this point)
    /// 4. After delay:
    ///    - total withdrawing balance transfers to depositor
    ///    - withdrawing balance and withdrawal block reset to 0
    function test_withdrawal_secondWithdrawalBeforeFirstWithdrawalIsReadyUpdatesBalancesAndResetsTimer() public {
        _assertInitialState(depositor);

        // Initiate first withdrawal
        uint256 firstWithdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedAvailableBalance = initialUsdcBalance - firstWithdrawalAmount;
        uint256 expectedWithdrawingBalance = firstWithdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedFirstBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            depositor,
            firstWithdrawalAmount,
            expectedAvailableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance,
            expectedFirstBlockHeightWhenWithdrawable
        );

        // Jump to halfway through the withdrawal delay
        vm.roll(vm.getBlockNumber() + wallet.withdrawalDelay() / 2);

        // Initiate second withdrawal
        uint256 secondWithdrawalAmount = initialUsdcBalance / 2;
        expectedAvailableBalance = initialUsdcBalance - firstWithdrawalAmount - secondWithdrawalAmount;
        expectedWithdrawingBalance = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedWithdrawableBalance = 0;
        uint256 expectedSecondBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            depositor,
            secondWithdrawalAmount,
            expectedAvailableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance,
            expectedSecondBlockHeightWhenWithdrawable
        );

        // Jump to block height when the second withdrawal should be withdrawable
        vm.roll(expectedSecondBlockHeightWhenWithdrawable);

        _completeWithdrawalAndVerifyState(
            depositor, firstWithdrawalAmount + secondWithdrawalAmount, expectedAvailableBalance
        );
        assertEq(IERC20(usdc).balanceOf(depositor), firstWithdrawalAmount + secondWithdrawalAmount);
    }

    /// Tests initiating a second withdrawal after first withdrawal is ready
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in available balance
    /// 2. Initiate first withdrawal of 1/4 initialUsdcBalance:
    ///    - available balance decreases by first withdrawal amount
    ///    - withdrawing balance increases by first withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. After first withdrawal delay:
    ///    - Initiate second withdrawal of 1/2 initialUsdcBalance
    ///    - available balance decreases by second withdrawal amount
    ///    - withdrawing balance increases by second withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 4. After second delay:
    ///    - total withdrawing balance transfers to depositor
    ///    - withdrawing balance and withdrawal block reset to 0
    function test_withdrawal_secondWithdrawalAfterFirstWithdrawalIsReadyUpdatesBalancesAndResetsTimer() public {
        _assertInitialState(depositor);

        // Initiate first withdrawal
        uint256 firstWithdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedAvailableBalance = initialUsdcBalance - firstWithdrawalAmount;
        uint256 expectedWithdrawingBalance = firstWithdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedFirstBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            depositor,
            firstWithdrawalAmount,
            expectedAvailableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance,
            expectedFirstBlockHeightWhenWithdrawable
        );

        // Jump to after first withdrawal is ready
        vm.roll(2 * expectedFirstBlockHeightWhenWithdrawable);

        // Initiate second withdrawal
        uint256 secondWithdrawalAmount = initialUsdcBalance / 2;
        expectedAvailableBalance = initialUsdcBalance - firstWithdrawalAmount - secondWithdrawalAmount;
        expectedWithdrawingBalance = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedWithdrawableBalance = 0;
        uint256 expectedSecondBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            depositor,
            secondWithdrawalAmount,
            expectedAvailableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance,
            expectedSecondBlockHeightWhenWithdrawable
        );

        // Jump to block height when the second withdrawal should be withdrawable
        vm.roll(expectedSecondBlockHeightWhenWithdrawable);

        _completeWithdrawalAndVerifyState(
            depositor, firstWithdrawalAmount + secondWithdrawalAmount, expectedAvailableBalance
        );
        assertEq(IERC20(usdc).balanceOf(depositor), firstWithdrawalAmount + secondWithdrawalAmount);
    }

    /// Tests two concurrent withdrawals initiated at the same time
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in available balance
    /// 2. Initiate first withdrawal of 1/4 initialUsdcBalance:
    ///    - available balance decreases by first withdrawal amount
    ///    - withdrawing balance increases by first withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. Immediately initiate second withdrawal of 1/2 initialUsdcBalance:
    ///    - available balance decreases by second withdrawal amount
    ///    - withdrawing balance increases by second withdrawal amount
    ///    - withdrawal block remains at current block + withdrawalDelay (both withdrawals share same delay)
    /// 4. After delay:
    ///    - total withdrawing balance transfers to depositor
    ///    - withdrawing balance and withdrawal block reset to 0
    function test_withdrawal_twoConcurrentWithdrawalsUpdatesBalances() public {
        _assertInitialState(depositor);

        // Initiate first withdrawal
        uint256 firstWithdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedAvailableBalance = initialUsdcBalance - firstWithdrawalAmount;
        uint256 expectedWithdrawingBalance = firstWithdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedFirstBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            depositor,
            firstWithdrawalAmount,
            expectedAvailableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance,
            expectedFirstBlockHeightWhenWithdrawable
        );

        // Initiate second withdrawal
        uint256 secondWithdrawalAmount = initialUsdcBalance / 2;
        expectedAvailableBalance = initialUsdcBalance - firstWithdrawalAmount - secondWithdrawalAmount;
        expectedWithdrawingBalance = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedWithdrawableBalance = 0;
        _initiateWithdrawalAndVerifyState(
            depositor,
            secondWithdrawalAmount,
            expectedAvailableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance,
            expectedFirstBlockHeightWhenWithdrawable /* Both withdrawals should be available at the same time */
        );

        // Jump to when both withdrawals are ready
        vm.roll(expectedFirstBlockHeightWhenWithdrawable);

        _completeWithdrawalAndVerifyState(
            depositor, firstWithdrawalAmount + secondWithdrawalAmount, expectedAvailableBalance
        );
        assertEq(IERC20(usdc).balanceOf(depositor), firstWithdrawalAmount + secondWithdrawalAmount);
    }

    /// Tests updating withdrawal delay and initiating a new withdrawal
    /// State transitions:
    /// 1. Initial state: depositor has initialUsdcBalance in available balance
    /// 2. Initiate first withdrawal of 1/4 initialUsdcBalance:
    ///    - available balance decreases by first withdrawal amount
    ///    - withdrawing balance increases by first withdrawal amount
    ///    - withdrawal block set to current block + withdrawalDelay
    /// 3. Update withdrawal delay to half of original:
    ///    - withdrawalDelay updated to new value
    /// 4. Initiate second withdrawal of 1/2 initialUsdcBalance:
    ///    - available balance decreases by second withdrawal amount
    ///    - withdrawing balance increases by second withdrawal amount
    ///    - withdrawal block set to current block + new withdrawalDelay (uses updated delay)
    /// 5. After delay:
    ///    - total withdrawing balance transfers to depositor
    ///    - withdrawing balance and withdrawal block reset to 0
    function test_withdrawal_updateWithdrawalDelayToShorterDelayThenInitiateWithdrawalAgain() public {
        _assertInitialState(depositor);

        // Initiate first withdrawal
        uint256 firstWithdrawalAmount = initialUsdcBalance / 4;
        uint256 expectedAvailableBalance = initialUsdcBalance - firstWithdrawalAmount;
        uint256 expectedWithdrawingBalance = firstWithdrawalAmount;
        uint256 expectedWithdrawableBalance = 0;
        uint256 expectedFirstBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            depositor,
            firstWithdrawalAmount,
            expectedAvailableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance,
            expectedFirstBlockHeightWhenWithdrawable
        );

        // Update withdrawal delay to shorter delay
        vm.startPrank(owner);
        wallet.updateWithdrawalDelay(wallet.withdrawalDelay() / 2);
        vm.stopPrank();

        // Initiate second withdrawal
        uint256 secondWithdrawalAmount = initialUsdcBalance / 2;
        expectedAvailableBalance = initialUsdcBalance - firstWithdrawalAmount - secondWithdrawalAmount;
        expectedWithdrawingBalance = firstWithdrawalAmount + secondWithdrawalAmount;
        expectedWithdrawableBalance = 0;
        uint256 expectedSecondBlockHeightWhenWithdrawable = vm.getBlockNumber() + wallet.withdrawalDelay();
        _initiateWithdrawalAndVerifyState(
            depositor,
            secondWithdrawalAmount,
            expectedAvailableBalance,
            expectedWithdrawingBalance,
            expectedWithdrawableBalance,
            expectedSecondBlockHeightWhenWithdrawable
        );

        // Jump to when both withdrawals are ready
        vm.roll(expectedSecondBlockHeightWhenWithdrawable);

        _completeWithdrawalAndVerifyState(
            depositor, firstWithdrawalAmount + secondWithdrawalAmount, expectedAvailableBalance
        );
        assertEq(IERC20(usdc).balanceOf(depositor), firstWithdrawalAmount + secondWithdrawalAmount);
    }
}
