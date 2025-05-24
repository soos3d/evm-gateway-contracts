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
import {Balances, BalanceType} from "src/modules/wallet/Balances.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";

contract GatewayWalletBalanceTest is Test, DeployUtils {
    address private owner = makeAddr("owner");
    address private depositor = makeAddr("depositor");
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

    // Helper function to create a balance id using BalanceType enum
    function _createBalanceId(address token, BalanceType balanceType) internal pure returns (uint256) {
        return _createBalanceIdRaw(token, uint96(balanceType));
    }

    function _createBalanceIdRaw(address token, uint96 balanceType) internal pure returns (uint256) {
        return uint256(bytes32(abi.encodePacked(balanceType, token)));
    }

    function test_balanceOf_returnsZeroForUnsupportedToken() public {
        address unsupportedToken = makeAddr("unsupportedToken");
        uint256 balanceId = _createBalanceId(unsupportedToken, BalanceType.Total);
        assertEq(wallet.balanceOf(depositor, balanceId), 0);
    }

    function test_balanceOf_returnsZeroForInvalidBalanceType() public view {
        uint256 balanceId = _createBalanceIdRaw(usdc, 4);
        assertEq(wallet.balanceOf(depositor, balanceId), 0);
    }

    function test_balanceOf_returnsTotalBalance() public {
        uint256 withdrawAmount = initialUsdcBalance / 2;

        vm.startPrank(depositor);
        wallet.initiateWithdrawal(usdc, withdrawAmount);
        vm.stopPrank();

        // Verify total balance is sum of available and withdrawing balances
        uint256 balanceId = _createBalanceId(usdc, BalanceType.Total);
        assertEq(wallet.balanceOf(depositor, balanceId), initialUsdcBalance);
        assertEq(
            wallet.balanceOf(depositor, balanceId),
            wallet.availableBalance(usdc, depositor) + wallet.withdrawingBalance(usdc, depositor)
        );
    }

    function test_balanceOf_returnsAvailableBalance() public view {
        uint256 balanceId = _createBalanceId(usdc, BalanceType.Available);
        assertEq(wallet.balanceOf(depositor, balanceId), initialUsdcBalance);
    }

    function test_balanceOf_returnsWithdrawingBalance() public {
        uint256 withdrawAmount = 10;

        vm.startPrank(depositor);
        wallet.initiateWithdrawal(usdc, withdrawAmount);
        vm.stopPrank();

        uint256 balanceId = _createBalanceId(usdc, BalanceType.Withdrawing);
        assertEq(wallet.balanceOf(depositor, balanceId), withdrawAmount);
    }

    function test_balanceOf_returnsZeroWithdrawableBalanceWhenNotYetAvailable() public {
        uint256 withdrawAmount = 10;

        vm.startPrank(depositor);
        wallet.initiateWithdrawal(usdc, withdrawAmount);
        vm.stopPrank();

        uint256 balanceId = _createBalanceId(usdc, BalanceType.Withdrawable);
        assertEq(wallet.balanceOf(depositor, balanceId), 0);
    }

    function test_balanceOf_returnsWithdrawableBalanceWhenAvailable() public {
        uint256 withdrawAmount = 10;

        vm.startPrank(depositor);
        wallet.initiateWithdrawal(usdc, withdrawAmount);
        vm.stopPrank();

        // Move past withdrawal delay
        vm.roll(block.number + initialWithdrawalDelay);

        uint256 balanceId = _createBalanceId(usdc, BalanceType.Withdrawable);
        assertEq(wallet.balanceOf(depositor, balanceId), withdrawAmount);
    }

    function test_balanceOf_returnsCorrectBalancesAfterWithdrawal() public {
        uint256 withdrawAmount = 10;

        vm.startPrank(depositor);
        wallet.initiateWithdrawal(usdc, withdrawAmount);
        vm.stopPrank();

        // Move past withdrawal delay
        vm.roll(block.number + initialWithdrawalDelay);

        vm.startPrank(depositor);
        wallet.withdraw(usdc);
        vm.stopPrank();

        // Check all balance types
        uint256 totalBalanceId = _createBalanceId(usdc, BalanceType.Total);
        uint256 availableBalanceId = _createBalanceId(usdc, BalanceType.Available);
        uint256 withdrawingBalanceId = _createBalanceId(usdc, BalanceType.Withdrawing);
        uint256 withdrawableBalanceId = _createBalanceId(usdc, BalanceType.Withdrawable);

        assertEq(wallet.balanceOf(depositor, totalBalanceId), initialUsdcBalance - withdrawAmount);
        assertEq(wallet.balanceOf(depositor, availableBalanceId), initialUsdcBalance - withdrawAmount);
        assertEq(wallet.balanceOf(depositor, withdrawingBalanceId), 0);
        assertEq(wallet.balanceOf(depositor, withdrawableBalanceId), 0);
    }

    function test_balanceOf_returnsCorrectBalancesForMultipleWithdrawals() public {
        uint256 firstWithdrawAmount = 10;
        uint256 secondWithdrawAmount = 5;
        uint256 totalWithdrawing = firstWithdrawAmount + secondWithdrawAmount;

        // Check all balance types
        uint256 totalBalanceId = _createBalanceId(usdc, BalanceType.Total);
        uint256 availableBalanceId = _createBalanceId(usdc, BalanceType.Available);
        uint256 withdrawingBalanceId = _createBalanceId(usdc, BalanceType.Withdrawing);
        uint256 withdrawableBalanceId = _createBalanceId(usdc, BalanceType.Withdrawable);

        // Initiate two withdrawals
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(usdc, firstWithdrawAmount);
        wallet.initiateWithdrawal(usdc, secondWithdrawAmount);
        vm.stopPrank();

        // Check balances after initiating withdrawals
        assertEq(wallet.balanceOf(depositor, totalBalanceId), initialUsdcBalance);
        assertEq(wallet.balanceOf(depositor, availableBalanceId), initialUsdcBalance - totalWithdrawing);
        assertEq(wallet.balanceOf(depositor, withdrawingBalanceId), totalWithdrawing);
        assertEq(wallet.balanceOf(depositor, withdrawableBalanceId), 0);

        // Move past withdrawal delay
        vm.roll(block.number + initialWithdrawalDelay);

        // Check balances when withdrawals become available
        assertEq(wallet.balanceOf(depositor, totalBalanceId), initialUsdcBalance);
        assertEq(wallet.balanceOf(depositor, availableBalanceId), initialUsdcBalance - totalWithdrawing);
        assertEq(wallet.balanceOf(depositor, withdrawingBalanceId), totalWithdrawing);
        assertEq(wallet.balanceOf(depositor, withdrawableBalanceId), totalWithdrawing);

        // Complete withdrawal
        vm.prank(depositor);
        wallet.withdraw(usdc);

        // Check final balances
        assertEq(wallet.balanceOf(depositor, totalBalanceId), initialUsdcBalance - totalWithdrawing);
        assertEq(wallet.balanceOf(depositor, availableBalanceId), initialUsdcBalance - totalWithdrawing);
        assertEq(wallet.balanceOf(depositor, withdrawingBalanceId), 0);
        assertEq(wallet.balanceOf(depositor, withdrawableBalanceId), 0);
        assertEq(IERC20(usdc).balanceOf(depositor), totalWithdrawing);
    }

    function test_balanceOfBatch_revertsOnInputArrayLengthMismatch() public {
        address[] memory depositors = new address[](2);
        depositors[0] = depositor;
        depositors[1] = depositor;

        uint256[] memory ids = new uint256[](1);
        ids[0] = _createBalanceId(usdc, BalanceType.Total);

        vm.expectRevert(Balances.InputArrayLengthMismatch.selector);
        wallet.balanceOfBatch(depositors, ids);
    }

    function test_balanceOfBatch_returnsMultipleBalanceTypes() public view {
        address[] memory depositors = new address[](4);
        uint256[] memory ids = new uint256[](4);

        // Query all balance types for same depositor/token
        depositors[uint256(BalanceType.Total)] = depositor;
        depositors[uint256(BalanceType.Available)] = depositor;
        depositors[uint256(BalanceType.Withdrawing)] = depositor;
        depositors[uint256(BalanceType.Withdrawable)] = depositor;

        ids[uint256(BalanceType.Total)] = _createBalanceId(usdc, BalanceType.Total);
        ids[uint256(BalanceType.Available)] = _createBalanceId(usdc, BalanceType.Available);
        ids[uint256(BalanceType.Withdrawing)] = _createBalanceId(usdc, BalanceType.Withdrawing);
        ids[uint256(BalanceType.Withdrawable)] = _createBalanceId(usdc, BalanceType.Withdrawable);

        uint256[] memory balances = wallet.balanceOfBatch(depositors, ids);

        // Assert each balance type matches expected value
        assertEq(balances[uint256(BalanceType.Total)], initialUsdcBalance, "Total balance mismatch");
        assertEq(balances[uint256(BalanceType.Available)], initialUsdcBalance, "Available balance mismatch");
        assertEq(balances[uint256(BalanceType.Withdrawing)], 0, "Withdrawing balance should be 0");
        assertEq(balances[uint256(BalanceType.Withdrawable)], 0, "Withdrawable balance should be 0");
    }

    function test_balanceOfBatch_returnsMultipleDepositors() public {
        address secondDepositor = makeAddr("secondDepositor");
        uint256 secondDepositorBalance = 500 * 10 ** 6;

        // Setup second depositor
        deal(usdc, secondDepositor, secondDepositorBalance);
        vm.startPrank(secondDepositor);
        IERC20(usdc).approve(address(wallet), secondDepositorBalance);
        wallet.deposit(usdc, secondDepositorBalance);
        vm.stopPrank();

        address[] memory depositors = new address[](2);
        depositors[0] = depositor;
        depositors[1] = secondDepositor;

        uint256[] memory ids = new uint256[](2);
        ids[0] = _createBalanceId(usdc, BalanceType.Total);
        ids[1] = _createBalanceId(usdc, BalanceType.Total);

        uint256[] memory balances = wallet.balanceOfBatch(depositors, ids);

        assertEq(balances[0], initialUsdcBalance);
        assertEq(balances[1], secondDepositorBalance);
    }

    function test_balanceOfBatch_returnsZeroesForUnsupportedOrInvalidTokens() public {
        address unsupportedToken = makeAddr("unsupportedToken");

        address[] memory depositors = new address[](2);
        depositors[0] = depositor;
        depositors[1] = depositor;

        uint256[] memory ids = new uint256[](2);
        ids[0] = _createBalanceIdRaw(usdc, 4);
        ids[1] = _createBalanceId(unsupportedToken, BalanceType.Total);

        uint256[] memory balances = wallet.balanceOfBatch(depositors, ids);
        assertEq(balances[0], 0);
        assertEq(balances[1], 0);
    }
}
