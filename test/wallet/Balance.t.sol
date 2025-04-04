/*
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.

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

contract SpendWalletBalanceTest is Test, DeployUtils {
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

    function _createBalanceId(address token, uint96 balanceType) internal pure returns (uint256) {
        return uint256(bytes32(abi.encodePacked(balanceType, token)));
    }

    function test_balanceOf_returnsZeroForUnsupportedToken() public {
        address unsupportedToken = makeAddr("unsupportedToken");
        uint256 balanceId = _createBalanceId(unsupportedToken, 0);

        assertEq(wallet.balanceOf(depositor, balanceId), 0);
    }

    function test_balanceOf_returnsZeroForInvalidBalanceType() public view {
        uint256 balanceId = _createBalanceId(usdc, 400);

        assertEq(wallet.balanceOf(depositor, balanceId), 0);
    }

    function test_balanceOf_returnsTotalBalance() public view {
        uint256 balanceId = _createBalanceId(usdc, 0);

        assertEq(wallet.balanceOf(depositor, balanceId), initialUsdcBalance);
    }

    function test_balanceOf_returnsSpendableBalance() public view {
        uint256 balanceId = _createBalanceId(usdc, 1);

        assertEq(wallet.balanceOf(depositor, balanceId), initialUsdcBalance);
    }

    function test_balanceOf_returnsWithdrawingBalance() public {
        uint256 withdrawAmount = 10;

        vm.startPrank(depositor);
        wallet.initiateWithdrawal(usdc, withdrawAmount);
        vm.stopPrank();

        uint256 balanceId = _createBalanceId(usdc, 2);

        assertEq(wallet.balanceOf(depositor, balanceId), withdrawAmount);
    }

    function test_balanceOf_returnsZeroWithdrawableBalanceWhenNotYetAvailable() public {
        uint256 withdrawAmount = 10;

        vm.startPrank(depositor);
        wallet.initiateWithdrawal(usdc, withdrawAmount);
        vm.stopPrank();

        uint256 balanceId = _createBalanceId(usdc, 3);

        assertEq(wallet.balanceOf(depositor, balanceId), 0);
    }

    function test_balanceOf_returnsWithdrawableBalanceWhenAvailable() public {
        uint256 withdrawAmount = 10;

        vm.startPrank(depositor);
        wallet.initiateWithdrawal(usdc, withdrawAmount);
        vm.stopPrank();

        // Move past withdrawal delay
        vm.roll(block.number + initialWithdrawalDelay);

        uint256 balanceId = _createBalanceId(usdc, 3);

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
        uint256 totalBalanceId = _createBalanceId(usdc, 0);
        uint256 spendableBalanceId = _createBalanceId(usdc, 1);
        uint256 withdrawingBalanceId = _createBalanceId(usdc, 2);
        uint256 withdrawableBalanceId = _createBalanceId(usdc, 3);

        assertEq(wallet.balanceOf(depositor, totalBalanceId), initialUsdcBalance - withdrawAmount);
        assertEq(wallet.balanceOf(depositor, spendableBalanceId), initialUsdcBalance - withdrawAmount);
        assertEq(wallet.balanceOf(depositor, withdrawingBalanceId), 0);
        assertEq(wallet.balanceOf(depositor, withdrawableBalanceId), 0);
    }

    function test_balanceOf_returnsCorrectBalancesForMultipleWithdrawals() public {
        uint256 firstWithdrawAmount = 10;
        uint256 secondWithdrawAmount = 5;

        // Initiate first withdrawal
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(usdc, firstWithdrawAmount);

        // Move forward by one block to separate withdrawals
        vm.roll(block.number + 1);

        // Initiate second withdrawal
        wallet.initiateWithdrawal(usdc, secondWithdrawAmount);
        vm.stopPrank();

        uint256 totalWithdrawing = firstWithdrawAmount + secondWithdrawAmount;

        // Check all balance types
        uint256 totalBalanceId = _createBalanceId(usdc, 0);
        uint256 spendableBalanceId = _createBalanceId(usdc, 1);
        uint256 withdrawingBalanceId = _createBalanceId(usdc, 2);
        uint256 withdrawableBalanceId = _createBalanceId(usdc, 3);

        assertEq(wallet.balanceOf(depositor, totalBalanceId), initialUsdcBalance);
        assertEq(wallet.balanceOf(depositor, spendableBalanceId), initialUsdcBalance - totalWithdrawing);
        assertEq(wallet.balanceOf(depositor, withdrawingBalanceId), totalWithdrawing);
        assertEq(wallet.balanceOf(depositor, withdrawableBalanceId), 0);

        // Move past withdrawal delay of first withdrawal
        vm.roll(block.number + initialWithdrawalDelay - 1);

        // First withdrawal should now be withdrawable, second still withdrawing
        assertEq(wallet.balanceOf(depositor, totalBalanceId), initialUsdcBalance);
        assertEq(wallet.balanceOf(depositor, spendableBalanceId), initialUsdcBalance - totalWithdrawing);
        assertEq(wallet.balanceOf(depositor, withdrawingBalanceId), totalWithdrawing);
        assertEq(wallet.balanceOf(depositor, withdrawableBalanceId), firstWithdrawAmount);

        // Complete first withdrawal
        vm.prank(depositor);
        wallet.withdraw(usdc);

        // // Check final balances after first withdrawal
        assertEq(wallet.balanceOf(depositor, totalBalanceId), initialUsdcBalance - firstWithdrawAmount);
        assertEq(wallet.balanceOf(depositor, spendableBalanceId), initialUsdcBalance - totalWithdrawing);
        assertEq(wallet.balanceOf(depositor, withdrawingBalanceId), secondWithdrawAmount);
        assertEq(wallet.balanceOf(depositor, withdrawableBalanceId), 0);

        vm.roll(block.number + 1);

        // Second withdrawal should now be withdrawable
        assertEq(wallet.balanceOf(depositor, totalBalanceId), initialUsdcBalance - firstWithdrawAmount);
        assertEq(wallet.balanceOf(depositor, spendableBalanceId), initialUsdcBalance - totalWithdrawing);
        assertEq(wallet.balanceOf(depositor, withdrawingBalanceId), secondWithdrawAmount);
        assertEq(wallet.balanceOf(depositor, withdrawableBalanceId), secondWithdrawAmount);
    }

    function test_balanceOfBatch_revertsOnLengthMismatch() public {
        address[] memory depositors = new address[](2);
        depositors[0] = depositor;
        depositors[1] = depositor;

        uint256[] memory ids = new uint256[](1);
        ids[0] = _createBalanceId(usdc, 0);

        vm.expectRevert(SpendWallet.LengthMismatch.selector);
        wallet.balanceOfBatch(depositors, ids);
    }

    function test_balanceOfBatch_returnsMultipleBalanceTypes() public {
        address[] memory depositors = new address[](4);
        uint256[] memory ids = new uint256[](4);

        // Query all balance types for same depositor/token
        for (uint96 i = 0; i < 4; i++) {
            depositors[i] = depositor;
            ids[i] = _createBalanceId(usdc, i);
        }

        uint256[] memory balances = wallet.balanceOfBatch(depositors, ids);

        // Total balance
        assertEq(balances[0], initialUsdcBalance);
        // Spendable balance
        assertEq(balances[1], initialUsdcBalance);
        // Withdrawing balance (0 since no withdrawal initiated)
        assertEq(balances[2], 0);
        // Withdrawable balance (0 since no withdrawal initiated)
        assertEq(balances[3], 0);
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
        ids[0] = _createBalanceId(usdc, 0); // Total balance for first depositor
        ids[1] = _createBalanceId(usdc, 0); // Total balance for second depositor

        uint256[] memory balances = wallet.balanceOfBatch(depositors, ids);

        assertEq(balances[0], initialUsdcBalance);
        assertEq(balances[1], secondDepositorBalance);
    }

    function test_balanceOfBatch_returnsZeroForUnsupportedTokens() public {
        address unsupportedToken = makeAddr("unsupportedToken");

        address[] memory depositors = new address[](2);
        depositors[0] = depositor;
        depositors[1] = depositor;

        uint256[] memory ids = new uint256[](2);
        ids[0] = _createBalanceId(usdc, 0); // Supported token
        ids[1] = _createBalanceId(unsupportedToken, 0); // Unsupported token

        uint256[] memory balances = wallet.balanceOfBatch(depositors, ids);

        assertEq(balances[0], initialUsdcBalance);
        assertEq(balances[1], 0);
    }

    function test_balanceOfBatch_returnsZeroForInvalidBalanceType() public {
        address[] memory depositors = new address[](2);
        depositors[0] = depositor;
        depositors[1] = depositor;

        uint256[] memory ids = new uint256[](2);
        ids[0] = _createBalanceId(usdc, 0); // Valid balance type
        ids[1] = _createBalanceId(usdc, 400); // Invalid balance type

        uint256[] memory balances = wallet.balanceOfBatch(depositors, ids);

        assertEq(balances[0], initialUsdcBalance);
        assertEq(balances[1], 0);
    }
}
