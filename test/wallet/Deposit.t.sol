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

/// Tests basic deposit functionality of SpendWallet
contract SpendWalletDepositTest is Test, DeployUtils {
    address private owner = makeAddr("owner");
    uint256 private depositorPrivateKey;
    address private depositor;
    address private usdc;

    uint256 private initialUsdcBalance = 1000 * 10 ** 6;

    // Revert error strings
    string private constant ERC20_TRANSFER_AMOUNT_EXCEEDS_ALLOWANCE = "ERC20: transfer amount exceeds allowance";

    SpendWallet private wallet;

    function setUp() public {
        (depositor, depositorPrivateKey) = makeAddrAndKey("spendWalletDepositor");
        wallet = deployWalletOnly(owner);

        usdc = ForkTestUtils.forkVars().usdc;
        vm.prank(owner);
        wallet.addSupportedToken(usdc);
        // Mint initial USDC balance to depositor
        deal(usdc, depositor, initialUsdcBalance);
    }

    function test_deposit_revertIfWalletNotApproved() public {
        vm.startPrank(depositor);
        vm.expectRevert(bytes(ERC20_TRANSFER_AMOUNT_EXCEEDS_ALLOWANCE));
        wallet.deposit(usdc, initialUsdcBalance);
        vm.stopPrank();
    }

    function test_deposit_revertIfValueNonPositive() public {
        vm.startPrank(depositor);
        vm.expectRevert(SpendWallet.DepositValueMustBePositive.selector);
        wallet.deposit(usdc, 0);
        vm.stopPrank();
    }

    function test_deposit_revertIfValueMoreThanApproved() public {
        vm.startPrank(depositor);
        IERC20(usdc).approve(address(wallet), initialUsdcBalance);
        vm.expectRevert(bytes(ERC20_TRANSFER_AMOUNT_EXCEEDS_ALLOWANCE));
        wallet.deposit(usdc, 2 * initialUsdcBalance);
        vm.stopPrank();
    }

    function test_deposit_spendableBalanceUpdatedAfterTransfer() public {
        vm.startPrank(depositor);
        IERC20(usdc).approve(address(wallet), initialUsdcBalance);

        // Deposit half of the allowance
        vm.expectEmit(true, true, false, true);
        emit SpendWallet.Deposited(usdc, depositor, initialUsdcBalance / 2);
        wallet.deposit(usdc, initialUsdcBalance / 2);
        assertEq(wallet.spendableBalance(usdc, depositor), initialUsdcBalance / 2);

        // Deposit the other half
        vm.expectEmit(true, true, false, true);
        emit SpendWallet.Deposited(usdc, depositor, initialUsdcBalance / 2);
        wallet.deposit(usdc, initialUsdcBalance / 2);
        assertEq(wallet.spendableBalance(usdc, depositor), initialUsdcBalance);

        vm.stopPrank();
    }
}
