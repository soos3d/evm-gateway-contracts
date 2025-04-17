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

import {SpendWallet} from "src/SpendWallet.sol";
import {Deposits} from "src/lib/wallet/Deposits.sol";
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
        wallet = deployWalletOnly(owner, ForkTestUtils.forkVars().domain);

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
        vm.expectRevert(Deposits.DepositValueMustBePositive.selector);
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
        emit Deposits.Deposited(usdc, depositor, initialUsdcBalance / 2);
        wallet.deposit(usdc, initialUsdcBalance / 2);
        assertEq(wallet.spendableBalance(usdc, depositor), initialUsdcBalance / 2);

        // Deposit the other half
        vm.expectEmit(true, true, false, true);
        emit Deposits.Deposited(usdc, depositor, initialUsdcBalance / 2);
        wallet.deposit(usdc, initialUsdcBalance / 2);
        assertEq(wallet.spendableBalance(usdc, depositor), initialUsdcBalance);

        vm.stopPrank();
    }
}
