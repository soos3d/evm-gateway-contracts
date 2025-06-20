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
import {AddressLib} from "src/lib/AddressLib.sol";
import {Deposits} from "src/modules/wallet/Deposits.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";

interface IBlacklistable {
    function blacklister() external returns (address);
    function blacklist(address _account) external;
}

/// Tests basic depositFor functionality of GatewayWallet
contract GatewayWalletDepositForTest is Test, DeployUtils {
    address private owner = makeAddr("owner");
    address private depositor = makeAddr("gatewayWalletDepositor");
    address private sender = makeAddr("gatewayWalletSender");
    address private usdc;

    uint256 private initialUsdcBalance = 1000 * 10 ** 6;

    // Revert error strings
    string private constant ERC20_TRANSFER_AMOUNT_EXCEEDS_ALLOWANCE = "ERC20: transfer amount exceeds allowance";

    GatewayWallet private wallet;

    function setUp() public {
        wallet = deployWalletOnly(owner, ForkTestUtils.forkVars().domain);

        usdc = ForkTestUtils.forkVars().usdc;
        vm.prank(owner);
        wallet.addSupportedToken(usdc);
        // Mint initial USDC balance to sender
        deal(usdc, sender, initialUsdcBalance);
    }

    function test_depositFor_revertIfWalletNotApproved() public {
        vm.startPrank(sender);
        vm.expectRevert(bytes(ERC20_TRANSFER_AMOUNT_EXCEEDS_ALLOWANCE));
        wallet.depositFor(usdc, depositor, initialUsdcBalance);
        vm.stopPrank();
    }

    function test_depositFor_revertIfValueNonPositive() public {
        vm.startPrank(sender);
        vm.expectRevert(Deposits.DepositValueMustBePositive.selector);
        wallet.depositFor(usdc, depositor, 0);
        vm.stopPrank();
    }

    function test_depositFor_revertIfValueMoreThanApproved() public {
        vm.startPrank(sender);
        IERC20(usdc).approve(address(wallet), initialUsdcBalance);
        vm.expectRevert(bytes(ERC20_TRANSFER_AMOUNT_EXCEEDS_ALLOWANCE));
        wallet.depositFor(usdc, depositor, 2 * initialUsdcBalance);
        vm.stopPrank();
    }

    function test_depositFor_revertIfDepositorBlacklisted() public {
        address blacklister = IBlacklistable(usdc).blacklister();
        vm.prank(blacklister);
        IBlacklistable(usdc).blacklist(depositor);
        vm.stopPrank();

        vm.startPrank(sender);
        IERC20(usdc).approve(address(wallet), initialUsdcBalance);
        vm.expectRevert(abi.encodeWithSelector(Deposits.DepositorIsBlacklisted.selector, depositor));
        wallet.depositFor(usdc, depositor, initialUsdcBalance);
        vm.stopPrank();
    }

    function test_depositFor_revertIfDepositorZeroAddress() public {
        vm.startPrank(sender);
        IERC20(usdc).approve(address(wallet), initialUsdcBalance);
        vm.expectRevert(AddressLib.InvalidAddress.selector);
        wallet.depositFor(usdc, address(0), initialUsdcBalance);
        vm.stopPrank();
    }

    function test_depositFor_availableBalanceUpdatedAfterTransfer() public {
        vm.startPrank(sender);
        IERC20(usdc).approve(address(wallet), initialUsdcBalance);

        // Deposit half of the allowance
        vm.expectEmit(true, true, true, true);
        emit Deposits.Deposited(usdc, depositor, sender, initialUsdcBalance / 2);
        wallet.depositFor(usdc, depositor, initialUsdcBalance / 2);
        assertEq(wallet.availableBalance(usdc, depositor), initialUsdcBalance / 2);

        // Deposit the other half
        vm.expectEmit(true, true, true, true);
        emit Deposits.Deposited(usdc, depositor, sender, initialUsdcBalance / 2);
        wallet.depositFor(usdc, depositor, initialUsdcBalance / 2);
        assertEq(wallet.availableBalance(usdc, depositor), initialUsdcBalance);

        vm.stopPrank();
    }
}
