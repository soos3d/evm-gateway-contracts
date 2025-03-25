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
import {Test} from "forge-std/Test.sol";

/// Tests Spend Authorization functionality of SpendWallet
contract SpendAuthorizationTest is Test, DeployUtils {
    address private owner = makeAddr("owner");
    address private usdc = makeAddr("usdc");

    SpendWallet private wallet;

    event SpenderAdded(address indexed token, address indexed depositor, address spender);

    event SpenderRemoved(address indexed token, address indexed depositor, address spender);

    function setUp() public {
        wallet = deployWalletOnly(owner);

        vm.prank(owner);
        wallet.addSupportedToken(usdc);
        vm.stopPrank();
    }

    function testSpenderAuthorizationFlow_addAndRemoveSpender() public {
        address spender = makeAddr("spender");

        vm.expectEmit(true, true, false, true);
        emit SpenderAdded(usdc, owner, spender);

        assertFalse(wallet.isSpender(usdc, spender, owner));

        vm.startPrank(owner);
        wallet.addSpender(usdc, spender);
        vm.stopPrank();

        assertTrue(wallet.isSpender(usdc, spender, owner));
        emit SpenderRemoved(usdc, owner, spender);

        vm.startPrank(owner);
        wallet.removeSpender(usdc, spender);
        vm.stopPrank();

        assertFalse(wallet.isSpender(usdc, spender, owner));
    }

    function testAddSpender_revertsWhenSpenderIsSelf() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(SpendWallet.CannotAddSelfAsSpender.selector));
        wallet.addSpender(usdc, owner);
        vm.stopPrank();
    }

    function testAddSpender_revertsWhenSpenderIsZeroAddress() public {
        address spender = address(0);

        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(SpendWallet.InvalidAddress.selector));
        wallet.addSpender(usdc, spender);
        vm.stopPrank();
    }

    function testRemoveSpender_revertsWhenSpenderIsZeroAddress() public {
        address spender = address(0);

        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(SpendWallet.InvalidAddress.selector));
        wallet.removeSpender(usdc, spender);
        vm.stopPrank();
    }

    function testIsSpender_returnsTrueWhenSpenderAndDepositorSame() public {
        vm.startPrank(owner);
        assertTrue(wallet.isSpender(usdc, owner, owner));
        vm.stopPrank();
    }

    function testIsSpender_returnsFalseWhenNoAuthorizationExists() public {
        address spender = makeAddr("spender");

        vm.startPrank(owner);
        assertFalse(wallet.isSpender(usdc, spender, owner));
        vm.stopPrank();
    }
}
