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

import {SpendCommon} from "src/SpendCommon.sol";
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
        vm.expectRevert(abi.encodeWithSelector(SpendCommon.InvalidAddress.selector));
        wallet.addSpender(usdc, spender);
        vm.stopPrank();
    }

    function testRemoveSpender_revertsWhenSpenderIsZeroAddress() public {
        address spender = address(0);

        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(SpendCommon.InvalidAddress.selector));
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
