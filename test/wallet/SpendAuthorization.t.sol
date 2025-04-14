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
import {Delegation} from "src/lib/wallet/Delegation.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {Test} from "forge-std/Test.sol";

/// Tests Spend Authorization functionality of SpendWallet
contract SpendAuthorizationTest is Test, DeployUtils {
    address private owner = makeAddr("owner");
    address private usdc = makeAddr("usdc");

    SpendWallet private wallet;

    function setUp() public {
        wallet = deployWalletOnly(owner);

        vm.prank(owner);
        wallet.addSupportedToken(usdc);
        vm.stopPrank();
    }

    function test_delegateAuthorizationFlow_addAndRemoveDelegate() public {
        address delegate = makeAddr("delegate");

        vm.expectEmit(true, true, false, true);
        emit Delegation.DelegateAdded(usdc, owner, delegate);

        assertFalse(wallet.isAuthorizedForBalance(usdc, owner, delegate));

        vm.startPrank(owner);
        wallet.addDelegate(usdc, delegate);
        vm.stopPrank();

        assertTrue(wallet.isAuthorizedForBalance(usdc, owner, delegate));
        emit Delegation.DelegateRemoved(usdc, owner, delegate);

        vm.startPrank(owner);
        wallet.removeDelegate(usdc, delegate);
        vm.stopPrank();

        assertFalse(wallet.isAuthorizedForBalance(usdc, owner, delegate));
    }

    function test_addDelegate_revertsWhenDelegateIsSelf() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(Delegation.CannotDelegateToSelf.selector));
        wallet.addDelegate(usdc, owner);
        vm.stopPrank();
    }

    function test_addDelegate_revertsWhenDelegateIsZeroAddress() public {
        address delegate = address(0);

        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(SpendCommon.InvalidAddress.selector));
        wallet.addDelegate(usdc, delegate);
        vm.stopPrank();
    }

    function test_removeDelegate_revertsWhenDelegateIsZeroAddress() public {
        address delegate = address(0);

        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(SpendCommon.InvalidAddress.selector));
        wallet.removeDelegate(usdc, delegate);
        vm.stopPrank();
    }

    function test_isAuthorizedForBalance_returnsTrueWhenDelegateAndDepositorSame() public {
        vm.startPrank(owner);
        assertTrue(wallet.isAuthorizedForBalance(usdc, owner, owner));
        vm.stopPrank();
    }

    function test_isAuthorizedForBalance_returnsFalseWhenNoAuthorizationExists() public {
        address delegate = makeAddr("delegate");

        vm.startPrank(owner);
        assertFalse(wallet.isAuthorizedForBalance(usdc, owner, delegate));
        vm.stopPrank();
    }
}
