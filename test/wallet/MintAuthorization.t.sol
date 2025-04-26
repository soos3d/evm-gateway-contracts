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
pragma solidity ^0.8.29;

import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {Test} from "forge-std/Test.sol";
import {GatewayWallet} from "src/GatewayWallet.sol";
import {AddressLib} from "src/lib/util/AddressLib.sol";
import {Denylist} from "src/modules/common/Denylist.sol";
import {TokenSupport} from "src/modules/common/TokenSupport.sol";
import {Delegation} from "src/modules/wallet/Delegation.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";

/// Tests mint authorization functionality of GatewayWallet
contract MintAuthorizationTest is Test, DeployUtils {
    address private owner = makeAddr("owner");
    address private usdc = makeAddr("usdc");

    GatewayWallet private wallet;

    function setUp() public {
        wallet = deployWalletOnly(owner, ForkTestUtils.forkVars().domain);

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

    function test_addDelegate_canAddRevokedDelegate() public {
        address delegate = makeAddr("delegate");

        vm.startPrank(owner);
        wallet.addDelegate(usdc, delegate);
        vm.stopPrank();

        assertTrue(wallet.isAuthorizedForBalance(usdc, owner, delegate));

        vm.startPrank(owner);
        wallet.removeDelegate(usdc, delegate);
        vm.stopPrank();

        assertFalse(wallet.isAuthorizedForBalance(usdc, owner, delegate));

        vm.expectEmit(true, true, true, true);
        emit Delegation.DelegateAdded(usdc, owner, delegate);

        vm.startPrank(owner);
        wallet.addDelegate(usdc, delegate);
        vm.stopPrank();

        assertTrue(wallet.isAuthorizedForBalance(usdc, owner, delegate));
    }

    function test_addDelegate_isIdempotent() public {
        address delegate = makeAddr("delegate");

        vm.expectEmit(true, true, true, true);
        emit Delegation.DelegateAdded(usdc, owner, delegate);

        vm.startPrank(owner);
        wallet.addDelegate(usdc, delegate);
        vm.stopPrank();
        assertTrue(wallet.isAuthorizedForBalance(usdc, owner, delegate));

        vm.expectEmit(true, true, true, true);
        emit Delegation.DelegateAdded(usdc, owner, delegate);

        vm.startPrank(owner);
        wallet.addDelegate(usdc, delegate);
        vm.stopPrank();
        assertTrue(wallet.isAuthorizedForBalance(usdc, owner, delegate));
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
        vm.expectRevert(abi.encodeWithSelector(AddressLib.InvalidAddress.selector));
        wallet.addDelegate(usdc, delegate);
        vm.stopPrank();
    }

    function test_addDelegate_revertsWhenPaused() public {
        address delegate = makeAddr("delegate");

        vm.startPrank(owner);
        wallet.pause();
        vm.stopPrank();

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        vm.startPrank(owner);
        wallet.addDelegate(usdc, delegate);
        vm.stopPrank();
    }

    function test_addDelegate_revertsWhenDelegateDenylisted() public {
        address denylistedDelegate = makeAddr("denylistedDelegate");

        vm.startPrank(owner);
        wallet.updateDenylister(owner);
        wallet.denylist(denylistedDelegate);
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(Denylist.AccountDenylisted.selector, denylistedDelegate));
        vm.startPrank(owner);
        wallet.addDelegate(usdc, denylistedDelegate);
        vm.stopPrank();
    }

    function test_addDelegate_revertsWhenSenderDenylisted() public {
        address delegate = makeAddr("delegate");
        address denylistedSender = makeAddr("denylistedSender");

        vm.startPrank(owner);
        wallet.updateDenylister(owner);
        wallet.denylist(denylistedSender);
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(Denylist.AccountDenylisted.selector, denylistedSender));
        vm.startPrank(denylistedSender);
        wallet.addDelegate(usdc, delegate);
        vm.stopPrank();
    }

    function test_addDelegate_revertsWhenTokenNotSupported() public {
        address delegate = makeAddr("delegate");
        address unsupportedToken = makeAddr("unsupportedToken");

        vm.expectRevert(abi.encodeWithSelector(TokenSupport.UnsupportedToken.selector, unsupportedToken));
        vm.startPrank(owner);
        wallet.addDelegate(unsupportedToken, delegate);
        vm.stopPrank();
    }

    function test_removeDelegate_doesNothingWhenDelegateUnauthorized() public {
        address delegate = makeAddr("delegate");

        assertFalse(wallet.isAuthorizedForBalance(usdc, owner, delegate));

        vm.startPrank(owner);
        wallet.removeDelegate(usdc, delegate);
        vm.stopPrank();

        assertFalse(wallet.isAuthorizedForBalance(usdc, owner, delegate));
    }

    function test_removeDelegate_doesNothingWhenDelegateRevoked() public {
        address delegate = makeAddr("delegate");

        assertFalse(wallet.isAuthorizedForBalance(usdc, owner, delegate));

        vm.startPrank(owner);
        wallet.addDelegate(usdc, delegate);
        assertTrue(wallet.isAuthorizedForBalance(usdc, owner, delegate));
        wallet.removeDelegate(usdc, delegate); // State is now Revoked
        assertFalse(wallet.isAuthorizedForBalance(usdc, owner, delegate));
        wallet.removeDelegate(usdc, delegate);
        vm.stopPrank();

        assertFalse(wallet.isAuthorizedForBalance(usdc, owner, delegate));
    }

    function test_removeDelegate_revertsWhenDelegateIsZeroAddress() public {
        address delegate = address(0);

        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(AddressLib.InvalidAddress.selector));
        wallet.removeDelegate(usdc, delegate);
        vm.stopPrank();
    }

    function test_removeDelegate_revertsWhenPaused() public {
        address delegate = makeAddr("delegate");

        vm.startPrank(owner);
        wallet.addDelegate(usdc, delegate);
        wallet.pause();
        vm.stopPrank();

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        vm.startPrank(owner);
        wallet.removeDelegate(usdc, delegate);
        vm.stopPrank();
    }

    function test_removeDelegate_succeedsWhenDelegateDenylisted() public {
        address delegateToRemove = makeAddr("delegateToRemove");

        vm.startPrank(owner);
        wallet.addDelegate(usdc, delegateToRemove);
        vm.stopPrank();

        assertTrue(wallet.isAuthorizedForBalance(usdc, owner, delegateToRemove));

        vm.startPrank(owner);
        wallet.updateDenylister(owner);
        wallet.denylist(delegateToRemove);
        vm.stopPrank();

        assertTrue(wallet.isDenylisted(delegateToRemove));

        vm.startPrank(owner);
        wallet.removeDelegate(usdc, delegateToRemove);
        vm.stopPrank();

        assertFalse(wallet.isAuthorizedForBalance(usdc, owner, delegateToRemove));
    }

    function test_removeDelegate_revertsWhenSenderDenylisted() public {
        address delegate = makeAddr("delegate");
        address denylistedSender = makeAddr("denylistedSender");

        vm.startPrank(owner);
        wallet.addDelegate(usdc, delegate);
        vm.stopPrank();

        vm.startPrank(owner);
        wallet.updateDenylister(owner);
        wallet.denylist(denylistedSender);
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(Denylist.AccountDenylisted.selector, denylistedSender));
        vm.startPrank(denylistedSender);
        wallet.removeDelegate(usdc, delegate);
        vm.stopPrank();
    }

    function test_removeDelegate_revertsWhenTokenNotSupported() public {
        address delegate = makeAddr("delegate");
        address unsupportedToken = makeAddr("unsupportedToken");

        vm.expectRevert(abi.encodeWithSelector(TokenSupport.UnsupportedToken.selector, unsupportedToken));
        vm.startPrank(owner);
        wallet.removeDelegate(unsupportedToken, delegate);
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

    function test_multipleDelegates_differentTokens() public {
        address delegateA = makeAddr("delegateA");
        address delegateB = makeAddr("delegateB");
        address otherToken = makeAddr("otherToken");

        vm.startPrank(owner);
        wallet.addSupportedToken(otherToken);
        wallet.addDelegate(usdc, delegateA);
        wallet.addDelegate(otherToken, delegateB);
        vm.stopPrank();

        assertTrue(wallet.isAuthorizedForBalance(usdc, owner, delegateA));
        assertTrue(wallet.isAuthorizedForBalance(otherToken, owner, delegateB));
        assertFalse(wallet.isAuthorizedForBalance(usdc, owner, delegateB));
        assertFalse(wallet.isAuthorizedForBalance(otherToken, owner, delegateA));
    }

    function test_multipleDelegates_sameToken() public {
        address delegateA = makeAddr("delegateA");
        address delegateB = makeAddr("delegateB");

        vm.startPrank(owner);
        wallet.addDelegate(usdc, delegateA);
        wallet.addDelegate(usdc, delegateB);
        vm.stopPrank();

        assertTrue(wallet.isAuthorizedForBalance(usdc, owner, delegateA));
        assertTrue(wallet.isAuthorizedForBalance(usdc, owner, delegateB));

        vm.startPrank(owner);
        wallet.removeDelegate(usdc, delegateA);
        vm.stopPrank();

        assertFalse(wallet.isAuthorizedForBalance(usdc, owner, delegateA));
        assertTrue(wallet.isAuthorizedForBalance(usdc, owner, delegateB));
    }

    function test_multipleDepositors() public {
        address depositor1 = makeAddr("depositor1");
        address depositor2 = makeAddr("depositor2");
        address delegateA = makeAddr("delegateA");
        address delegateB = makeAddr("delegateB");

        vm.startPrank(depositor1);
        wallet.addDelegate(usdc, delegateA);
        vm.stopPrank();

        vm.startPrank(depositor2);
        wallet.addDelegate(usdc, delegateB);
        vm.stopPrank();

        assertTrue(wallet.isAuthorizedForBalance(usdc, depositor1, delegateA));
        assertFalse(wallet.isAuthorizedForBalance(usdc, depositor2, delegateA));

        assertTrue(wallet.isAuthorizedForBalance(usdc, depositor2, delegateB));
        assertFalse(wallet.isAuthorizedForBalance(usdc, depositor1, delegateB));
    }
}
