/*
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.

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

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {SpendCommon} from "src/SpendCommon.sol";
import {SpendWallet} from "src/SpendWallet.sol";
import {OwnershipTest} from "test/util/OwnershipTest.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";

/// Tests ownership and initialization functionality of SpendMinter
contract SpendWalletBasicsTest is OwnershipTest, DeployUtils {
    SpendWallet private wallet;

    /// Used by OwnershipTest
    function _subject() internal view override returns (address) {
        return address(wallet);
    }

    function setUp() public {
        wallet = deployWalletOnly(owner);
    }

    function test_initialize_revertWhenReinitialized() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(Initializable.InvalidInitialization.selector));
        wallet.initialize(makeAddr("random"));
    }

    function test_updateBurnCaller_revertWhenNotOwner() public {
        address randomCaller = makeAddr("random");
        address newBurnCaller = makeAddr("newBurnCaller");

        vm.prank(randomCaller);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, randomCaller));
        wallet.updateBurnCaller(newBurnCaller);
    }

    function test_updateBurnCaller_revertWhenZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(SpendCommon.InvalidAddress.selector);
        wallet.updateBurnCaller(address(0));
    }

    function test_updateBurnCaller_success(address newBurnCaller) public {
        vm.assume(newBurnCaller != address(0));

        address oldBurnCaller = wallet.burnCaller();

        vm.expectEmit(false, false, false, true);
        emit SpendWallet.BurnCallerUpdated(oldBurnCaller, newBurnCaller);

        vm.prank(owner);
        wallet.updateBurnCaller(newBurnCaller);

        assertEq(wallet.burnCaller(), newBurnCaller);
    }

    function test_updateBurnCaller_idempotent() public {
        address newBurnCaller = makeAddr("newBurnCaller");
        vm.startPrank(owner);
        wallet.updateBurnCaller(newBurnCaller); // first update
        assertEq(wallet.burnCaller(), newBurnCaller);

        vm.expectEmit(false, false, false, true);
        emit SpendWallet.BurnCallerUpdated(newBurnCaller, newBurnCaller);
        wallet.updateBurnCaller(newBurnCaller); // second update

        assertEq(wallet.burnCaller(), newBurnCaller);
    }

    function test_burnSpent_revertWhenNotBurnCaller() public {
        address randomCaller = makeAddr("random");

        vm.prank(randomCaller);
        vm.expectRevert(abi.encodeWithSelector(SpendWallet.CallerNotBurnCaller.selector));
        wallet.burnSpent(new bytes[](0), new bytes[](0), new uint256[][](0));
    }
}
