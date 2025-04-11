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

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {SpendCommon} from "src/SpendCommon.sol";
import {SpendWallet} from "src/SpendWallet.sol";
import {OwnershipTest} from "test/util/OwnershipTest.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";

/// Tests ownership and initialization functionality of SpendMinter
contract SpendWalletBasicsTest is OwnershipTest, DeployUtils {
    uint32 private domain = 99;

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
        wallet.initialize(makeAddr("random"), domain);
    }

    function test_updateBurnSigner_revertWhenNotOwner() public {
        address randomCaller = makeAddr("random");
        address newBurnSigner = makeAddr("newBurnSigner");

        vm.prank(randomCaller);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, randomCaller));
        wallet.updateBurnSigner(newBurnSigner);
    }

    function test_updateBurnSigner_revertWhenZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(SpendCommon.InvalidAddress.selector);
        wallet.updateBurnSigner(address(0));
    }

    function test_updateBurnSigner_success(address newBurnSigner) public {
        vm.assume(newBurnSigner != address(0));

        address oldBurnSigner = wallet.burnSigner();

        vm.expectEmit(false, false, false, true);
        emit SpendWallet.BurnSignerUpdated(oldBurnSigner, newBurnSigner);

        vm.prank(owner);
        wallet.updateBurnSigner(newBurnSigner);

        assertEq(wallet.burnSigner(), newBurnSigner);
    }

    function test_updateBurnSigner_idempotent() public {
        address newBurnSigner = makeAddr("newBurnSigner");
        vm.startPrank(owner);
        wallet.updateBurnSigner(newBurnSigner); // first update
        assertEq(wallet.burnSigner(), newBurnSigner);

        vm.expectEmit(false, false, false, true);
        emit SpendWallet.BurnSignerUpdated(newBurnSigner, newBurnSigner);
        wallet.updateBurnSigner(newBurnSigner); // second update

        assertEq(wallet.burnSigner(), newBurnSigner);
    }

    function test_updateFeeRecipient_revertWhenNotOwner() public {
        address randomCaller = makeAddr("random");
        address newFeeRecipient = makeAddr("newFeeRecipient");

        vm.prank(randomCaller);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, randomCaller));
        wallet.updateFeeRecipient(newFeeRecipient);
    }

    function test_updateFeeRecipient_revertWhenZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(SpendCommon.InvalidAddress.selector);
        wallet.updateFeeRecipient(address(0));
    }

    function test_updateFeeRecipient_success(address newFeeRecipient) public {
        vm.assume(newFeeRecipient != address(0));

        address oldFeeRecipient = wallet.feeRecipient();

        vm.expectEmit(false, false, false, true);
        emit SpendWallet.FeeRecipientUpdated(oldFeeRecipient, newFeeRecipient);

        vm.prank(owner);
        wallet.updateFeeRecipient(newFeeRecipient);

        assertEq(wallet.feeRecipient(), newFeeRecipient);
    }

    function test_updateFeeRecipient_idempotent() public {
        address newFeeRecipient = makeAddr("newFeeRecipient");
        vm.startPrank(owner);
        wallet.updateFeeRecipient(newFeeRecipient); // first update
        assertEq(wallet.feeRecipient(), newFeeRecipient);

        vm.expectEmit(false, false, false, true);
        emit SpendWallet.FeeRecipientUpdated(newFeeRecipient, newFeeRecipient);
        wallet.updateFeeRecipient(newFeeRecipient); // second update

        assertEq(wallet.feeRecipient(), newFeeRecipient);
    }
}
