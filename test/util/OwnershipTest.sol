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

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Test} from "forge-std/Test.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

abstract contract OwnershipTest is Test {
    address internal owner = makeAddr("owner");

    /// Implement this to return the subject of the test
    function _subject() internal virtual returns (address);

    /// Returns the subject as an Ownable2StepUpgradeable
    function _ownableSubject() private returns (Ownable2StepUpgradeable) {
        return Ownable2StepUpgradeable(_subject());
    }

    function _upgradableSubject() private returns (UUPSUpgradeable) {
        return UUPSUpgradeable(_subject());
    }

    function test_owner() public {
        assertEq(_ownableSubject().owner(), owner);
    }

    function test_transferOwnership() public {
        address newOwner = makeAddr("new owner");

        vm.startPrank(owner);
        _ownableSubject().transferOwnership(newOwner);
        vm.stopPrank();

        assertEq(_ownableSubject().owner(), owner);
        assertEq(_ownableSubject().pendingOwner(), newOwner);

        vm.startPrank(newOwner);
        _ownableSubject().acceptOwnership();
        vm.stopPrank();

        assertEq(_ownableSubject().owner(), newOwner);
        assertEq(_ownableSubject().pendingOwner(), address(0));
    }

    function test_transferOwnership_revertIfNotOwner() public {
        address random = makeAddr("random");

        vm.startPrank(random);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, random));
        _ownableSubject().transferOwnership(random);
        vm.stopPrank();
    }

    function test_upgradeToAndCall_revertIfNotOwner() public {
        address random = makeAddr("random");
        address mockImplementation = makeAddr("mockImplementation");

        vm.startPrank(random);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, random));
        _upgradableSubject().upgradeToAndCall(address(mockImplementation), new bytes(0));
        vm.stopPrank();
    }
}
