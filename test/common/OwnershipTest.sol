/*
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.

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

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {NullOwnerNotAllowed, ContractOwnerNotAllowed} from "src/lib/Ownership.sol";
import {Test} from "forge-std/src/Test.sol";

abstract contract OwnershipTest is Test {
    address internal owner = makeAddr("owner");

    function _subject() internal virtual returns (address);

    function _ownableSubject() private returns (Ownable2StepUpgradeable) {
        return Ownable2StepUpgradeable(_subject());
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
}
