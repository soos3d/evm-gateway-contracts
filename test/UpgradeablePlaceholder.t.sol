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

import {Test} from "forge-std/src/Test.sol";
import {UpgradeablePlaceholder} from "../src/UpgradeablePlaceholder.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract ERC1967ProxyHarness is ERC1967Proxy {
    constructor(address _implementation, bytes memory _data) ERC1967Proxy(_implementation, _data) {}

    function implementation() public view returns (address) {
        return _implementation();
    }

    receive() external payable {}
}

contract UpgradeablePlaceholderTest is Test {
    address private owner = makeAddr("owner");

    UpgradeablePlaceholder private placeholder;
    ERC1967ProxyHarness private proxy;

    function setUp() public {
        UpgradeablePlaceholder placeholderImpl = new UpgradeablePlaceholder();
        proxy = new ERC1967ProxyHarness(
            address(placeholderImpl), abi.encodeCall(UpgradeablePlaceholder.initialize, (owner))
        );
        placeholder = UpgradeablePlaceholder(payable(address(proxy)));
    }

    function test_owner() public view {
        assertEq(placeholder.owner(), owner);
    }

    function test_initialize_revertWhenReInitialized() public {
        address randomAddress = vm.addr(123);
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(Initializable.InvalidInitialization.selector));
        placeholder.initialize(randomAddress);
        vm.stopPrank();
    }

    function test_transferOwnership() public {
        assertEq(placeholder.owner(), owner);

        address newOwner = makeAddr("new owner");
        vm.startPrank(owner);
        placeholder.transferOwnership(newOwner);
        vm.stopPrank();

        assertEq(placeholder.owner(), owner);
        assertEq(placeholder.pendingOwner(), newOwner);

        vm.startPrank(newOwner);
        placeholder.acceptOwnership();
        vm.stopPrank();

        assertEq(placeholder.owner(), newOwner);
        assertEq(placeholder.pendingOwner(), address(0));
    }

    function test_transferOwnership_revertIfNotOwner() public {
        address random = makeAddr("random");
        vm.startPrank(random);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, random));
        placeholder.transferOwnership(random);
        vm.stopPrank();
    }
}
