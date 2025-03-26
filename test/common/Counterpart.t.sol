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

import {Test} from "forge-std/Test.sol";
import {Counterpart} from "src/lib/common/Counterpart.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract CounterpartHarness is Counterpart {
    function initialize(address owner) public initializer {
        __Ownable_init(owner);
        __Ownable2Step_init();
    }

    function initializeCounterpart(address contractAddress) public reinitializer(2) {
        __Counterpart_init(contractAddress);
    }

    // Expose internal _counterpart function for testing
    function counterpart() public view returns (address) {
        return _counterpart();
    }

    // Helper function to specifically test the modifier onlyCounterpart
    function verifyCounterpartModifier() public onlyCounterpart {}
}

contract CounterpartTest is Test {
    CounterpartHarness private counterpart;

    address private owner = makeAddr("owner");
    address private contractAddress = makeAddr("contractAddress");
    address private newContractAddress = makeAddr("newContractAddress");

    event CounterpartUpdated(address contractAddress);

    function setUp() public {
        counterpart = new CounterpartHarness();
        counterpart.initialize(owner);
    }

    function testInitializationAndUpdate_success() public {
        assertEq(address(0), counterpart.counterpart());

        counterpart.initializeCounterpart(contractAddress);
        assertEq(contractAddress, counterpart.counterpart());

        vm.expectEmit(false, false, false, true);
        emit CounterpartUpdated(newContractAddress);

        vm.startPrank(owner);
        counterpart.updateCounterpart(newContractAddress);
        vm.stopPrank();

        assertEq(counterpart.counterpart(), newContractAddress);
    }

    function testInitialization_revertIfAlreadyInitialized() public {
        counterpart.initializeCounterpart(contractAddress);

        vm.expectRevert(abi.encodeWithSelector(Initializable.InvalidInitialization.selector));
        counterpart.initializeCounterpart(newContractAddress);
    }

    function testUpdateCounterpart_revertIfNotOwner() public {
        address random = makeAddr("random");
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, random));

        vm.startPrank(random);
        counterpart.updateCounterpart(newContractAddress);
        vm.stopPrank();
    }

    function testOnlyCounterpartModifier_success() public {
        counterpart.initializeCounterpart(contractAddress);

        vm.startPrank(contractAddress);
        counterpart.verifyCounterpartModifier();
        vm.stopPrank();
    }

    function testOnlyCounterpartModifier_revertIfNotCounterPartAddress() public {
        address random = makeAddr("random");
        vm.expectRevert(abi.encodeWithSelector(Counterpart.UnauthorizedCounterpart.selector, random));

        vm.startPrank(random);
        counterpart.verifyCounterpartModifier();
        vm.stopPrank();
    }
}
