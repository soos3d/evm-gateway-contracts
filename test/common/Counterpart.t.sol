/**
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
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

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Test} from "forge-std/Test.sol";
import {Counterpart} from "src/modules/common/Counterpart.sol";

contract CounterpartHarness is Counterpart {
    function initialize(address owner, address counterpartAddress) public initializer {
        __Ownable_init(owner);
        __Ownable2Step_init();
        __Counterpart_init(counterpartAddress);
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
    address private counterpartAddress = makeAddr("counterpartAddress");
    address private secondCounterpartAddress = makeAddr("secondCounterpartAddress");

    function setUp() public {
        counterpart = new CounterpartHarness();
    }

    function testInitializationAndUpdate_success() public {
        assertEq(address(0), counterpart.counterpart());

        counterpart.initialize(owner, counterpartAddress);
        assertEq(counterpartAddress, counterpart.counterpart());

        vm.expectEmit(false, false, false, true);
        emit Counterpart.CounterpartUpdated(secondCounterpartAddress);

        vm.startPrank(owner);
        counterpart.updateCounterpart(secondCounterpartAddress);
        vm.stopPrank();

        assertEq(counterpart.counterpart(), secondCounterpartAddress);
    }

    function testInitialization_revertIfAlreadyInitialized() public {
        counterpart.initialize(owner, counterpartAddress);

        vm.expectRevert(abi.encodeWithSelector(Initializable.InvalidInitialization.selector));
        counterpart.initialize(owner, secondCounterpartAddress);
    }

    function testUpdateCounterpart_revertIfNotOwner() public {
        address random = makeAddr("random");
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, random));

        vm.startPrank(random);
        counterpart.updateCounterpart(counterpartAddress);
        vm.stopPrank();
    }

    function testOnlyCounterpartModifier_success() public {
        counterpart.initialize(owner, counterpartAddress);

        vm.startPrank(counterpartAddress);
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
