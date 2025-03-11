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

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UpgradeablePlaceholder} from "src/UpgradeablePlaceholder.sol";
import {OwnershipTest} from "test/util/OwnershipTest.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";

contract UpgradeablePlaceholderBasicsTest is OwnershipTest, DeployUtils {
    UpgradeablePlaceholder private placeholder;

    /// Used by OwnershipTest
    function _subject() internal view override returns (address) {
        return address(placeholder);
    }

    function setUp() public {
        placeholder = deployPlaceholder(owner);
    }

    function test_initialize_revertWhenReinitialized() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(Initializable.InvalidInitialization.selector));
        placeholder.initialize(makeAddr("random"));
    }

    function test_initialize_revertIfOwnerAddressIsZero() public {
        placeholder = deployPlaceholderWithoutInitializing();

        vm.expectRevert(UpgradeablePlaceholder.NullOwnerNotAllowed.selector);
        placeholder.initialize(address(0));
    }

    function test_initialize_revertIfOwnerIsContract() public {
        placeholder = deployPlaceholderWithoutInitializing();

        address contractAddress = makeAddr("fakeContract");
        vm.etch(contractAddress, hex"100000");
        vm.expectRevert(
            abi.encodeWithSelector(UpgradeablePlaceholder.ContractOwnerNotAllowed.selector, contractAddress)
        );
        placeholder.initialize(contractAddress);
    }
}
