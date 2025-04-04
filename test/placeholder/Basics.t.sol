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
