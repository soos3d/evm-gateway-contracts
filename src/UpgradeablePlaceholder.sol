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

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title Upgradeable Placeholder
///
/// A no-op, upgradeable implementation contract for UUPS proxies
contract UpgradeablePlaceholder is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    /// Thrown if the owner address is the zero address
    error NullOwnerNotAllowed();

    /// Thrown if the new owner address is a contract
    ///
    /// @param owner   The address of the owner
    error ContractOwnerNotAllowed(address owner);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// Initializes the contract with the given owner address
    ///
    /// @param newOwner   The address of the new owner
    function initialize(address newOwner) external initializer {
        if (newOwner == address(0)) {
            revert NullOwnerNotAllowed();
        }

        if (newOwner.code.length > 0) {
            revert ContractOwnerNotAllowed(newOwner);
        }

        __UUPSUpgradeable_init();
        __Ownable_init(newOwner);
        __Ownable2Step_init();
    }

    /// Implements the UUPS upgrade pattern by restricting upgrades to the owner
    ///
    /// @param newImplementation   The address of the new implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
