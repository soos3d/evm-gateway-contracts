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
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {NullOwnerNotAllowed, ContractOwnerNotAllowed} from "src/lib/Ownership.sol";

/// A no-op, upgradeable implementation contract for UUPS proxies
contract UpgradeablePlaceholder is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    /// Implements the UUPS upgrade pattern by restricting upgrades to the owner
    ///
    /// @param newImplementation   The address of the new implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// Initializes the contract with the given owner address
    ///
    /// @param newOwner   The address of the new owner
    function initialize(address newOwner) public initializer {
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
}
