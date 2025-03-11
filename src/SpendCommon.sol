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
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Pausing} from "src/lib/common/Pausing.sol";
import {Counterpart} from "src/lib/common/Counterpart.sol";
import {Rejection} from "src/lib/common/Rejection.sol";
import {TokenSupport} from "src/lib/common/TokenSupport.sol";
import {SpendHashes} from "src/lib/common/SpendHashes.sol";
import {ContractOwnerNotAllowed} from "src/lib/Ownership.sol";

/// @title SpendCommon
///
/// This contract contains functionality that is common between `SpendWallet` and `SpendMinter`.
contract SpendCommon is
    Initializable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable,
    Pausing,
    Rejection,
    Counterpart,
    TokenSupport,
    SpendHashes
{
    /// Implements the UUPS upgrade pattern by restricting upgrades to the owner
    ///
    /// @param newImplementation   The address of the new implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// Initializes the contract
    function __SpendCommon_init() public initializer {
        __Pausing_init();
    }

    /// Prevent ownership from being transferred to a contract. Ownable2StepUpgradeable already prevents it from being
    /// transferred to the null address.
    function transferOwnership(address newOwner) public override onlyOwner {
        if (newOwner.code.length > 0) {
            revert ContractOwnerNotAllowed(newOwner);
        }
        super.transferOwnership(newOwner);
    }
}
