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
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Pausing} from "src/lib/common/Pausing.sol";
import {Counterpart} from "src/lib/common/Counterpart.sol";
import {Rejection} from "src/lib/common/Rejection.sol";
import {TokenSupport} from "src/lib/common/TokenSupport.sol";
import {SpendHashes} from "src/lib/common/SpendHashes.sol";

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
    /**
     * @dev Reverts if an invalid address is set.
     */
    error InvalidAddress();

    /// Implements the UUPS upgrade pattern by restricting upgrades to the owner
    ///
    /// @param newImplementation   The address of the new implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Ensure that the implementation contract cannot be initialized, only the proxy
        _disableInitializers();
    }

    /// Initializes the contract, setting the counterpart to the given address and the pauser to the owner initially
    ///
    /// @param counterpart   The address of the counterpart contract (either `SpendWallet` or `SpendMinter`)
    function __SpendCommon_init(address counterpart) public onlyInitializing {
        __Pausing_init(owner());
        __Counterpart_init(counterpart);
    }

    /// Validates that an address is not the zero address
    ///
    /// @param addr   The address being authorized to spend
    function _checkNotZeroAddress(address addr) internal pure {
        if (addr == address(0)) {
            revert InvalidAddress();
        }
    }
}
