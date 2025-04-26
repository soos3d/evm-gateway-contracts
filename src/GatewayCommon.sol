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
import {Counterpart} from "src/modules/common/Counterpart.sol";
import {Denylist} from "src/modules/common/Denylist.sol";
import {Domain} from "src/modules/common/Domain.sol";
import {Pausing} from "src/modules/common/Pausing.sol";
import {TransferSpecHashes} from "src/modules/common/TransferSpecHashes.sol";
import {TokenSupport} from "src/modules/common/TokenSupport.sol";

/// @title Gateway Common
///
/// @notice Contains functionality that is common between `GatewayWallet` and `GatewayMinter`.
contract GatewayCommon is
    Initializable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable,
    Pausing,
    Denylist,
    Counterpart,
    TokenSupport,
    TransferSpecHashes,
    Domain
{
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Ensure that the implementation contract cannot be initialized, only the proxy
        _disableInitializers();
    }

    /// Initializes the contract, setting the counterpart to the given address, the pauser to the owner initially,
    /// and the domain to the given domain
    ///
    /// @param counterpart   The address of the counterpart contract (either `GatewayWallet` or `GatewayMinter`)
    /// @param domain        The operator-issued identifier for this chain
    function __GatewayCommon_init(address counterpart, uint32 domain) internal onlyInitializing {
        __Pausing_init(owner());
        __Counterpart_init(counterpart);
        __Domain_init(domain);
    }

    /// Implements the UUPS upgrade pattern by restricting upgrades to the owner
    ///
    /// @param newImplementation   The address of the new implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
