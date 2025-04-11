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

/// @title Domain
///
/// Stores the operator-issued domain identifier of the current chain
contract Domain is Initializable {
    /// Sets the domain during initialization
    ///
    /// @param domain The operator-issued identifier for the current chain
    function __Domain_init(uint32 domain) internal onlyInitializing {
        DomainStorage.get().domain = domain;
    }

    /// Returns whether the given domain matches the current domain
    ///
    /// @param domain   The domain identifier to check
    function isCurrentDomain(uint32 domain) public view returns (bool) {
        return DomainStorage.get().domain == domain;
    }
}

/// Implements the EIP-7201 storage pattern for the Domain module
library DomainStorage {
    /// @custom:storage-location 7201:circle.spend.Domain
    struct Data {
        /// An operator-issued identifier for the current chain (does not match the chainId)
        uint32 domain;
    }

    /// keccak256(abi.encode(uint256(keccak256("circle.spend.Domain")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant SLOT = 0xb1f04e58cb6888af5b416b98ad47dac7866530383251193b3bfd00214c32ec00;

    /// EIP-7201 getter for the storage slot
    function get() internal pure returns (Data storage $) {
        assembly {
            $.slot := SLOT
        }
    }
}
