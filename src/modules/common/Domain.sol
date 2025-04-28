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

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/// @title Domain
///
/// @notice Stores the operator-issued domain identifier of the current chain
contract Domain is Initializable {
    /// Initializes the domain
    ///
    /// @param domain_   The operator-issued identifier for the current chain
    function __Domain_init(uint32 domain_) internal onlyInitializing {
        DomainStorage.get().domain = domain_;
    }

    /// Returns the current domain
    ///
    /// @return   The operator-issued identifier for the current chain
    function domain() public view returns (uint32) {
        return DomainStorage.get().domain;
    }

    /// Returns whether the given domain matches the current domain
    ///
    /// @param _domain   The domain identifier to check
    /// @return          `true` if the given domain matches the current domain, `false` otherwise
    function _isCurrentDomain(uint32 _domain) internal view returns (bool) {
        return DomainStorage.get().domain == _domain;
    }
}

/// @title DomainStorage
///
/// @notice Implements the EIP-7201 storage pattern for the `Domain` module
library DomainStorage {
    /// @custom:storage-location 7201:circle.gateway.Domain
    struct Data {
        /// An operator-issued identifier for the current chain (does not match the chainId)
        uint32 domain;
    }

    /// `keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Domain"))) - 1)) & ~bytes32(uint256(0xff))`
    bytes32 public constant SLOT = 0xfe4c86d7e89d95779292c8077b542f271e850fa895928d0b7b19a0ae50865c00;

    /// EIP-7201 getter for the storage slot
    ///
    /// @return $   The storage struct for the `Domain` module
    function get() internal pure returns (Data storage $) {
        assembly ("memory-safe") {
            $.slot := SLOT
        }
    }
}
