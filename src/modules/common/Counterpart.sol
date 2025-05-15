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

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/// @title Counterpart
///
/// @notice Manages pairs of contracts that each need to know the address of the other, namely the `GatewayWallet` and
/// `GatewayMinter` contracts.
contract Counterpart is Initializable, Ownable2StepUpgradeable {
    /// Emitted when the counterpart is updated
    ///
    /// @param oldCounterpart   The old counterpart address
    /// @param newCounterpart   The new counterpart address
    event CounterpartChanged(address indexed oldCounterpart, address indexed newCounterpart);

    /// Initializes the `counterpart` contract address
    ///
    /// @param counterpart_   The counterpart address
    function __Counterpart_init(address counterpart_) internal onlyInitializing {
        _setCounterpart(counterpart_);
    }

    /// Updates the counterpart (only callable by the owner)
    ///
    /// @param newCounterpart   The new counterpart contract address
    function updateCounterpart(address newCounterpart) public onlyOwner {
        _setCounterpart(newCounterpart);
    }

    /// Returns the counterpart address
    ///
    /// @return   The counterpart address
    function _counterpart() internal view returns (address) {
        return CounterpartStorage.get().counterpart;
    }

    /// Sets the counterpart in storage and emits an event
    ///
    /// @param newCounterpart   The new counterpart contract address
    function _setCounterpart(address newCounterpart) private {
        address oldCounterpart = CounterpartStorage.get().counterpart;
        CounterpartStorage.get().counterpart = newCounterpart;
        emit CounterpartChanged(oldCounterpart, newCounterpart);
    }
}

/// @title CounterpartStorage
///
/// @notice Implements the EIP-7201 storage pattern for the `Counterpart` module
library CounterpartStorage {
    /// @custom:storage-location 7201:circle.gateway.Counterpart
    struct Data {
        /// The address of the counterpart contract on the same chain
        address counterpart;
    }

    /// `keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Counterpart"))) - 1)) & ~bytes32(uint256(0xff))`
    bytes32 public constant SLOT = 0x93e77e25ef9d7551b01674a3ef68f44dcb2b33c68692c96a16f33bfe6d355b00;

    /// EIP-7201 getter for the storage slot
    ///
    /// @return $   The storage struct for the `Counterpart` module
    function get() internal pure returns (Data storage $) {
        assembly ("memory-safe") {
            $.slot := SLOT
        }
    }
}
