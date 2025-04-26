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

/// @title Counterpart
///
/// @notice Manages pairs of contracts that each need to know the address of the other, namely the `GatewayWallet` and
/// `GatewayMinter` contracts.
contract Counterpart is Initializable, Ownable2StepUpgradeable {
    /// Emitted when the counterpart is updated
    ///
    /// @param newCounterpart   The new counterpart address
    event CounterpartUpdated(address newCounterpart);

    /// Thrown when the counterpart is expected, but an unauthorized caller is used
    error UnauthorizedCounterpart(address caller);

    /// Sets the counterpart during initialization
    ///
    /// @param counterpart   The counterpart address
    function __Counterpart_init(address counterpart) internal onlyInitializing {
        _setCounterpart(counterpart);
    }

    /// Restricts the caller to the `counterpart` role, reverting with an error for other callers
    modifier onlyCounterpart() {
        _ensureIsCounterpart(msg.sender);
        _;
    }

    /// Updates the counterpart (only callable by the owner)
    ///
    /// @param newCounterpart   The new counterpart contract address
    function updateCounterpart(address newCounterpart) external onlyOwner {
        _setCounterpart(newCounterpart);
    }

    /// Ensures that the given address is the counterpart contract
    ///
    /// @param addr   The address to check
    function _ensureIsCounterpart(address addr) internal view {
        if (_counterpart() != addr) {
            revert UnauthorizedCounterpart(addr);
        }
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
        CounterpartStorage.get().counterpart = newCounterpart;
        emit CounterpartUpdated(newCounterpart);
    }
}

/// Implements the EIP-7201 storage pattern for the `Counterpart` module
library CounterpartStorage {
    /// @custom:storage-location 7201:circle.gateway.Counterpart
    struct Data {
        /// The address of the counterpart contract on the same chain
        address counterpart;
    }

    /// `keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Counterpart"))) - 1)) & ~bytes32(uint256(0xff))`
    bytes32 private constant SLOT = 0x93e77e25ef9d7551b01674a3ef68f44dcb2b33c68692c96a16f33bfe6d355b00;

    /// EIP-7201 getter for the storage slot
    function get() internal pure returns (Data storage $) {
        assembly {
            $.slot := SLOT
        }
    }
}
