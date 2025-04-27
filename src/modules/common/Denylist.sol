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

/// @title Denylist
///
/// @notice Manages a denylist of addresses that are not allowed to interact with the system.
contract Denylist is Ownable2StepUpgradeable {
    /// Emitted when an address is added to the denylist
    ///
    /// @param addr   The address that is now being denied from interacting with the contract
    event Denylisted(address indexed addr);

    /// Emitted when an address is removed from the denylist
    ///
    /// @param addr   The address that is allowed to interact with the contract again
    event UnDenylisted(address indexed addr);

    /// Emitted when the denylister address is updated
    ///
    /// @param oldDenylister   The old denylister address
    /// @param newDenylister   The new denylister address
    event DenylisterChanged(address indexed oldDenylister, address indexed newDenylister);

    /// Thrown when an unauthorized address attempts to denylist or un-denylist addresses
    ///
    /// @param addr   The unauthorized address
    error UnauthorizedDenylister(address addr);

    /// Thrown when an address is denied from interacting with the contract
    ///
    /// @param addr   The denylisted address
    error AccountDenylisted(address addr);

    /// Restricts access to a function to addresses that are not denylisted
    ///
    /// @param addr   The address to check
    modifier notDenylisted(address addr) {
        _ensureNotDenylisted(addr);
        _;
    }

    /// Restricts the caller to the `denylister` role, reverting with an error for other callers
    modifier onlyDenylister() {
        if (msg.sender != DenylistStorage.get().denylister) {
            revert UnauthorizedDenylister(msg.sender);
        }
        _;
    }

    /// Whether or not a given address is denied from interacting with the contract
    ///
    /// @param addr   The address to check
    /// @return       `true` if the address is denylisted, `false` otherwise
    function isDenylisted(address addr) public view returns (bool) {
        return DenylistStorage.get().denylistMapping[addr];
    }

    /// The address with the denylister role that can modify the denylist
    ///
    /// @return   The address of the denylister
    function denylister() public view returns (address) {
        return DenylistStorage.get().denylister;
    }

    /// Denylists an address from interacting with the contract
    ///
    /// @dev May only be called by the `denylister` role
    ///
    /// @param addr   The address to be denylisted
    function denylist(address addr) external onlyDenylister {
        _denylist(addr, true);
        emit Denylisted(addr);
    }

    /// Allows a previously-denylisted address to interact with the contract again
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param addr   The address to be allowed
    function unDenylist(address addr) external onlyDenylister {
        _denylist(addr, false);
        emit UnDenylisted(addr);
    }

    /// Sets the address that is allowed to modify the denylist
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newDenylister   The new denylister address
    function updateDenylister(address newDenylister) external onlyOwner {
        address oldDenylister = DenylistStorage.get().denylister;
        _setDenylister(newDenylister);
        emit DenylisterChanged(oldDenylister, newDenylister);
    }

    /// Reverts if the given address is denylisted
    ///
    /// @param addr   The address to check
    function _ensureNotDenylisted(address addr) internal view {
        if (isDenylisted(addr)) {
            revert AccountDenylisted(addr);
        }
    }

    /// Sets the denylist status of an address
    ///
    /// @param addr     The address to set the denylist status for
    /// @param denied   Whether or not the address should be denylisted
    function _denylist(address addr, bool denied) internal {
        DenylistStorage.get().denylistMapping[addr] = denied;
    }

    /// Sets the address that is allowed to modify the denylist
    ///
    /// @param newDenylister   The new denylister address
    function _setDenylister(address newDenylister) internal {
        DenylistStorage.get().denylister = newDenylister;
    }
}

/// Implements the EIP-7201 storage pattern for the `Denylist` module
library DenylistStorage {
    /// @custom:storage-location 7201:circle.gateway.Denylist
    struct Data {
        /// Mapping of addresses to their denylist status
        mapping(address addr => bool denylisted) denylistMapping;
        /// The address that is allowed to manage the denylist
        address denylister;
    }

    /// `keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Denylist"))) - 1)) & ~bytes32(uint256(0xff))`
    bytes32 public constant SLOT = 0x77aee7014301166d8532df7f3d0b1c40d5b12f074d2d69255b43654e04193400;

    /// EIP-7201 getter for the storage slot
    function get() internal pure returns (Data storage $) {
        assembly ("memory-safe") {
            $.slot := SLOT
        }
    }
}
