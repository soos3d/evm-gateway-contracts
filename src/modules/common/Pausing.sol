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
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/// @title Pausing
///
/// @notice Defines a `pauser` role that may pause and unpause the contract
contract Pausing is Initializable, Ownable2StepUpgradeable, PausableUpgradeable {
    /// Emitted when the pauser address is updated
    ///
    /// @param newPauser   The new pauser address
    event PauserUpdated(address newPauser);

    /// Thrown when the pauser is expected, but an unauthorized caller is used
    ///
    /// @param caller   The unauthorized caller
    error UnauthorizedPauser(address caller);

    /// Initializes the underlying `Pausable` contract and the `pauser` role
    ///
    /// @param pauser_   The initial pauser address
    function __Pausing_init(address pauser_) internal onlyInitializing {
        __Pausable_init();
        _setPauser(pauser_);
    }

    /// Restricts the caller to the `pauser` role, reverting with an error for other callers
    modifier onlyPauser() {
        if (pauser() != msg.sender) {
            revert UnauthorizedPauser(msg.sender);
        }
        _;
    }

    /// The address with the `pauser` role that can pause and unpause the contract
    ///
    /// @return   The address of the pauser
    function pauser() public view returns (address) {
        return PausingStorage.get().pauser;
    }

    /// Pauses the contract
    ///
    /// @dev May only be called by the `pauser` role
    function pause() external onlyPauser {
        _pause();
    }

    /// Unpauses the contract
    ///
    /// @dev May only be called by the `pauser` role
    function unpause() external onlyPauser {
        _unpause();
    }

    /// Sets the address that may call `pause` and `unpause`
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newPauser   The new pauser address
    function updatePauser(address newPauser) public onlyOwner {
        _setPauser(newPauser);
    }

    /// Sets the pauser in storage and emits an event
    ///
    /// @param newPauser   The new pauser address
    function _setPauser(address newPauser) private {
        PausingStorage.get().pauser = newPauser;
        emit PauserUpdated(newPauser);
    }
}

/// @title PausingStorage
///
/// @notice Implements the EIP-7201 storage pattern for the `Pausing` module
library PausingStorage {
    /// @custom:storage-location erc7201:circle.gateway.Pausing
    struct Data {
        /// The address that is allowed to pause and unpause the contract
        address pauser;
    }

    /// `keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Pausing"))) - 1)) & ~bytes32(uint256(0xff))`
    bytes32 public constant SLOT = 0x7e0f0117f6f510f2a35b1c8185f303b28ba884334cd776f9d98e2abef24e2f00;

    /// EIP-7201 getter for the storage slot
    ///
    /// @return $   The storage struct for the `Pausing` module
    function get() internal pure returns (Data storage $) {
        assembly ("memory-safe") {
            $.slot := SLOT
        }
    }
}
