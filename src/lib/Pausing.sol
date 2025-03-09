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
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/// @title Pausing
///
/// Defines a `pauser` role that may pause and unpause the contract
contract Pausing is Initializable, Ownable2StepUpgradeable, PausableUpgradeable {
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // EIP-7201 Storage

    /// @custom:storage-location 7201:circle.spend.Pausing
    struct PausingStorage {
        /// The address that is allowed to pause and unpause the contract
        address pauser;
    }

    /// keccak256(abi.encode(uint256(keccak256("circle.spend.Pausing")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant PAUSING_STORAGE_SLOT = 0xf07f35b87760c15d28aad27fd9f57f1a9aaded4bd55a711c0b6e1bc98d257100;

    function _getPausingStorage() private pure returns (PausingStorage storage $) {
        assembly {
            $.slot := PAUSING_STORAGE_SLOT
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /// Thrown when the pauser is expected, but an unauthorized caller is used
    ///
    /// @param caller   The unauthorized caller
    error UnauthorizedPauser(address caller);

    /// Restricts the caller to the `pauser` role, reverting with an error for other callers
    modifier onlyPauser() {
        if (_getPausingStorage().pauser != _msgSender()) {
            revert UnauthorizedPauser(_msgSender());
        }
        _;
    }

    /// Initializes the underlying `Pausable` contract
    function __Pausing_init() internal onlyInitializing {
        __Pausable_init();
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
    function updatePauser(address newPauser) external onlyOwner {}
}
