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

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

/// @title Rejection
///
/// Rejection of services for specific addresses
contract Rejection is Ownable2StepUpgradeable {
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // EIP-7201 Storage

    /// @custom:storage-location 7201:circle.spend.Rejection
    struct RejectionStorage {
        /// Whether or not a given address should be rejected from interacting with the contract
        mapping(address addr => bool rejected) rejectedAddresses;
    }

    /// keccak256(abi.encode(uint256(keccak256("circle.spend.Rejection")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REJECTION_STORAGE_SLOT = 0x1f77a9ebc6439acf5242590b1d7a06bf8312dd6281b5df39cd80eeafa76b8900;

    function _getRejectionStorage() private pure returns (RejectionStorage storage $) {
        assembly {
            $.slot := REJECTION_STORAGE_SLOT
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /// Thrown when an address is rejected from interacting with the contract
    ///
    /// @param addr   The rejected address
    error RejectedAddress(address addr);

    /// Restricts access to a function to addresses that are not rejected
    ///
    /// @param addr   The address to check
    modifier notRejected(address addr) {
        _ensureNotRejected(addr);
        _;
    }

    /// Reverts if the given address is rejected
    ///
    /// @param addr   The address to check
    function _ensureNotRejected(address addr) internal view {
        if (_getRejectionStorage().rejectedAddresses[addr]) {
            revert RejectedAddress(addr);
        }
    }

    /// Whether or not a given address is rejected from interacting with the contract
    ///
    /// @param addr   The address to check
    function isRejected(address addr) external view returns (bool) {
        return _getRejectionStorage().rejectedAddresses[addr];
    }

    /// Rejects an address from interacting with the contract
    ///
    /// @param addr   The address to be rejected
    function rejectAddress(address addr) external onlyOwner {
        _getRejectionStorage().rejectedAddresses[addr] = true;
    }

    /// Allows a previously-rejected address to interact with the contract again
    ///
    /// @param addr   The address to be allowed
    function allowAddress(address addr) external onlyOwner {
        _getRejectionStorage().rejectedAddresses[addr] = false;
    }
}
