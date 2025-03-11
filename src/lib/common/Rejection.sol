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
    /// Emitted when an address is added to the rejection list
    ///
    /// @param addr   The address that is now rejected from interacting with the contract
    event AddressRejected(address addr);

    /// Emitted when an address is removed from the rejection list
    ///
    /// @param addr   The address that is allowed to interact with the contract again
    event AddressAllowed(address addr);

    /// Thrown when an address is rejected from interacting with the contract
    ///
    /// @param addr   The rejected address
    error RejectedAddress(address addr);

    /// Whether or not a given address is rejected from interacting with the contract
    ///
    /// @param addr   The address to check
    function isRejected(address addr) public view returns (bool) {
        return RejectionStorage.get().rejectedAddresses[addr];
    }

    /// Sets the rejection status of an address
    ///
    /// @param addr       The address to set the rejection status for
    /// @param rejected   Whether or not the address should be rejected
    function _setRejected(address addr, bool rejected) internal {
        RejectionStorage.get().rejectedAddresses[addr] = rejected;
    }

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
        if (isRejected(addr)) {
            revert RejectedAddress(addr);
        }
    }

    /// Rejects an address from interacting with the contract
    ///
    /// @param addr   The address to be rejected
    function rejectAddress(address addr) external onlyOwner {
        _setRejected(addr, true);
        emit AddressRejected(addr);
    }

    /// Allows a previously-rejected address to interact with the contract again
    ///
    /// @param addr   The address to be allowed
    function allowAddress(address addr) external onlyOwner {
        _setRejected(addr, false);
        emit AddressAllowed(addr);
    }
}

/// Implements the EIP-7201 storage pattern for the Rejection module
library RejectionStorage {
    /// @custom:storage-location 7201:circle.spend.Rejection
    struct Data {
        /// Whether or not a given address should be rejected from interacting with the contract
        mapping(address addr => bool rejected) rejectedAddresses;
    }

    /// keccak256(abi.encode(uint256(keccak256("circle.spend.Rejection")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant SLOT = 0x1f77a9ebc6439acf5242590b1d7a06bf8312dd6281b5df39cd80eeafa76b8900;

    /// EIP-7201 getter for the storage slot
    function get() internal pure returns (Data storage $) {
        assembly {
            $.slot := SLOT
        }
    }
}
