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

/// Implements the EIP-7201 storage pattern for the Counterpart module
library CounterpartStorage {
    /// @custom:storage-location 7201:circle.spend.Counterpart
    struct Data {
        /// The address of the counterpart contract on the same chain
        address counterpart;
    }

    /// keccak256(abi.encode(uint256(keccak256("circle.spend.Counterpart")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant SLOT = 0x70565df7873d79606231fdb63c2348309f93e2c30a5f9f935737851220372500;

    function get() internal pure returns (Data storage $) {
        assembly {
            $.slot := SLOT
        }
    }
}

/// @title Counterpart
///
/// Manages pairs of contracts that each need to know the address of the other, namely the `SpendWallet` and
/// `SpendMinter` contracts.
contract Counterpart is Initializable, Ownable2StepUpgradeable {
    /// Emitted when the counterpart is updated
    ///
    /// @param newCounterpart   The new counterpart address
    event CounterpartUpdated(address newCounterpart);

    /// Thrown when the counterpart is expected, but an unauthorized caller is used
    error UnauthorizedCounterpart(address caller);

    /// Restricts the caller to the `counterpart` role, reverting with an error for other callers
    modifier onlyCounterpart() {
        _ensureIsCounterpart(_msgSender());
        _;
    }

    /// Returns the counterpart address
    function _counterpart() internal view returns (address) {
        return CounterpartStorage.get().counterpart;
    }

    /// Ensures that the given address is the counterpart contract
    ///
    /// @param addr   The address to check
    function _ensureIsCounterpart(address addr) internal view {
        if (CounterpartStorage.get().counterpart != addr) {
            revert UnauthorizedCounterpart(addr);
        }
    }

    /// Sets the counterpart during initialization
    ///
    /// @param counterpart   The counterpart address
    function __Counterpart_init(address counterpart) internal onlyInitializing {
        _setCounterpart(counterpart);
    }

    /// Updates the counterpart. Only callable by the owner.
    ///
    /// @param newCounterpart   The new counterpart contract address
    function updateCounterpart(address newCounterpart) external onlyOwner {
        _setCounterpart(newCounterpart);
    }

    /// Sets the counterpart in storage and emits an event
    ///
    /// @param newCounterpart   The new counterpart contract address
    function _setCounterpart(address newCounterpart) private {
        CounterpartStorage.get().counterpart = newCounterpart;
        emit CounterpartUpdated(newCounterpart);
    }
}
