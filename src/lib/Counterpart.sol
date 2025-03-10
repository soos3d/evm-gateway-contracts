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

/// @title Counterpart
///
/// Manages pairs of contracts that each need to know the address of the other, namely the `SpendWallet` and
/// `SpendMinter` contracts.
contract Counterpart is Ownable2StepUpgradeable {
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // EIP-7201 Storage

    /// @custom:storage-location 7201:circle.spend.Counterpart
    struct CounterpartStorage {
        /// The address of the counterpart contract on the same chain
        address counterpart;
    }

    /// keccak256(abi.encode(uint256(keccak256("circle.spend.Counterpart")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant COUNTERPART_STORAGE_SLOT =
        0x70565df7873d79606231fdb63c2348309f93e2c30a5f9f935737851220372500;

    function _getCounterpartStorage() private pure returns (CounterpartStorage storage $) {
        assembly {
            $.slot := COUNTERPART_STORAGE_SLOT
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /// Thrown when the counterpart is expected, but an unauthorized caller is used
    error UnauthorizedCounterpart(address caller);

    /// Restricts the caller to the `counterpart` role, reverting with an error for other callers
    modifier onlyCounterpart() {
        _ensureIsCounterpart(_msgSender());
        _;
    }

    /// Ensures that the given address is the counterpart contract
    ///
    /// @param addr   The address to check
    function _ensureIsCounterpart(address addr) internal view {
        if (_getCounterpartStorage().counterpart != addr) {
            revert UnauthorizedCounterpart(addr);
        }
    }

    /// Sets the counterpart contract address
    ///
    /// @param newCounterpart   The new counterpart contract address
    function updateCounterpart(address newCounterpart) external onlyOwner {
        _getCounterpartStorage().counterpart = newCounterpart;
    }
}
