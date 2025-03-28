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

/// @title SpendHashes
///
/// Manages a set of "spend hashes" that have been used, in order to prevent replay. A "spend hash" is the `keccak256`
/// hash of a `SpendSpec` struct, which is common to both `BurnAuthorization` and `SpendAuthorization`.
contract SpendHashes {
    /// Thrown when a given spend hash has already been used, to prevent replay
    ///
    /// @param spendHash   The spend hash that was used
    error SpendHashUsed(bytes32 spendHash);

    /// Marks the given spend hash as used
    ///
    /// @param spendHash   The spend hash to mark as used
    function _markSpendHashAsUsed(bytes32 spendHash) internal {
        SpendHashesStorage.get().usedSpendHashes[spendHash] = 1;
    }

    /// Reverts if the given spend hash has already been used
    ///
    /// @param spendHash   The spend hash to check
    function _ensureSpendHashNotUsed(bytes32 spendHash) internal view {
        if (SpendHashesStorage.get().usedSpendHashes[spendHash] != 0) {
            revert SpendHashUsed(spendHash);
        }
    }
}

/// Implements the EIP-7201 storage pattern for the SpendHashes module
library SpendHashesStorage {
    /// @custom:storage-location 7201:circle.spend.SpendHashes
    struct Data {
        /// Whether or not a given spend hash has been used (0 if unused, 1 if used)
        mapping(bytes32 spendHash => uint256 used) usedSpendHashes;
    }

    /// keccak256(abi.encode(uint256(keccak256("circle.spend.SpendHashes")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant SLOT = 0xd40ed81e80275907a36da4125aa85b969c2d499c973b74ef2c642080726ad800;

    /// EIP-7201 getter for the storage slot
    function get() internal pure returns (Data storage $) {
        assembly {
            $.slot := SLOT
        }
    }
}
