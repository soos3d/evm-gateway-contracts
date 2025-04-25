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

/// @title SpendHashes
///
/// Manages a set of "spend hashes" that have been used, in order to prevent replay. A "spend hash" is the `keccak256`
/// hash of a `SpendSpec` struct, which is common to both `BurnAuthorization` and `SpendAuthorization`.
contract SpendHashes {
    /// Thrown when a given spend hash has already been used, to prevent replay
    ///
    /// @param spendHash   The spend hash that was used
    error SpendHashUsed(bytes32 spendHash);

    /// Asserts that the given spend hash has not been used, reverting if it has, and marks it as used
    ///
    /// @param spendHash    The spend hash to check and mark
    function _checkAndMarkSpendHash(bytes32 spendHash) internal {
        _ensureSpendHashNotUsed(spendHash);
        _markSpendHashAsUsed(spendHash);
    }

    /// Reverts if the given spend hash has already been used
    ///
    /// @param spendHash   The spend hash to check
    function _ensureSpendHashNotUsed(bytes32 spendHash) internal view {
        if (SpendHashesStorage.get().usedSpendHashes[spendHash]) {
            revert SpendHashUsed(spendHash);
        }
    }

    /// Marks the given spend hash as used
    ///
    /// @param spendHash   The spend hash to mark as used
    function _markSpendHashAsUsed(bytes32 spendHash) internal {
        SpendHashesStorage.get().usedSpendHashes[spendHash] = true;
    }
}

/// Implements the EIP-7201 storage pattern for the SpendHashes module
library SpendHashesStorage {
    /// @custom:storage-location 7201:circle.spend.SpendHashes
    struct Data {
        /// Whether or not a given spend hash has been used
        mapping(bytes32 spendHash => bool used) usedSpendHashes;
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
