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

/// @title TransferSpecHashes
///
/// @notice Manages a set of "transfer spec hashes" that have been used, in order to prevent replay. A "transfer spec
/// hash" is the `keccak256` hash of an encoded `TransferSpec` struct. This hash is also used as a cross-chain
/// identifier.
contract TransferSpecHashes {
    /// Thrown when a given transfer spec hash has already been used, to prevent replay
    ///
    /// @param transferSpecHash   The transfer spec hash that was used
    error TransferSpecHashUsed(bytes32 transferSpecHash);

    /// Whether or not a transfer spec hash has been used
    ///
    /// @param transferSpecHash   The transfer spec hash to check
    /// @return                   `true` if the transfer spec hash has been used, `false` otherwise
    function isTransferSpecHashUsed(bytes32 transferSpecHash) public view returns (bool) {
        return TransferSpecHashesStorage.get().usedHashes[transferSpecHash];
    }

    /// Asserts that the given transfer spec hash has not been used, reverting if it has, and marks it as used
    ///
    /// @param transferSpecHash   The transfer spec hash to check and mark
    function _checkAndMarkTransferSpecHash(bytes32 transferSpecHash) internal {
        _ensureTransferSpecHashNotUsed(transferSpecHash);
        _markTransferSpecHashAsUsed(transferSpecHash);
    }

    /// Reverts if the given transfer spec hash has already been used
    ///
    /// @param transferSpecHash   The transfer spec hash to check
    function _ensureTransferSpecHashNotUsed(bytes32 transferSpecHash) internal view {
        if (isTransferSpecHashUsed(transferSpecHash)) {
            revert TransferSpecHashUsed(transferSpecHash);
        }
    }

    /// Marks the given transfer spec hash as used
    ///
    /// @param transferSpecHash   The transfer spec hash to mark as used
    function _markTransferSpecHashAsUsed(bytes32 transferSpecHash) internal {
        TransferSpecHashesStorage.get().usedHashes[transferSpecHash] = true;
    }
}

/// @title TransferSpecHashesStorage
///
/// @notice Implements the EIP-7201 storage pattern for the `TransferSpecHashes` module
library TransferSpecHashesStorage {
    /// @custom:storage-location erc7201:circle.gateway.TransferSpecHashes
    struct Data {
        /// Whether or not a given transfer spec hash has been used
        mapping(bytes32 transferSpecHash => bool used) usedHashes;
    }

    /// `keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.TransferSpecHashes"))) - 1)) & ~bytes32(uint256(0xff))`
    bytes32 public constant SLOT = 0x20b6f2ac2ef95221991caf3be38efadb0bb1d3093c65d3a8c962def8d652ee00;

    /// EIP-7201 getter for the storage slot
    ///
    /// @return $   The storage struct for the `TransferSpecHashes` module
    function get() internal pure returns (Data storage $) {
        assembly ("memory-safe") {
            $.slot := SLOT
        }
    }
}
