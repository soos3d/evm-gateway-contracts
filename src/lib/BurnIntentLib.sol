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

import {TypedMemView} from "@memview-sol/TypedMemView.sol";
import {Cursor} from "./Cursor.sol";
import {
    BurnIntent,
    BurnIntentSet,
    BURN_INTENT_MAGIC,
    BURN_INTENT_SET_MAGIC,
    BURN_INTENT_MAGIC_OFFSET,
    BURN_INTENT_MAX_BLOCK_HEIGHT_OFFSET,
    BURN_INTENT_MAX_FEE_OFFSET,
    BURN_INTENT_TRANSFER_SPEC_LENGTH_OFFSET,
    BURN_INTENT_TRANSFER_SPEC_OFFSET,
    BURN_INTENT_SET_NUM_AUTHORIZATIONS_OFFSET,
    BURN_INTENT_SET_AUTHORIZATIONS_OFFSET,
    // solhint-disable-next-line no-unused-import
    BURN_INTENT_TYPEHASH,
    BURN_INTENT_SET_TYPEHASH
} from "./BurnIntents.sol";
import {TRANSFER_SPEC_MAGIC} from "./TransferSpec.sol";
import {TransferSpecLib, BYTES4_BYTES, UINT32_BYTES, UINT256_BYTES} from "./TransferSpecLib.sol";

/// @title BurnIntentLib
///
/// @notice Library for encoding, validating, and iterating over `BurnIntent` and `BurnIntentSet` structs
///
/// @dev Provides functions to handle single burn authorizations or sets of them, using `TypedMemView` for efficient
///      memory operations and `Cursor` for unified iteration
library BurnIntentLib {
    using TypedMemView for bytes;
    using TypedMemView for bytes29;

    /// Checks whether the provided `bytes29` reference is a `BurnIntentSet`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `BurnIntent` or `BurnIntentSet`
    /// @return      `true` if the provided `bytes29` reference is a `BurnIntentSet`, `false` otherwise
    function _isSet(bytes29 ref) private pure returns (bool) {
        return ref.index(0, BYTES4_BYTES) == BURN_INTENT_SET_MAGIC;
    }

    // --- Casting -----------------------------------------------------------------------------------------------------

    /// Creates a typed memory view for a `BurnIntent` or `BurnIntentSet`
    ///
    /// @dev Checks for either `BurnIntent` or `BurnIntentSet` magic
    /// @dev Reverts with `InvalidAuthorizationMagic` if neither known magic number is present
    /// @dev Reverts if data length is less than 4
    ///
    /// @param data   The raw bytes to create a view into. Must contain at least 4 bytes.
    /// @return ref   A `TypedMemView` reference to `data`, typed according to the magic number found
    function _asAuthOrSetView(bytes memory data) internal pure returns (bytes29 ref) {
        if (data.length < BYTES4_BYTES) {
            revert TransferSpecLib.AuthorizationDataTooShort(BYTES4_BYTES, data.length);
        }

        bytes29 initialView = data.ref(0);
        bytes4 magic = bytes4(initialView.index(0, BYTES4_BYTES));

        if (magic == BURN_INTENT_MAGIC) {
            ref = initialView.castTo(TransferSpecLib._toMemViewType(BURN_INTENT_MAGIC));
        } else if (magic == BURN_INTENT_SET_MAGIC) {
            ref = initialView.castTo(TransferSpecLib._toMemViewType(BURN_INTENT_SET_MAGIC));
        } else {
            revert TransferSpecLib.InvalidAuthorizationMagic(magic);
        }
    }

    // --- Validation --------------------------------------------------------------------------------------------------

    /// Validates the structural integrity of an encoded `BurnIntent` memory view
    ///
    /// @notice Validation steps:
    ///   1. Minimum header length check
    ///   2. Total length consistency check (using declared `TransferSpec` length)
    ///
    /// @dev Performs structural validation on a `BurnIntent` view, *excluding* recursive validation of the
    ///      nested `TransferSpec` and its magic number. Reverts on failure. Assumes outer magic number check has passed
    ///      (via casting).
    ///
    /// @param authView   The `TypedMemView` reference to the encoded `BurnIntent` to validate
    function _validateBurnIntentOuterStructure(bytes29 authView) private pure {
        // 1. Minimum header length check
        if (authView.len() < BURN_INTENT_TRANSFER_SPEC_OFFSET) {
            revert TransferSpecLib.AuthorizationHeaderTooShort(BURN_INTENT_TRANSFER_SPEC_OFFSET, authView.len());
        }

        // 2. Total length consistency check
        uint32 specLengthDeclaredInAuth = getTransferSpecLength(authView);
        uint256 expectedAuthLength = BURN_INTENT_TRANSFER_SPEC_OFFSET + specLengthDeclaredInAuth;
        if (authView.len() != expectedAuthLength) {
            revert TransferSpecLib.AuthorizationOverallLengthMismatch(expectedAuthLength, authView.len());
        }
    }

    /// Validates the full structural integrity of a `BurnIntent` view, including the nested `TransferSpec`
    ///
    /// @notice Validation includes:
    ///   1. Wrapper structure validation (header length, total length consistency).
    ///   2. Full recursive validation of the nested `TransferSpec` structure.
    ///
    /// @dev Performs structural validation on a `BurnIntent` view. Reverts on failure. Assumes the view has the
    ///      correct `BurnIntent` magic number (e.g., validated by `_asAuthOrSetView`).
    /// @dev Reverts with specific errors (e.g., `AuthorizationHeaderTooShort`, `AuthorizationOverallLengthMismatch`,
    ///      `InvalidTransferSpecMagic`, `TransferSpecHeaderTooShort`, `TransferSpecOverallLengthMismatch`) if the
    ///      structure is invalid
    ///
    /// @param authView   The `TypedMemView` reference to the encoded `BurnIntent` to validate
    function _validateBurnIntent(bytes29 authView) internal pure {
        _validateBurnIntentOuterStructure(authView);

        bytes29 specView = getTransferSpec(authView);
        TransferSpecLib._validateTransferSpecStructure(specView);
    }

    /// Validates the full structural integrity of an encoded `BurnIntentSet` memory view
    ///
    /// @notice Validation includes:
    ///   1. Minimum header length check.
    ///   2. Reading declared authorization count.
    ///   3. Iterating through declared authorizations:
    ///      a. Checking bounds based on previously declared lengths.
    ///      b. Checking the magic number of each authorization.
    ///      c. Performing full recursive validation on each authorization using `_validateBurnIntent`.
    ///   4. Final total length consistency check.
    ///
    /// @dev Performs structural validation on a `BurnIntentSet` view. Reverts on failure. Assumes the view has
    ///      the correct `BurnIntentSet` magic number (e.g., checked via `_as...Set`).
    /// @dev Reverts with errors relating to set/element structure, bounds, magic numbers, and nested validation
    ///      (see `_validateBurnIntent`)
    ///
    /// @param setView   The `TypedMemView` reference to the encoded `BurnIntentSet` to validate
    function _validateBurnIntentSet(bytes29 setView) internal pure {
        // 1. Minimum header length check
        if (setView.len() < BURN_INTENT_SET_AUTHORIZATIONS_OFFSET) {
            revert TransferSpecLib.AuthorizationSetHeaderTooShort(
                BURN_INTENT_SET_AUTHORIZATIONS_OFFSET, setView.len()
            );
        }

        // 2. Read declared count
        uint32 numAuths = getNumAuthorizations(setView);
        uint256 currentOffset = BURN_INTENT_SET_AUTHORIZATIONS_OFFSET;

        // 3. Iterate and validate each element
        for (uint32 i = 0; i < numAuths; i++) {
            uint256 requiredOffsetForHeader = currentOffset + BURN_INTENT_TRANSFER_SPEC_OFFSET;

            // 3a. Check bounds for header read
            if (setView.len() < requiredOffsetForHeader) {
                revert TransferSpecLib.AuthorizationSetElementHeaderTooShort(i, setView.len(), requiredOffsetForHeader);
            }

            // Read spec length to determine current auth total length
            uint32 specLength =
                uint32(setView.indexUint(currentOffset + BURN_INTENT_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
            uint256 currentAuthTotalLength = BURN_INTENT_TRANSFER_SPEC_OFFSET + specLength;
            uint256 requiredOffsetForElement = currentOffset + currentAuthTotalLength;

            // Check bounds for full auth read
            if (setView.len() < requiredOffsetForElement) {
                revert TransferSpecLib.AuthorizationSetElementTooShort(i, setView.len(), requiredOffsetForElement);
            }

            // 3b. Check magic number of the current element slice
            bytes4 elementMagic = bytes4(setView.index(currentOffset + BURN_INTENT_MAGIC_OFFSET, BYTES4_BYTES));
            if (elementMagic != BURN_INTENT_MAGIC) {
                revert TransferSpecLib.AuthorizationSetInvalidElementMagic(i, elementMagic);
            }

            // 3c. Create view and perform full recursive validation on the element
            bytes29 authView = setView.slice(
                currentOffset, currentAuthTotalLength, TransferSpecLib._toMemViewType(BURN_INTENT_MAGIC)
            );
            _validateBurnIntent(authView);

            // Update offset for the next iteration
            currentOffset += currentAuthTotalLength;
        }

        // 4. Final total length consistency check
        if (currentOffset != setView.len()) {
            revert TransferSpecLib.AuthorizationSetOverallLengthMismatch(currentOffset, setView.len());
        }
    }

    /// Validates the structural integrity of either a `BurnIntent` or a `BurnIntentSet`
    ///
    /// @dev First casts the data using `_asAuthOrSetView`, then calls the appropriate specific validation function
    ///      (`_validateBurnIntent` or `_validateBurnIntentSet`). Reverts with specific errors if casting
    ///      or validation fails.
    ///
    /// @param data   The raw bytes representing either an encoded `BurnIntent` or `BurnIntentSet`
    /// @return ref   A `TypedMemView` reference to `data`, typed according to the magic number found
    function _validate(bytes memory data) internal pure returns (bytes29 ref) {
        ref = _asAuthOrSetView(data);

        if (_isSet(ref)) {
            _validateBurnIntentSet(ref);
        } else {
            _validateBurnIntent(ref);
        }
    }

    // --- Iteration ---------------------------------------------------------------------------------------------------

    /// Validates `data` and returns a cursor that can uniformly iterate over any burn authorizations it contains
    ///
    /// @dev For a single `BurnIntent`, the cursor will yield that single element. For a `BurnIntentSet`,
    ///      it iterates through each contained `BurnIntent`. Sets the 'done' flag immediately if the set
    ///      contains zero authorizations.
    /// @dev Reverts with `AuthorizationDataTooShort` or `InvalidAuthorizationMagic` if casting fails
    ///
    /// @param data   The raw bytes representing either an encoded `BurnIntent` or `BurnIntentSet`
    /// @return c     An initialized `Cursor` struct
    function cursor(bytes memory data) internal pure returns (Cursor memory c) {
        bytes29 ref = _validate(data);
        c.setOrAuthView = ref;
        c.index = 0;

        if (!_isSet(ref)) {
            c.offset = 0;
            c.numAuths = 1;
            c.done = false; // There's one element to process
            return c;
        }

        uint32 numAuths = getNumAuthorizations(ref);
        c.offset = BURN_INTENT_SET_AUTHORIZATIONS_OFFSET;
        c.numAuths = numAuths;
        c.done = (numAuths == 0); // If the set is empty, the cursor is immediately done
    }

    /// Gets the `TypedMemView` reference to the next element and advances the cursor
    ///
    /// @dev Updates the cursor's internal state (`offset`, `index`, `done`). Reverts with `CursorOutOfBounds` if called
    ///      when no elements are remaining.
    ///
    /// @param c      The `Cursor` struct
    /// @return ref   The element the cursor was pointing at immediately before this function was called
    function next(Cursor memory c) internal pure returns (bytes29 ref) {
        if (c.done) {
            revert TransferSpecLib.CursorOutOfBounds();
        }

        uint32 currentSpecLength =
            uint32(c.setOrAuthView.indexUint(c.offset + BURN_INTENT_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
        uint256 currentAuthTotalLength = BURN_INTENT_TRANSFER_SPEC_OFFSET + currentSpecLength;

        ref = c.setOrAuthView.slice(
            c.offset, currentAuthTotalLength, TransferSpecLib._toMemViewType(BURN_INTENT_MAGIC)
        );

        c.offset += currentAuthTotalLength;
        c.index++;

        if (c.index >= c.numAuths) {
            c.done = true;
        }
    }

    // --- Field accessors ---------------------------------------------------------------------------------------------

    /// Extract the max block height from an encoded `BurnIntent`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `BurnIntent`
    /// @return      The `maxBlockHeight` field
    function getMaxBlockHeight(bytes29 ref) internal pure returns (uint256) {
        return ref.indexUint(BURN_INTENT_MAX_BLOCK_HEIGHT_OFFSET, UINT256_BYTES);
    }

    /// Extract the max fee from an encoded BurnIntent
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `BurnIntent`
    /// @return      The `maxFee` field
    function getMaxFee(bytes29 ref) internal pure returns (uint256) {
        return ref.indexUint(BURN_INTENT_MAX_FEE_OFFSET, UINT256_BYTES);
    }

    /// Extract the transfer spec length from an encoded `BurnIntent`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `BurnIntent`
    /// @return      The transfer spec length
    function getTransferSpecLength(bytes29 ref) internal pure returns (uint32) {
        return uint32(ref.indexUint(BURN_INTENT_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
    }

    /// Extract the transfer spec from an encoded `BurnIntent`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `BurnIntent`
    /// @return      A `TypedMemView` reference to the `TransferSpec` portion
    function getTransferSpec(bytes29 ref) internal pure returns (bytes29) {
        uint32 specLength = getTransferSpecLength(ref);
        bytes29 specRef = ref.slice(
            BURN_INTENT_TRANSFER_SPEC_OFFSET, specLength, TransferSpecLib._toMemViewType(TRANSFER_SPEC_MAGIC)
        );

        // Validate that the slice contains a valid TransferSpec
        bytes4 specMagic = bytes4(specRef.index(0, BYTES4_BYTES));
        if (specMagic != TRANSFER_SPEC_MAGIC) {
            revert TransferSpecLib.InvalidTransferSpecMagic(specMagic);
        }

        return specRef;
    }

    /// Extract the number of authorizations from an encoded `BurnIntentSet`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `BurnIntentSet`
    /// @return      The number of authorizations in the set
    function getNumAuthorizations(bytes29 ref) internal pure returns (uint32) {
        return uint32(ref.indexUint(BURN_INTENT_SET_NUM_AUTHORIZATIONS_OFFSET, UINT32_BYTES));
    }

    // --- Encoding ----------------------------------------------------------------------------------------------------

    /// Encode a `BurnIntent` struct into bytes
    ///
    /// @param auth   The `BurnIntent` to encode
    /// @return       The encoded bytes
    function encodeBurnIntent(BurnIntent memory auth) internal pure returns (bytes memory) {
        bytes memory specBytes = TransferSpecLib.encodeTransferSpec(auth.spec);

        return abi.encodePacked(
            BURN_INTENT_MAGIC,
            auth.maxBlockHeight,
            auth.maxFee,
            uint32(specBytes.length), // 4 bytes
            specBytes
        );
    }

    /// Encode a `BurnIntentSet` struct into bytes
    ///
    /// @param authSet   The `BurnIntentSet` to encode
    /// @return          The encoded bytes
    function encodeBurnIntentSet(BurnIntentSet memory authSet) internal pure returns (bytes memory) {
        uint256 numAuths = authSet.authorizations.length;

        if (numAuths > type(uint32).max) {
            revert TransferSpecLib.AuthorizationSetTooManyElements(type(uint32).max);
        }

        // Calculate total size of all encoded authorizations
        uint256 totalSize = 0;
        bytes[] memory encodedAuths = new bytes[](numAuths);
        for (uint256 i = 0; i < numAuths; i++) {
            encodedAuths[i] = encodeBurnIntent(authSet.authorizations[i]);
            totalSize += encodedAuths[i].length;
        }

        // Create header with magic and authorization count
        bytes memory header = abi.encodePacked(
            BURN_INTENT_SET_MAGIC,
            uint32(numAuths) // 4 bytes
        );

        // Combine header and all encoded authorizations
        bytes memory result = new bytes(header.length + totalSize);

        // Copy header into result
        for (uint256 i = 0; i < header.length; i++) {
            result[i] = header[i];
        }

        // Copy each encoded authorization into result
        uint256 position = header.length;
        for (uint256 i = 0; i < numAuths; i++) {
            bytes memory auth = encodedAuths[i];
            for (uint256 j = 0; j < auth.length; j++) {
                result[position] = auth[j];
                position++;
            }
        }

        return result;
    }

    // --- Hashing -----------------------------------------------------------------------------------------------------

    /// Computes the EIP-712 typed data hash for a burn authorization or burn authorization set
    ///
    /// @param auth     The encoded burn authorization or burn authorization set
    /// @return         The EIP-712 typed data hash
    function getTypedDataHash(bytes memory auth) internal view returns (bytes32) {
        bytes29 ref = _asAuthOrSetView(auth);
        if (_isSet(ref)) {
            return _getburnAuthorizationSetTypedDataHash(ref);
        } else {
            return _getburnAuthorizationTypedDataHash(ref);
        }
    }

    /// Computes the EIP-712 typed data hash for a single burn authorization
    ///
    /// @param auth         A MemView reference to the encoded burn authorization
    /// @return structHash  The EIP-712 typed data hash of the burn authorization
    function _getburnAuthorizationTypedDataHash(bytes29 auth) private view returns (bytes32 structHash) {
        uint256 maxBlockHeight = getMaxBlockHeight(auth);
        uint256 maxFee = getMaxFee(auth);
        bytes29 transferSpec = getTransferSpec(auth);
        bytes32 transferSpecHash = TransferSpecLib.getTypedDataHash(transferSpec);

        assembly {
            // Get the free memory pointer
            let ptr := mload(0x40)

            // Store BURN_INTENT_TYPEHASH at ptr
            mstore(ptr, BURN_INTENT_TYPEHASH)
            // Store maxBlockHeight at ptr + 32
            mstore(add(ptr, 32), maxBlockHeight)
            // Store maxFee at ptr + 64
            mstore(add(ptr, 64), maxFee)
            // Get and store transferSpec hash at ptr + 96
            mstore(add(ptr, 96), transferSpecHash)

            // Hash the full data (128 bytes total)
            structHash := keccak256(ptr, 128)
        }
    }

    /// Computes the EIP-712 typed data hash for a burn authorization set
    ///
    /// @param setView   A MemView reference to the encoded burn authorization set
    /// @return          The EIP-712 typed data hash of the burn authorization set
    function _getburnAuthorizationSetTypedDataHash(bytes29 setView) private view returns (bytes32) {
        uint32 numAuths = getNumAuthorizations(setView);
        uint256 currentOffset = BURN_INTENT_SET_AUTHORIZATIONS_OFFSET;
        bytes32[] memory authHashes = new bytes32[](numAuths);

        // Iterate through each authorization in the set and compute its hash
        for (uint32 i = 0; i < numAuths; i++) {
            // Read spec length to determine current auth total length
            uint32 specLength =
                uint32(setView.indexUint(currentOffset + BURN_INTENT_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
            uint256 currentAuthTotalLength = BURN_INTENT_TRANSFER_SPEC_OFFSET + specLength;

            bytes29 authView = setView.slice(
                currentOffset, currentAuthTotalLength, TransferSpecLib._toMemViewType(BURN_INTENT_MAGIC)
            );
            authHashes[i] = _getburnAuthorizationTypedDataHash(authView);

            // Update offset for the next iteration
            currentOffset += currentAuthTotalLength;
        }

        return keccak256(abi.encodePacked(BURN_INTENT_SET_TYPEHASH, keccak256(abi.encodePacked(authHashes))));
    }
}
