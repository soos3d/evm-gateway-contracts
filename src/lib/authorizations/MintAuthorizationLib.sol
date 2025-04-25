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

import {TypedMemView} from "@memview-sol/TypedMemView.sol";
import {AuthorizationCursor} from "./AuthorizationCursor.sol";
import {
    MintAuthorization,
    MintAuthorizationSet,
    MINT_AUTHORIZATION_MAGIC,
    MINT_AUTHORIZATION_SET_MAGIC,
    MINT_AUTHORIZATION_MAGIC_OFFSET,
    MINT_AUTHORIZATION_MAX_BLOCK_HEIGHT_OFFSET,
    MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET,
    MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET,
    MINT_AUTHORIZATION_SET_NUM_AUTHORIZATIONS_OFFSET,
    MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET
} from "./MintAuthorizations.sol";
import {TRANSFER_SPEC_MAGIC} from "./TransferSpec.sol";
import {TransferSpecLib, BYTES4_BYTES, UINT32_BYTES, UINT256_BYTES} from "./TransferSpecLib.sol";

/// @title MintAuthorizationLib
///
/// @notice Library for encoding, validating, and iterating over `MintAuthorization` and `MintAuthorizationSet` structs
///
/// @dev Provides functions to handle single mint authorizations or sets of them, using `TypedMemView` for efficient
///      memory operations and `AuthorizationCursor` for unified iteration
library MintAuthorizationLib {
    using TypedMemView for bytes;
    using TypedMemView for bytes29;

    /// Checks whether the provided `bytes29` reference is a `MintAuthorizationSet`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `MintAuthorization` or `MintAuthorizationSet`
    /// @return      `true` if the provided `bytes29` reference is a `MintAuthorizationSet`, `false` otherwise
    function _isSet(bytes29 ref) private pure returns (bool) {
        return ref.index(0, BYTES4_BYTES) == MINT_AUTHORIZATION_SET_MAGIC;
    }

    // --- Casting -----------------------------------------------------------------------------------------------------

    /// Creates a typed memory view for a `MintAuthorization` or `MintAuthorizationSet`
    ///
    /// @dev Checks for either `MintAuthorization` or `MintAuthorizationSet` magic
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

        if (magic == MINT_AUTHORIZATION_MAGIC) {
            ref = initialView.castTo(TransferSpecLib._toMemViewType(MINT_AUTHORIZATION_MAGIC));
        } else if (magic == MINT_AUTHORIZATION_SET_MAGIC) {
            ref = initialView.castTo(TransferSpecLib._toMemViewType(MINT_AUTHORIZATION_SET_MAGIC));
        } else {
            revert TransferSpecLib.InvalidAuthorizationMagic(magic);
        }
    }

    // --- Validation --------------------------------------------------------------------------------------------------

    /// Validates the structural integrity of an encoded `MintAuthorization` memory view
    ///
    /// @notice Validation steps:
    ///   1. Minimum header length check
    ///   2. Total length consistency check (using declared `TransferSpec` length)
    ///
    /// @dev Performs structural validation on a `MintAuthorization` view, *excluding* recursive validation of the
    ///      nested `TransferSpec` and its magic number. Reverts on failure. Assumes outer magic number check has passed
    ///      (via casting).
    ///
    /// @param authView   The `TypedMemView` reference to the encoded `MintAuthorization` to validate
    function _validateMintAuthorizationOuterStructure(bytes29 authView) private pure {
        // 1. Minimum header length check
        if (authView.len() < MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET) {
            revert TransferSpecLib.AuthorizationHeaderTooShort(MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET, authView.len());
        }

        // 2. Total length consistency check
        uint32 specLengthDeclaredInAuth = getTransferSpecLength(authView);
        uint256 expectedAuthLength = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + specLengthDeclaredInAuth;
        if (authView.len() != expectedAuthLength) {
            revert TransferSpecLib.AuthorizationOverallLengthMismatch(expectedAuthLength, authView.len());
        }
    }

    /// Validates the full structural integrity of a `MintAuthorization` view, including the nested `TransferSpec`
    ///
    /// @notice Validation includes:
    ///   1. Wrapper structure validation (header length, total length consistency).
    ///   2. Full recursive validation of the nested `TransferSpec` structure.
    ///
    /// @dev Performs structural validation on a `MintAuthorization` view. Reverts on failure. Assumes the view has the
    ///      correct `MintAuthorization` magic number (e.g., validated by `_asAuthOrSetView`).
    /// @dev Reverts with specific errors (e.g., `AuthorizationHeaderTooShort`, `AuthorizationOverallLengthMismatch`,
    ///      `InvalidTransferSpecMagic`, `TransferSpecHeaderTooShort`, `TransferSpecOverallLengthMismatch`) if the
    ///      structure is invalid
    ///
    /// @param authView   The `TypedMemView` reference to the encoded `MintAuthorization` to validate
    function _validateMintAuthorization(bytes29 authView) internal pure {
        _validateMintAuthorizationOuterStructure(authView);

        bytes29 specView = getTransferSpec(authView);
        TransferSpecLib._validateTransferSpecStructure(specView);
    }

    /// Validates the full structural integrity of an encoded `MintAuthorizationSet` memory view
    ///
    /// @notice Validation includes:
    ///   1. Minimum header length check.
    ///   2. Reading declared authorization count.
    ///   3. Iterating through declared authorizations:
    ///      a. Checking bounds based on previously declared lengths.
    ///      b. Checking the magic number of each authorization.
    ///      c. Performing full recursive validation on each authorization using `_validateMintAuthorization`.
    ///   4. Final total length consistency check.
    ///
    /// @dev Performs structural validation on a `MintAuthorizationSet` view. Reverts on failure. Assumes the view has
    ///      the correct `MintAuthorizationSet` magic number (e.g., checked via `_as...Set`).
    /// @dev Reverts with errors relating to set/element structure, bounds, magic numbers, and nested validation
    ///      (see `_validateMintAuthorization`)
    ///
    /// @param setView   The `TypedMemView` reference to the encoded `MintAuthorizationSet` to validate
    function _validateMintAuthorizationSet(bytes29 setView) internal pure {
        // 1. Minimum header length check
        if (setView.len() < MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET) {
            revert TransferSpecLib.AuthorizationSetHeaderTooShort(
                MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET, setView.len()
            );
        }

        // 2. Read declared count
        uint32 numAuths = getNumAuthorizations(setView);
        uint256 currentOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;

        // 3. Iterate and validate each element
        for (uint32 i = 0; i < numAuths; i++) {
            uint256 requiredOffsetForHeader = currentOffset + MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET;

            // 3a. Check bounds for header read
            if (setView.len() < requiredOffsetForHeader) {
                revert TransferSpecLib.AuthorizationSetElementHeaderTooShort(i, setView.len(), requiredOffsetForHeader);
            }

            // Read spec length to determine current auth total length
            uint32 specLength =
                uint32(setView.indexUint(currentOffset + MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
            uint256 currentAuthTotalLength = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + specLength;
            uint256 requiredOffsetForElement = currentOffset + currentAuthTotalLength;

            // Check bounds for full auth read
            if (setView.len() < requiredOffsetForElement) {
                revert TransferSpecLib.AuthorizationSetElementTooShort(i, setView.len(), requiredOffsetForElement);
            }

            // 3b. Check magic number of the current element slice
            bytes4 elementMagic = bytes4(setView.index(currentOffset + MINT_AUTHORIZATION_MAGIC_OFFSET, BYTES4_BYTES));
            if (elementMagic != MINT_AUTHORIZATION_MAGIC) {
                revert TransferSpecLib.AuthorizationSetInvalidElementMagic(i, elementMagic);
            }

            // 3c. Create view and perform full recursive validation on the element
            bytes29 authView = setView.slice(
                currentOffset, currentAuthTotalLength, TransferSpecLib._toMemViewType(MINT_AUTHORIZATION_MAGIC)
            );
            _validateMintAuthorization(authView);

            // Update offset for the next iteration
            currentOffset += currentAuthTotalLength;
        }

        // 4. Final total length consistency check
        if (currentOffset != setView.len()) {
            revert TransferSpecLib.AuthorizationSetOverallLengthMismatch(currentOffset, setView.len());
        }
    }

    /// Validates the structural integrity of either a `MintAuthorization` or a `MintAuthorizationSet`
    ///
    /// @dev First casts the data using `_asAuthOrSetView`, then calls the appropriate specific validation function
    ///      (`_validateMintAuthorization` or `_validateMintAuthorizationSet`). Reverts with specific errors if casting
    ///      or validation fails.
    ///
    /// @param data   The raw bytes representing either an encoded `MintAuthorization` or `MintAuthorizationSet`
    /// @return ref   A `TypedMemView` reference to `data`, typed according to the magic number found
    function _validate(bytes memory data) internal pure returns (bytes29 ref) {
        ref = _asAuthOrSetView(data);

        if (_isSet(ref)) {
            _validateMintAuthorizationSet(ref);
        } else {
            _validateMintAuthorization(ref);
        }
    }

    // --- Iteration ---------------------------------------------------------------------------------------------------

    /// Validates `data` and returns a cursor that can uniformly iterate over any mint authorizations it contains
    ///
    /// @dev For a single `MintAuthorization`, the cursor will yield that single element. For a `MintAuthorizationSet`,
    ///      it iterates through each contained `MintAuthorization`. Sets the 'done' flag immediately if the set
    ///      contains zero authorizations.
    /// @dev Reverts with `AuthorizationDataTooShort` or `InvalidAuthorizationMagic` if casting fails
    ///
    /// @param data   The raw bytes representing either an encoded `MintAuthorization` or `MintAuthorizationSet`
    /// @return c     An initialized `AuthorizationCursor` struct
    function cursor(bytes memory data) internal pure returns (AuthorizationCursor memory c) {
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
        c.offset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;
        c.numAuths = numAuths;
        c.done = (numAuths == 0); // If the set is empty, the cursor is immediately done
    }

    /// Gets the `TypedMemView` reference to the next element and advances the cursor
    ///
    /// @dev Updates the cursor's internal state (`offset`, `index`, `done`). Reverts with `CursorOutOfBounds` if called
    ///      when no elements are remaining.
    ///
    /// @param c      The `AuthorizationCursor` struct
    /// @return ref   The current element the cursor is pointing at
    function next(AuthorizationCursor memory c) internal pure returns (bytes29 ref) {
        if (c.done) {
            revert TransferSpecLib.CursorOutOfBounds();
        }

        uint32 currentSpecLength =
            uint32(c.setOrAuthView.indexUint(c.offset + MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
        uint256 currentAuthTotalLength = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + currentSpecLength;

        ref = c.setOrAuthView.slice(
            c.offset, currentAuthTotalLength, TransferSpecLib._toMemViewType(MINT_AUTHORIZATION_MAGIC)
        );

        c.offset += currentAuthTotalLength;
        c.index++;

        if (c.index >= c.numAuths) {
            c.done = true;
        }

        return ref;
    }

    // --- Field accessors ---------------------------------------------------------------------------------------------

    /// Extract the max block height from an encoded `MintAuthorization`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `MintAuthorization`
    /// @return      The `maxBlockHeight` field
    function getMaxBlockHeight(bytes29 ref) internal pure returns (uint256) {
        return ref.indexUint(MINT_AUTHORIZATION_MAX_BLOCK_HEIGHT_OFFSET, UINT256_BYTES);
    }

    /// Extract the transfer spec length from an encoded `MintAuthorization`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `MintAuthorization`
    /// @return      The transfer spec length
    function getTransferSpecLength(bytes29 ref) internal pure returns (uint32) {
        return uint32(ref.indexUint(MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
    }

    /// Extract the transfer spec from an encoded `MintAuthorization`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `MintAuthorization`
    /// @return      A `TypedMemView` reference to the `TransferSpec` portion
    function getTransferSpec(bytes29 ref) internal pure returns (bytes29) {
        uint32 specLength = getTransferSpecLength(ref);
        bytes29 specRef = ref.slice(
            MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET, specLength, TransferSpecLib._toMemViewType(TRANSFER_SPEC_MAGIC)
        );

        // Validate that the slice contains a valid TransferSpec
        bytes4 specMagic = bytes4(specRef.index(0, BYTES4_BYTES));
        if (specMagic != TRANSFER_SPEC_MAGIC) {
            revert TransferSpecLib.InvalidTransferSpecMagic(specMagic);
        }

        return specRef;
    }

    /// Extract the number of authorizations from an encoded `MintAuthorizationSet`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `MintAuthorizationSet`
    /// @return      The number of authorizations in the set
    function getNumAuthorizations(bytes29 ref) internal pure returns (uint32) {
        return uint32(ref.indexUint(MINT_AUTHORIZATION_SET_NUM_AUTHORIZATIONS_OFFSET, UINT32_BYTES));
    }

    // --- Encoding ----------------------------------------------------------------------------------------------------

    /// Encode a `MintAuthorization` struct into bytes
    ///
    /// @param auth   The `MintAuthorization` to encode
    /// @return       The encoded bytes
    function encodeMintAuthorization(MintAuthorization memory auth) internal pure returns (bytes memory) {
        bytes memory specBytes = TransferSpecLib.encodeTransferSpec(auth.spec);

        return abi.encodePacked(
            MINT_AUTHORIZATION_MAGIC,
            auth.maxBlockHeight,
            uint32(specBytes.length), // 4 bytes
            specBytes
        );
    }

    /// Encode a `MintAuthorizationSet` struct into bytes
    ///
    /// @param authSet   The `MintAuthorizationSet` to encode
    /// @return          The encoded bytes
    function encodeMintAuthorizationSet(MintAuthorizationSet memory authSet) internal pure returns (bytes memory) {
        uint256 numAuths = authSet.authorizations.length;

        if (numAuths > type(uint32).max) {
            revert TransferSpecLib.AuthorizationSetTooManyElements(type(uint32).max);
        }

        // Calculate total size of all encoded authorizations
        uint256 totalSize = 0;
        bytes[] memory encodedAuths = new bytes[](numAuths);
        for (uint256 i = 0; i < numAuths; i++) {
            encodedAuths[i] = encodeMintAuthorization(authSet.authorizations[i]);
            totalSize += encodedAuths[i].length;
        }

        // Create header with magic and authorization count
        bytes memory header = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
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
}
