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
    Attestation,
    AttestationSet,
    ATTESTATION_MAGIC,
    ATTESTATION_SET_MAGIC,
    ATTESTATION_MAGIC_OFFSET,
    ATTESTATION_MAX_BLOCK_HEIGHT_OFFSET,
    ATTESTATION_TRANSFER_SPEC_LENGTH_OFFSET,
    ATTESTATION_TRANSFER_SPEC_OFFSET,
    ATTESTATION_SET_NUM_ATTESTATIONS_OFFSET,
    ATTESTATION_SET_ATTESTATIONS_OFFSET
} from "./Attestations.sol";
import {TRANSFER_SPEC_MAGIC} from "./TransferSpec.sol";
import {TransferSpecLib, BYTES4_BYTES, UINT32_BYTES, UINT256_BYTES} from "./TransferSpecLib.sol";

/// @title AttestationLib
///
/// @notice Library for encoding, validating, and iterating over `Attestation` and `AttestationSet` structs
///
/// @dev Provides functions to handle single attestations or sets of them, using `TypedMemView` for efficient
///      memory operations and `Cursor` for unified iteration
library AttestationLib {
    using TypedMemView for bytes;
    using TypedMemView for bytes29;

    /// Checks whether the provided `bytes29` reference is a `AttestationSet`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `Attestation` or `AttestationSet`
    /// @return      `true` if the provided `bytes29` reference is a `AttestationSet`, `false` otherwise
    function _isSet(bytes29 ref) private pure returns (bool) {
        return ref.index(0, BYTES4_BYTES) == ATTESTATION_SET_MAGIC;
    }

    // --- Casting -----------------------------------------------------------------------------------------------------

    /// Creates a typed memory view for a `Attestation` or `AttestationSet`
    ///
    /// @dev Checks for either `Attestation` or `AttestationSet` magic
    /// @dev Reverts with `InvalidTransferPayloadMagic` if neither known magic number is present
    /// @dev Reverts if data length is less than 4
    ///
    /// @param data   The raw bytes to create a view into. Must contain at least 4 bytes.
    /// @return ref   A `TypedMemView` reference to `data`, typed according to the magic number found
    function _asAttestationOrSetView(bytes memory data) internal pure returns (bytes29 ref) {
        if (data.length < BYTES4_BYTES) {
            revert TransferSpecLib.TransferPayloadDataTooShort(BYTES4_BYTES, data.length);
        }

        bytes29 initialView = data.ref(0);
        bytes4 magic = bytes4(initialView.index(0, BYTES4_BYTES));

        if (magic == ATTESTATION_MAGIC) {
            ref = initialView.castTo(TransferSpecLib._toMemViewType(ATTESTATION_MAGIC));
        } else if (magic == ATTESTATION_SET_MAGIC) {
            ref = initialView.castTo(TransferSpecLib._toMemViewType(ATTESTATION_SET_MAGIC));
        } else {
            revert TransferSpecLib.InvalidTransferPayloadMagic(magic);
        }
    }

    // --- Validation --------------------------------------------------------------------------------------------------

    /// Validates the structural integrity of an encoded `Attestation` memory view
    ///
    /// @notice Validation steps:
    ///   1. Minimum header length check
    ///   2. Total length consistency check (using declared `TransferSpec` length)
    ///
    /// @dev Performs structural validation on a `Attestation` view, *excluding* recursive validation of the
    ///      nested `TransferSpec` and its magic number. Reverts on failure. Assumes outer magic number check has passed
    ///      (via casting).
    ///
    /// @param attestationView   The `TypedMemView` reference to the encoded `Attestation` to validate
    function _validateAttestationOuterStructure(bytes29 attestationView) private pure {
        // 1. Minimum header length check
        if (attestationView.len() < ATTESTATION_TRANSFER_SPEC_OFFSET) {
            revert TransferSpecLib.TransferPayloadHeaderTooShort(
                ATTESTATION_TRANSFER_SPEC_OFFSET, attestationView.len()
            );
        }

        // 2. Total length consistency check
        uint32 specLengthDeclaredInAttestation = getTransferSpecLength(attestationView);
        uint256 expectedAttestationLength = ATTESTATION_TRANSFER_SPEC_OFFSET + specLengthDeclaredInAttestation;
        if (attestationView.len() != expectedAttestationLength) {
            revert TransferSpecLib.TransferPayloadOverallLengthMismatch(
                expectedAttestationLength, attestationView.len()
            );
        }
    }

    /// Validates the full structural integrity of a `Attestation` view, including the nested `TransferSpec`
    ///
    /// @notice Validation includes:
    ///   1. Wrapper structure validation (header length, total length consistency).
    ///   2. Full recursive validation of the nested `TransferSpec` structure.
    ///
    /// @dev Performs structural validation on a `Attestation` view. Reverts on failure. Assumes the view has the
    ///      correct `Attestation` magic number (e.g., validated by `_asAttestationOrSetView`).
    /// @dev Reverts with specific errors (e.g., `TransferPayloadHeaderTooShort`, `TransferPayloadOverallLengthMismatch`,
    ///      `InvalidTransferSpecMagic`, `TransferSpecHeaderTooShort`, `TransferSpecOverallLengthMismatch`) if the
    ///      structure is invalid
    ///
    /// @param attestationView   The `TypedMemView` reference to the encoded `Attestation` to validate
    function _validateAttestation(bytes29 attestationView) internal pure {
        _validateAttestationOuterStructure(attestationView);

        bytes29 specView = getTransferSpec(attestationView);
        TransferSpecLib._validateTransferSpecStructure(specView);
    }

    /// Validates the full structural integrity of an encoded `AttestationSet` memory view
    ///
    /// @notice Validation includes:
    ///   1. Minimum header length check.
    ///   2. Reading declared attestation count.
    ///   3. Iterating through declared attestations:
    ///      a. Checking bounds based on previously declared lengths.
    ///      b. Checking the magic number of each attestation.
    ///      c. Performing full recursive validation on each attestation using `_validateAttestation`.
    ///   4. Final total length consistency check.
    ///
    /// @dev Performs structural validation on a `AttestationSet` view. Reverts on failure. Assumes the view has
    ///      the correct `AttestationSet` magic number (e.g., checked via `_as...Set`).
    /// @dev Reverts with errors relating to set/element structure, bounds, magic numbers, and nested validation
    ///      (see `_validateAttestation`)
    ///
    /// @param setView   The `TypedMemView` reference to the encoded `AttestationSet` to validate
    function _validateAttestationSet(bytes29 setView) internal pure {
        // 1. Minimum header length check
        if (setView.len() < ATTESTATION_SET_ATTESTATIONS_OFFSET) {
            revert TransferSpecLib.TransferPayloadSetHeaderTooShort(ATTESTATION_SET_ATTESTATIONS_OFFSET, setView.len());
        }

        // 2. Read declared count
        uint32 numAttestations = getNumAttestations(setView);
        uint256 currentOffset = ATTESTATION_SET_ATTESTATIONS_OFFSET;

        // 3. Iterate and validate each element
        for (uint32 i = 0; i < numAttestations; i++) {
            uint256 requiredOffsetForHeader = currentOffset + ATTESTATION_TRANSFER_SPEC_OFFSET;

            // 3a. Check bounds for header read
            if (setView.len() < requiredOffsetForHeader) {
                revert TransferSpecLib.TransferPayloadSetElementHeaderTooShort(
                    i, setView.len(), requiredOffsetForHeader
                );
            }

            // Read spec length to determine current attestation's total length
            uint32 specLength =
                uint32(setView.indexUint(currentOffset + ATTESTATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
            uint256 currentAttestationTotalLength = ATTESTATION_TRANSFER_SPEC_OFFSET + specLength;
            uint256 requiredOffsetForElement = currentOffset + currentAttestationTotalLength;

            // Check bounds for full attestation read
            if (setView.len() < requiredOffsetForElement) {
                revert TransferSpecLib.TransferPayloadSetElementTooShort(i, setView.len(), requiredOffsetForElement);
            }

            // 3b. Check magic number of the current element slice
            bytes4 elementMagic = bytes4(setView.index(currentOffset + ATTESTATION_MAGIC_OFFSET, BYTES4_BYTES));
            if (elementMagic != ATTESTATION_MAGIC) {
                revert TransferSpecLib.TransferPayloadSetInvalidElementMagic(i, elementMagic);
            }

            // 3c. Create view and perform full recursive validation on the element
            bytes29 attestationView = setView.slice(
                currentOffset, currentAttestationTotalLength, TransferSpecLib._toMemViewType(ATTESTATION_MAGIC)
            );
            _validateAttestation(attestationView);

            // Update offset for the next iteration
            currentOffset += currentAttestationTotalLength;
        }

        // 4. Final total length consistency check
        if (currentOffset != setView.len()) {
            revert TransferSpecLib.TransferPayloadSetOverallLengthMismatch(currentOffset, setView.len());
        }
    }

    /// Validates the structural integrity of either a `Attestation` or a `AttestationSet`
    ///
    /// @dev First casts the data using `_asAttestationOrSetView`, then calls the appropriate specific validation function
    ///      (`_validateAttestation` or `_validateAttestationSet`). Reverts with specific errors if casting
    ///      or validation fails.
    ///
    /// @param data   The raw bytes representing either an encoded `Attestation` or `AttestationSet`
    /// @return ref   A `TypedMemView` reference to `data`, typed according to the magic number found
    function _validate(bytes memory data) internal pure returns (bytes29 ref) {
        ref = _asAttestationOrSetView(data);

        if (_isSet(ref)) {
            _validateAttestationSet(ref);
        } else {
            _validateAttestation(ref);
        }
    }

    // --- Iteration ---------------------------------------------------------------------------------------------------

    /// Validates `data` and returns a cursor that can uniformly iterate over any attestations it contains
    ///
    /// @dev For a single `Attestation`, the cursor will yield that single element. For a `AttestationSet`,
    ///      it iterates through each contained `Attestation`. Sets the 'done' flag immediately if the set
    ///      contains zero attestations.
    /// @dev Reverts with `TransferPayloadDataTooShort` or `InvalidTransferPayloadMagic` if casting fails
    ///
    /// @param data   The raw bytes representing either an encoded `Attestation` or `AttestationSet`
    /// @return c     An initialized `Cursor` struct
    function cursor(bytes memory data) internal pure returns (Cursor memory c) {
        bytes29 ref = _validate(data);
        c.memView = ref;
        c.index = 0;

        if (!_isSet(ref)) {
            c.offset = 0;
            c.numElements = 1;
            c.done = false; // There's one element to process
            return c;
        }

        uint32 numAttestations = getNumAttestations(ref);
        c.offset = ATTESTATION_SET_ATTESTATIONS_OFFSET;
        c.numElements = numAttestations;
        c.done = (numAttestations == 0); // If the set is empty, the cursor is immediately done
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
            uint32(c.memView.indexUint(c.offset + ATTESTATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
        uint256 currentAttestationTotalLength = ATTESTATION_TRANSFER_SPEC_OFFSET + currentSpecLength;

        ref =
            c.memView.slice(c.offset, currentAttestationTotalLength, TransferSpecLib._toMemViewType(ATTESTATION_MAGIC));

        c.offset += currentAttestationTotalLength;
        c.index++;

        if (c.index >= c.numElements) {
            c.done = true;
        }

        return ref;
    }

    // --- Field accessors ---------------------------------------------------------------------------------------------

    /// Extract the max block height from an encoded `Attestation`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `Attestation`
    /// @return      The `maxBlockHeight` field
    function getMaxBlockHeight(bytes29 ref) internal pure returns (uint256) {
        return ref.indexUint(ATTESTATION_MAX_BLOCK_HEIGHT_OFFSET, UINT256_BYTES);
    }

    /// Extract the transfer spec length from an encoded `Attestation`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `Attestation`
    /// @return      The transfer spec length
    function getTransferSpecLength(bytes29 ref) internal pure returns (uint32) {
        return uint32(ref.indexUint(ATTESTATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
    }

    /// Extract the transfer spec from an encoded `Attestation`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `Attestation`
    /// @return      A `TypedMemView` reference to the `TransferSpec` portion
    function getTransferSpec(bytes29 ref) internal pure returns (bytes29) {
        uint32 specLength = getTransferSpecLength(ref);
        bytes29 specRef =
            ref.slice(ATTESTATION_TRANSFER_SPEC_OFFSET, specLength, TransferSpecLib._toMemViewType(TRANSFER_SPEC_MAGIC));

        // Validate that the slice contains a valid TransferSpec
        bytes4 specMagic = bytes4(specRef.index(0, BYTES4_BYTES));
        if (specMagic != TRANSFER_SPEC_MAGIC) {
            revert TransferSpecLib.InvalidTransferSpecMagic(specMagic);
        }

        return specRef;
    }

    /// Extract the number of attestations from an encoded `AttestationSet`
    ///
    /// @param ref   The `TypedMemView` reference to the encoded `AttestationSet`
    /// @return      The number of attestations in the set
    function getNumAttestations(bytes29 ref) internal pure returns (uint32) {
        return uint32(ref.indexUint(ATTESTATION_SET_NUM_ATTESTATIONS_OFFSET, UINT32_BYTES));
    }

    // --- Encoding ----------------------------------------------------------------------------------------------------

    /// Encode a `Attestation` struct into bytes
    ///
    /// @param attestation   The `Attestation` to encode
    /// @return       The encoded bytes
    function encodeAttestation(Attestation memory attestation) internal pure returns (bytes memory) {
        bytes memory specBytes = TransferSpecLib.encodeTransferSpec(attestation.spec);

        return abi.encodePacked(
            ATTESTATION_MAGIC,
            attestation.maxBlockHeight,
            uint32(specBytes.length), // 4 bytes
            specBytes
        );
    }

    /// Encode a `AttestationSet` struct into bytes
    ///
    /// @param attestationSet   The `AttestationSet` to encode
    /// @return          The encoded bytes
    function encodeAttestationSet(AttestationSet memory attestationSet) internal pure returns (bytes memory) {
        uint256 numAttestations = attestationSet.attestations.length;

        if (numAttestations > type(uint32).max) {
            revert TransferSpecLib.TransferPayloadSetTooManyElements(type(uint32).max);
        }

        // Calculate total size of all encoded attestations
        uint256 totalSize = 0;
        bytes[] memory encodedAttestations = new bytes[](numAttestations);
        for (uint256 i = 0; i < numAttestations; i++) {
            encodedAttestations[i] = encodeAttestation(attestationSet.attestations[i]);
            totalSize += encodedAttestations[i].length;
        }

        // Create header with magic and attestation count
        bytes memory header = abi.encodePacked(
            ATTESTATION_SET_MAGIC,
            uint32(numAttestations) // 4 bytes
        );

        // Combine header and all encoded attestations
        bytes memory result = new bytes(header.length + totalSize);

        // Copy header into result
        for (uint256 i = 0; i < header.length; i++) {
            result[i] = header[i];
        }

        // Copy each encoded attestation into result
        uint256 position = header.length;
        for (uint256 i = 0; i < numAttestations; i++) {
            bytes memory attestation = encodedAttestations[i];
            for (uint256 j = 0; j < attestation.length; j++) {
                result[position] = attestation[j];
                position++;
            }
        }

        return result;
    }
}
