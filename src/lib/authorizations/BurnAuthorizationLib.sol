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
pragma solidity ^0.8.28;

import {TypedMemView} from "@memview-sol/TypedMemView.sol";
import {TransferSpec, TRANSFER_SPEC_MAGIC} from "./TransferSpec.sol";
import {
    BurnAuthorization,
    BurnAuthorizationSet,
    BURN_AUTHORIZATION_MAGIC,
    BURN_AUTHORIZATION_SET_MAGIC,
    BURN_AUTHORIZATION_MAGIC_OFFSET,
    BURN_AUTHORIZATION_MAX_BLOCK_HEIGHT_OFFSET,
    BURN_AUTHORIZATION_MAX_FEE_OFFSET,
    BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET,
    BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET,
    BURN_AUTHORIZATION_SET_MAGIC_OFFSET,
    BURN_AUTHORIZATION_SET_NUM_AUTHORIZATIONS_OFFSET,
    BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET
} from "./BurnAuthorizations.sol";
import {
    TransferSpecLib,
    BYTES4_BYTES,
    UINT32_BYTES,
    UINT256_BYTES} from "./TransferSpecLib.sol";

library BurnAuthorizationLib {
    using TypedMemView for bytes;
    using TypedMemView for bytes29;

    // BurnAuthorization decoding errors
    error MalformedBurnAuthorization(bytes data);
    error MalformedBurnAuthorizationInvalidLength(uint256 expectedMinimumLength, uint256 actualLength);
    error MalformedBurnAuthorizationSet(bytes data);

    modifier onlyBurnAuthorization(bytes29 ref) {
        ref.assertType(TransferSpecLib._toMemViewType(BURN_AUTHORIZATION_MAGIC));
        _;
    }

    modifier onlyBurnAuthorizationSet(bytes29 ref) {
        ref.assertType(TransferSpecLib._toMemViewType(BURN_AUTHORIZATION_SET_MAGIC));
        _;
    }

    // --- Casting ---

    /// @notice Creates a typed memory view for a BurnAuthorization
    /// @dev Creates a typed view with the proper type encoding and validates the magic number
    /// @param data The raw bytes to create a view into
    /// @return ref A typed memory view referencing the BurnAuthorization data
    function asBurnAuthorization(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(TransferSpecLib._toMemViewType(BURN_AUTHORIZATION_MAGIC));
        if (ref.index(0, BYTES4_BYTES) != BURN_AUTHORIZATION_MAGIC) {
            revert MalformedBurnAuthorization(data);
        }
    }

    /// @notice Creates a typed memory view for a BurnAuthorizationSet
    /// @dev Creates a typed view with the proper type encoding and validates the magic number
    /// @param data The raw bytes to create a view into
    /// @return ref A typed memory view referencing the BurnAuthorizationSet data
    function asBurnAuthorizationSet(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(TransferSpecLib._toMemViewType(BURN_AUTHORIZATION_SET_MAGIC));
        if (ref.index(0, BYTES4_BYTES) != BURN_AUTHORIZATION_SET_MAGIC) {
            revert MalformedBurnAuthorizationSet(data);
        }
    }

    // --- Validation ---

    /// @notice Validates the structural integrity of an encoded BurnAuthorization wrapper.
    /// @dev Performs structural validation on a BurnAuthorization view,
    ///      *excluding* recursive validation of the nested TransferSpec and its magic number. Reverts on failure.
    ///      Assumes outer magic number check has passed (via asBurnAuthorization).
    /// Validation steps:
    /// 1. Minimum header length check.
    /// 2. Total length consistency check (using declared TransferSpec length).
    /// @param authView The TypedMemView reference to the encoded BurnAuthorization to validate.
    function _validateBurnAuthorizationOuterStructure(bytes29 authView) private pure {
        // 1. Minimum header length check
        if (authView.len() < BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET) {
            revert MalformedBurnAuthorizationInvalidLength(BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET, authView.len());
        }

        // 2. Total length consistency check
        uint32 specLengthDeclaredInAuth = getBurnAuthorizationTransferSpecLength(authView);
        uint256 expectedAuthLength = BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET + specLengthDeclaredInAuth;
        if (authView.len() != expectedAuthLength) {
            revert MalformedBurnAuthorizationInvalidLength(expectedAuthLength, authView.len());
        }
    }

    /// @notice Validates the full structural integrity of a BurnAuthorization view, including the nested TransferSpec.
    /// @dev Performs structural validation on a BurnAuthorization view. Reverts on failure.
    /// Assumes the view has the correct BurnAuthorization magic number (enforced by the
    ///      `onlyBurnAuthorization` modifier).
    /// Validation includes:
    /// 1. Wrapper structure validation (header length, total length consistency, nested TransferSpec magic).
    /// 2. Full recursive validation of the nested TransferSpec structure.
    /// @dev Reverts with specific errors (e.g., MalformedBurnAuthorizationInvalidLength, MalformedTransferSpec) if the
    ///      structure is invalid.
    /// @param authView The TypedMemView reference to the encoded BurnAuthorization to
    ///                 validate.
    function validateBurnAuthorization(bytes29 authView) internal pure onlyBurnAuthorization(authView) {
        _validateBurnAuthorizationOuterStructure(authView);
        bytes29 specView = getBurnAuthorizationTransferSpec(authView);
        TransferSpecLib.validateTransferSpecStructure(specView);
    }

    /// @notice Validates the full structural integrity of an encoded BurnAuthorizationSet memory view.
    /// @dev Performs structural validation on a BurnAuthorizationSet view. Reverts on failure.
    /// Assumes the view has the correct BurnAuthorizationSet magic number (e.g., checked via `as...Set`).
    /// Validation includes:
    /// 1. Minimum header length check.
    /// 2. Reading declared authorization count.
    /// 3. Iterating through declared authorizations:
    ///    a. Checking bounds based on previously declared lengths.
    ///    b. Checking the magic number of each authorization.
    ///    c. Performing full recursive validation on each authorization using `validateBurnAuthorization`.
    /// 4. Final total length consistency check.
    /// @dev Reverts with specific errors (e.g., MalformedBurnAuthorizationSet) if the structure is invalid.
    /// @param setView The TypedMemView reference to the encoded BurnAuthorizationSet to validate.
    function validateBurnAuthorizationSet(bytes29 setView) internal pure onlyBurnAuthorizationSet(setView) {
        // 1. Minimum header length check
        if (setView.len() < BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET) {
            revert MalformedBurnAuthorizationSet("Data too short for set header");
        }

        // 2. Read declared count
        uint32 numAuths = getBurnAuthorizationSetNumAuthorizations(setView);
        uint256 currentOffset = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;

        // 3. Iterate and validate each element
        for (uint32 i = 0; i < numAuths; i++) {
            // 3a. Check bounds for header read
            if (setView.len() < currentOffset + BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET) {
                revert MalformedBurnAuthorizationSet("Data too short for next BurnAuthorization header");
            }
            // Read spec length to determine current auth total length
            uint32 specLength =
                uint32(setView.indexUint(currentOffset + BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
            uint256 currentAuthTotalLength = BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET + specLength;
            // Check bounds for full auth read
            if (setView.len() < currentOffset + currentAuthTotalLength) {
                revert MalformedBurnAuthorizationSet("Data too short for next BurnAuthorization");
            }

            // 3b. Check magic number of the current element slice
            if (
                bytes4(setView.index(currentOffset + BURN_AUTHORIZATION_MAGIC_OFFSET, BYTES4_BYTES))
                    != BURN_AUTHORIZATION_MAGIC
            ) {
                revert MalformedBurnAuthorizationSet("Invalid authorization magic in set");
            }

            // 3c. Create view and perform full recursive validation on the element
            bytes29 authView =
                setView.slice(currentOffset, currentAuthTotalLength, TransferSpecLib._toMemViewType(BURN_AUTHORIZATION_MAGIC));
            validateBurnAuthorization(authView);

            // Update offset for the next iteration
            currentOffset += currentAuthTotalLength;
        }

        // 4. Final total length consistency check
        if (currentOffset != setView.len()) {
            revert MalformedBurnAuthorizationSet("Set length mismatch after validating all elements");
        }
    }

    // --- View field accessors ---

    /// @notice Extract the max block height from an encoded BurnAuthorization
    /// @param ref The TypedMemView reference to the encoded BurnAuthorization
    /// @return The maxBlockHeight field
    function getBurnAuthorizationMaxBlockHeight(bytes29 ref)
        internal
        pure
        onlyBurnAuthorization(ref)
        returns (uint256)
    {
        return ref.indexUint(BURN_AUTHORIZATION_MAX_BLOCK_HEIGHT_OFFSET, UINT256_BYTES);
    }

    /// @notice Extract the max fee from an encoded BurnAuthorization
    /// @param ref The TypedMemView reference to the encoded BurnAuthorization
    /// @return The maxFee field
    function getBurnAuthorizationMaxFee(bytes29 ref) internal pure onlyBurnAuthorization(ref) returns (uint256) {
        return ref.indexUint(BURN_AUTHORIZATION_MAX_FEE_OFFSET, UINT256_BYTES);
    }

    /// @notice Extract the transfer spec length from an encoded BurnAuthorization
    /// @param ref The TypedMemView reference to the encoded BurnAuthorization
    /// @return The transfer spec length
    function getBurnAuthorizationTransferSpecLength(bytes29 ref)
        internal
        pure
        onlyBurnAuthorization(ref)
        returns (uint32)
    {
        return uint32(ref.indexUint(BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
    }

    /// @notice Extract the transfer spec from an encoded BurnAuthorization
    /// @param ref The TypedMemView reference to the encoded BurnAuthorization
    /// @return A TypedMemView reference to the transferSpec portion
    function getBurnAuthorizationTransferSpec(bytes29 ref) internal pure onlyBurnAuthorization(ref) returns (bytes29) {
        uint32 specLength = getBurnAuthorizationTransferSpecLength(ref);
        bytes29 specRef =
            ref.slice(BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET, specLength, TransferSpecLib._toMemViewType(TRANSFER_SPEC_MAGIC));

        // Validate that the slice contains a valid TransferSpec
        if (specRef.index(0, BYTES4_BYTES) != TRANSFER_SPEC_MAGIC) {
            revert TransferSpecLib.MalformedTransferSpec("Invalid TransferSpec magic in BurnAuthorization");
        }

        return specRef;
    }

    /// @notice Extract the number of authorizations from an encoded BurnAuthorizationSet
    /// @param ref The TypedMemView reference to the encoded BurnAuthorizationSet
    /// @return The number of authorizations in the set
    function getBurnAuthorizationSetNumAuthorizations(bytes29 ref)
        internal
        pure
        onlyBurnAuthorizationSet(ref)
        returns (uint32)
    {
        return uint32(ref.indexUint(BURN_AUTHORIZATION_SET_NUM_AUTHORIZATIONS_OFFSET, UINT32_BYTES));
    }

    /// @notice Extract a BurnAuthorization at the given index from a BurnAuthorizationSet
    /// @param ref The TypedMemView reference to the encoded BurnAuthorizationSet
    /// @param index The index of the authorization to extract
    /// @return A typed memory view for the authorization at the given index
    function getBurnAuthorizationSetAuthorizationAt(bytes29 ref, uint32 index)
        internal
        pure
        onlyBurnAuthorizationSet(ref)
        returns (bytes29)
    {
        uint32 numAuths = getBurnAuthorizationSetNumAuthorizations(ref);

        if (index >= numAuths) {
            revert MalformedBurnAuthorizationSet("Index out of bounds");
        }

        // Initial offset is just the fixed header of BurnAuthorizationSet before the authorizations themselves
        uint32 offset = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;

        // Skip past authorizations before the one we want
        for (uint32 i = 0; i < index; i++) {
            // Ensure we're at a valid BurnAuthorization
            bytes4 magic = bytes4(ref.index(offset, BYTES4_BYTES));
            if (magic != BURN_AUTHORIZATION_MAGIC) {
                revert MalformedBurnAuthorizationSet("Invalid authorization magic in set");
            }
            uint32 specLength =
                uint32(ref.indexUint(offset + BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
            offset += BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET + specLength;
        }

        // Verify the magic at the current offset
        bytes4 targetMagic = bytes4(ref.index(offset, BYTES4_BYTES));
        if (targetMagic != BURN_AUTHORIZATION_MAGIC) {
            revert MalformedBurnAuthorizationSet("Invalid authorization magic in set");
        }

        uint32 targetSpecLength =
            uint32(ref.indexUint(offset + BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
        uint256 authSize = BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET + targetSpecLength;

        // Validate that the calculated slice is within the bounds of the parent view
        if (ref.len() < offset + authSize) {
            revert MalformedBurnAuthorizationSet("Calculated authorization slice exceeds set bounds");
        }

        // Return a typed memory view to this authorization
        bytes29 authView = ref.slice(offset, authSize, TransferSpecLib._toMemViewType(BURN_AUTHORIZATION_MAGIC));
        return authView;
    }

    // --- Encoding ---

    /// @notice Encode a BurnAuthorization struct into bytes
    /// @param auth The BurnAuthorization to encode
    /// @return The encoded bytes
    function encodeBurnAuthorization(BurnAuthorization memory auth) internal pure returns (bytes memory) {
        bytes memory specBytes = TransferSpecLib.encodeTransferSpec(auth.spec);
        return abi.encodePacked(
            BURN_AUTHORIZATION_MAGIC,
            auth.maxBlockHeight,
            auth.maxFee,
            uint32(specBytes.length), // 4 bytes
            specBytes
        );
    }

    /// @notice Encode a BurnAuthorizationSet struct into bytes
    /// @param authSet The BurnAuthorizationSet to encode
    /// @return The encoded bytes
    function encodeBurnAuthorizationSet(BurnAuthorizationSet memory authSet) internal pure returns (bytes memory) {
        uint256 numAuths = authSet.authorizations.length;

        if (numAuths > type(uint32).max) {
            revert MalformedBurnAuthorizationSet("Too many authorizations");
        }

        // Calculate total size of all encoded authorizations
        uint256 totalSize = 0;
        bytes[] memory encodedAuths = new bytes[](numAuths);
        for (uint256 i = 0; i < numAuths; i++) {
            encodedAuths[i] = encodeBurnAuthorization(authSet.authorizations[i]);
            totalSize += encodedAuths[i].length;
        }

        // Create header with magic and authorization count
        bytes memory header = abi.encodePacked(
            BURN_AUTHORIZATION_SET_MAGIC,
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

    // --- Decoding ---

    /// @notice Internal helper to decode a BurnAuthorization struct from its TypedMemView reference
    /// @dev Assumes the authView points to a valid slice within a larger structure or represents the full data.
    /// @param authView The TypedMemView reference to the encoded BurnAuthorization
    /// @return The decoded BurnAuthorization struct
    function _decodeBurnAuthorizationFromView(bytes29 authView) private view returns (BurnAuthorization memory) {
        _validateBurnAuthorizationOuterStructure(authView);
        bytes29 specView = getBurnAuthorizationTransferSpec(authView);
        TransferSpec memory decodedSpec = TransferSpecLib._decodeTransferSpecFromView(specView);
        return BurnAuthorization({
            maxBlockHeight: getBurnAuthorizationMaxBlockHeight(authView),
            maxFee: getBurnAuthorizationMaxFee(authView),
            spec: decodedSpec
        });
    }

    /// @notice Decode a BurnAuthorization struct from its byte representation
    /// @param data The encoded BurnAuthorization bytes
    /// @return The decoded BurnAuthorization struct
    function decodeBurnAuthorization(bytes memory data) internal view returns (BurnAuthorization memory) {
        bytes29 authView = asBurnAuthorization(data);
        return _decodeBurnAuthorizationFromView(authView);
    }

    /// @notice Decode a BurnAuthorizationSet struct from its byte representation
    /// @param data The encoded BurnAuthorizationSet bytes
    /// @return The decoded BurnAuthorizationSet struct
    /// @dev Performs validation during decoding:
    ///      1. Minimum header length check.
    ///      2. Magic number check via `asBurnAuthorizationSet`.
    ///      3. Iterative decoding and validation of each `BurnAuthorization`:
    ///         a. Checks that entire set is long enough for next authorization header.
    ///         b. Checks that entire set is long enough to contain the full next authorization
    ///         c. Checks magic number of the current authorization.
    ///         d. Decodes the `BurnAuthorization` using `_decodeBurnAuthorizationFromView`,
    ///            which includes nested validation.
    ///      4. Final total length consistency check.
    function decodeBurnAuthorizationSet(bytes memory data) internal view returns (BurnAuthorizationSet memory) {
        // 1. Minimum header length check
        if (data.length < BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET) {
            revert MalformedBurnAuthorizationSet("Data too short for set header");
        }

        // Create view of the BurnAuthorizationSet
        // 2. Magic number check
        bytes29 setView = asBurnAuthorizationSet(data);

        uint32 numAuths = getBurnAuthorizationSetNumAuthorizations(setView);
        BurnAuthorization[] memory authorizations = new BurnAuthorization[](numAuths);

        // Initial offset is just the fixed header of BurnAuthorizationSet before the authorizations themselves
        uint256 currentOffset = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;

        for (uint32 i = 0; i < numAuths; i++) {
            // 3a. Check that the entire set is long enough to contain the next BurnAuthorization header
            if (setView.len() < currentOffset + BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET) {
                revert MalformedBurnAuthorizationSet("Data too short for next BurnAuthorization header");
            }

            // 3b. Check that the entire set is long enough to contain the full next BurnAuthorization
            uint32 specLength =
                uint32(setView.indexUint(currentOffset + BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
            uint256 currentAuthTotalLength = BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET + specLength;
            if (setView.len() < currentOffset + currentAuthTotalLength) {
                revert MalformedBurnAuthorizationSet("Data too short for next BurnAuthorization");
            }

            // 3c. Check the magic number of the current authorization
            bytes4 actualMagic = bytes4(setView.index(currentOffset + BURN_AUTHORIZATION_MAGIC_OFFSET, BYTES4_BYTES));
            if (actualMagic != BURN_AUTHORIZATION_MAGIC) {
                revert MalformedBurnAuthorizationSet("Invalid authorization magic in set");
            }

            // Create a view for the BurnAuthorization
            bytes29 authView =
                setView.slice(currentOffset, currentAuthTotalLength, TransferSpecLib._toMemViewType(BURN_AUTHORIZATION_MAGIC));

            // 3d. Validate and decode the BurnAuthorization
            authorizations[i] = _decodeBurnAuthorizationFromView(authView);

            // Update the offset for the next iteration
            currentOffset += currentAuthTotalLength;
        }

        if (currentOffset != setView.len()) {
            revert MalformedBurnAuthorizationSet("Set length mismatch after decoding all elements");
        }

        return BurnAuthorizationSet({authorizations: authorizations});
    }

} 