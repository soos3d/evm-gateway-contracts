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
    MintAuthorization,
    MintAuthorizationSet,
    MINT_AUTHORIZATION_MAGIC,
    MINT_AUTHORIZATION_SET_MAGIC,
    MINT_AUTHORIZATION_MAGIC_OFFSET,
    MINT_AUTHORIZATION_MAX_BLOCK_HEIGHT_OFFSET,
    MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET,
    MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET,
    MINT_AUTHORIZATION_SET_MAGIC_OFFSET,
    MINT_AUTHORIZATION_SET_NUM_AUTHORIZATIONS_OFFSET,
    MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET
} from "./MintAuthorizations.sol";
import {
    TransferSpecLib,
    BYTES4_BYTES,
    UINT32_BYTES,
    UINT256_BYTES
} from "./TransferSpecLib.sol";

library MintAuthorizationLib {
    using TypedMemView for bytes;
    using TypedMemView for bytes29;

    // MintAuthorization decoding errors
    error MalformedMintAuthorization(bytes data);
    error MalformedMintAuthorizationInvalidLength(uint256 expectedMinimumLength, uint256 actualLength);
    error MalformedMintAuthorizationSet(bytes data);

    modifier onlyMintAuthorization(bytes29 ref) {
        ref.assertType(TransferSpecLib._toMemViewType(MINT_AUTHORIZATION_MAGIC));
        _;
    }

    modifier onlyMintAuthorizationSet(bytes29 ref) {
        ref.assertType(TransferSpecLib._toMemViewType(MINT_AUTHORIZATION_SET_MAGIC));
        _;
    }

    // --- Casting ---

    /// @notice Creates a typed memory view for a MintAuthorization
    /// @dev Creates a typed view with the proper type encoding and validates the magic number
    /// @param data The raw bytes to create a view into
    /// @return ref A typed memory view referencing the MintAuthorization data
    function asMintAuthorization(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(TransferSpecLib._toMemViewType(MINT_AUTHORIZATION_MAGIC));
        if (ref.index(0, BYTES4_BYTES) != MINT_AUTHORIZATION_MAGIC) {
            revert MalformedMintAuthorization(data);
        }
    }

    /// @notice Creates a typed memory view for a MintAuthorizationSet
    /// @dev Creates a typed view with the proper type encoding and validates the magic number
    /// @param data The raw bytes to create a view into
    /// @return ref A typed memory view referencing the MintAuthorizationSet data
    function asMintAuthorizationSet(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(TransferSpecLib._toMemViewType(MINT_AUTHORIZATION_SET_MAGIC));
        if (ref.index(0, BYTES4_BYTES) != MINT_AUTHORIZATION_SET_MAGIC) {
            revert MalformedMintAuthorizationSet(data);
        }
    }

    // --- Validation ---

    /// @notice Validates the structural integrity of an encoded MintAuthorization wrapper.
    /// @dev Performs structural validation on a MintAuthorization view,
    ///      *excluding* recursive validation of the nested TransferSpec and its magic number. Reverts on failure.
    ///      Assumes outer magic number check has passed (via asMintAuthorization).
    /// Validation steps:
    /// 1. Minimum header length check.
    /// 2. Total length consistency check (using declared TransferSpec length).
    /// @param authView The TypedMemView reference to the encoded MintAuthorization to validate.
    function _validateMintAuthorizationOuterStructure(bytes29 authView) private pure {
        // 1. Minimum header length check
        if (authView.len() < MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET) {
            revert MalformedMintAuthorizationInvalidLength(MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET, authView.len());
        }

        // 2. Total length consistency check
        uint32 specLengthDeclaredInAuth = getMintAuthorizationTransferSpecLength(authView);
        uint256 expectedAuthLength = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + specLengthDeclaredInAuth;
        if (authView.len() != expectedAuthLength) {
            revert MalformedMintAuthorizationInvalidLength(expectedAuthLength, authView.len());
        }
    }

    /// @notice Validates the full structural integrity of a MintAuthorization view, including the nested TransferSpec.
    /// @dev Performs comprehensive structural validation on a MintAuthorization view. Reverts on failure.
    /// Assumes the view has the correct MintAuthorization magic number (enforced by the
    ///      `onlyMintAuthorization` modifier).
    /// Validation includes:
    /// 1. Wrapper structure validation (header length, total length consistency, nested TransferSpec magic).
    /// 2. Full recursive validation of the nested TransferSpec structure.
    /// @dev Reverts with specific errors (e.g., MalformedMintAuthorizationInvalidLength, MalformedTransferSpec) if the
    ///      structure is invalid.
    /// @param authView The TypedMemView reference to the encoded MintAuthorization to
    ///                 validate.
    function validateMintAuthorization(bytes29 authView) internal pure onlyMintAuthorization(authView) {
        _validateMintAuthorizationOuterStructure(authView);
        bytes29 specView = getMintAuthorizationTransferSpec(authView);
        TransferSpecLib.validateTransferSpecStructure(specView);
    }

    /// @notice Validates the full structural integrity of an encoded MintAuthorization memory view.
    /// @dev Performs structural validation on a MintAuthorizationSet view. Reverts on failure.
    /// Assumes the view has the correct MintAuthorizationSet magic number (e.g., checked via `as...Set`).
    /// Validation includes:
    /// 1. Minimum header length check.
    /// 2. Reading declared authorization count.
    /// 3. Iterating through declared authorizations:
    ///    a. Checking bounds based on previously declared lengths.
    ///    b. Checking the magic number of each authorization.
    ///    c. Performing full recursive validation on each authorization using `validateMintAuthorization`.
    /// 4. Final total length consistency check.
    /// @dev Reverts with specific errors (e.g., MalformedMintAuthorizationSet) if the structure is invalid.
    /// @param setView The TypedMemView reference to the encoded MintAuthorizationSet to validate.
    function validateMintAuthorizationSet(bytes29 setView) internal pure onlyMintAuthorizationSet(setView) {
        // 1. Minimum header length check
        if (setView.len() < MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET) {
            revert MalformedMintAuthorizationSet("Data too short for set header");
        }

        // 2. Read declared count
        uint32 numAuths = getMintAuthorizationSetNumAuthorizations(setView);
        uint256 currentOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;

        // 3. Iterate and validate each element
        for (uint32 i = 0; i < numAuths; i++) {
            // 3a. Check bounds for header read
            if (setView.len() < currentOffset + MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET) {
                revert MalformedMintAuthorizationSet("Data too short for next MintAuthorization header");
            }
            // Read spec length to determine current auth total length
            uint32 specLength =
                uint32(setView.indexUint(currentOffset + MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
            uint256 currentAuthTotalLength = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + specLength;
            // Check bounds for full auth read
            if (setView.len() < currentOffset + currentAuthTotalLength) {
                revert MalformedMintAuthorizationSet("Data too short for next MintAuthorization");
            }

            // 3b. Check magic number of the current element slice
            if (
                bytes4(setView.index(currentOffset + MINT_AUTHORIZATION_MAGIC_OFFSET, BYTES4_BYTES))
                    != MINT_AUTHORIZATION_MAGIC
            ) {
                revert MalformedMintAuthorizationSet("Invalid authorization magic in set");
            }

            // 3c. Create view and perform full recursive validation on the element
            bytes29 authView =
                setView.slice(currentOffset, currentAuthTotalLength, TransferSpecLib._toMemViewType(MINT_AUTHORIZATION_MAGIC));
            validateMintAuthorization(authView);

            // Update offset for the next iteration
            currentOffset += currentAuthTotalLength;
        }

        // 4. Final total length consistency check
        if (currentOffset != setView.len()) {
            revert MalformedMintAuthorizationSet("Set length mismatch after validating all elements");
        }
    }

    // --- View field accessors ---

    /// @notice Extract the max block height from an encoded MintAuthorization
    /// @param ref The TypedMemView reference to the encoded MintAuthorization
    /// @return The maxBlockHeight field
    function getMintAuthorizationMaxBlockHeight(bytes29 ref)
        internal
        pure
        onlyMintAuthorization(ref)
        returns (uint256)
    {
        return ref.indexUint(MINT_AUTHORIZATION_MAX_BLOCK_HEIGHT_OFFSET, UINT256_BYTES);
    }

    /// @notice Extract the transfer spec length from an encoded MintAuthorization
    /// @param ref The TypedMemView reference to the encoded MintAuthorization
    /// @return The transfer spec length
    function getMintAuthorizationTransferSpecLength(bytes29 ref)
        internal
        pure
        onlyMintAuthorization(ref)
        returns (uint32)
    {
        return uint32(ref.indexUint(MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
    }

    /// @notice Extract the transfer spec from an encoded MintAuthorization
    /// @param ref The TypedMemView reference to the encoded MintAuthorization
    /// @return A TypedMemView reference to the transferSpec portion
    function getMintAuthorizationTransferSpec(bytes29 ref) internal pure onlyMintAuthorization(ref) returns (bytes29) {
        uint32 specLength = getMintAuthorizationTransferSpecLength(ref);
        bytes29 specRef =
            ref.slice(MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET, specLength, TransferSpecLib._toMemViewType(TRANSFER_SPEC_MAGIC));

        // Validate that the slice contains a valid TransferSpec
        if (specRef.index(0, BYTES4_BYTES) != TRANSFER_SPEC_MAGIC) {
            revert TransferSpecLib.MalformedTransferSpec("Invalid TransferSpec magic in MintAuthorization");
        }

        return specRef;
    }

    /// @notice Extract the number of authorizations from an encoded MintAuthorizationSet
    /// @param ref The TypedMemView reference to the encoded MintAuthorizationSet
    /// @return The number of authorizations in the set
    function getMintAuthorizationSetNumAuthorizations(bytes29 ref)
        internal
        pure
        onlyMintAuthorizationSet(ref)
        returns (uint32)
    {
        return uint32(ref.indexUint(MINT_AUTHORIZATION_SET_NUM_AUTHORIZATIONS_OFFSET, UINT32_BYTES));
    }

    /// @notice Extract a MintAuthorization at the given index from a MintAuthorizationSet
    /// @param ref The TypedMemView reference to the encoded MintAuthorizationSet
    /// @param index The index of the authorization to extract
    /// @return A typed memory view for the authorization at the given index
    function getMintAuthorizationSetAuthorizationAt(bytes29 ref, uint32 index)
        internal
        pure
        onlyMintAuthorizationSet(ref)
        returns (bytes29)
    {
        uint32 numAuths = getMintAuthorizationSetNumAuthorizations(ref);

        if (index >= numAuths) {
            revert MalformedMintAuthorizationSet("Index out of bounds");
        }

        // Initial offset is just the fixed header of MintAuthorizationSet before the authorizations themselves
        uint32 offset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;

        // Skip past authorizations before the one we want
        for (uint32 i = 0; i < index; i++) {
            // Ensure we're at a valid MintAuthorization
            bytes4 magic = bytes4(ref.index(offset, BYTES4_BYTES));
            if (magic != MINT_AUTHORIZATION_MAGIC) {
                revert MalformedMintAuthorizationSet("Invalid authorization magic in set");
            }
            uint32 specLength =
                uint32(ref.indexUint(offset + MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
            offset += MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + specLength;
        }

        // Verify the magic at the current offset
        bytes4 targetMagic = bytes4(ref.index(offset, BYTES4_BYTES));
        if (targetMagic != MINT_AUTHORIZATION_MAGIC) {
            revert MalformedMintAuthorizationSet("Invalid authorization magic in set");
        }

        uint32 targetSpecLength =
            uint32(ref.indexUint(offset + MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
        uint256 authSize = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + targetSpecLength;

        // Validate that the calculated slice is within the bounds of the parent view
        if (ref.len() < offset + authSize) {
            revert MalformedMintAuthorizationSet("Calculated authorization slice exceeds set bounds");
        }

        // Return a typed memory view to this authorization
        bytes29 authView = ref.slice(offset, authSize, TransferSpecLib._toMemViewType(MINT_AUTHORIZATION_MAGIC));
        return authView;
    }

    // --- Encoding ---

    /// @notice Encode a MintAuthorization struct into bytes
    /// @param auth The MintAuthorization to encode
    /// @return The encoded bytes
    function encodeMintAuthorization(MintAuthorization memory auth) internal pure returns (bytes memory) {
        bytes memory specBytes = TransferSpecLib.encodeTransferSpec(auth.spec);

        return abi.encodePacked(
            MINT_AUTHORIZATION_MAGIC,
            auth.maxBlockHeight, // 32 bytes
            uint32(specBytes.length), // 4 bytes
            specBytes
        );
    }

    /// @notice Encode a MintAuthorizationSet struct into bytes
    /// @param authSet The MintAuthorizationSet to encode
    /// @return The encoded bytes
    function encodeMintAuthorizationSet(MintAuthorizationSet memory authSet) internal pure returns (bytes memory) {
        uint256 numAuths = authSet.authorizations.length;

        if (numAuths > type(uint32).max) {
            revert MalformedMintAuthorizationSet("Too many authorizations");
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

    // --- Decoding ---

    /// @notice Internal helper to decode a MintAuthorization struct from its TypedMemView reference
    /// @dev Assumes the authView points to a valid slice within a larger structure or represents the full data.
    /// @param authView The TypedMemView reference to the encoded MintAuthorization
    /// @return The decoded MintAuthorization struct
    function _decodeMintAuthorizationFromView(bytes29 authView) private view returns (MintAuthorization memory) {
        _validateMintAuthorizationOuterStructure(authView);
        bytes29 specView = getMintAuthorizationTransferSpec(authView);
        TransferSpec memory decodedSpec = TransferSpecLib._decodeTransferSpecFromView(specView);
        return MintAuthorization({maxBlockHeight: getMintAuthorizationMaxBlockHeight(authView), spec: decodedSpec});
    }

    /// @notice Decode a MintAuthorization struct from its byte representation
    /// @param data The encoded MintAuthorization bytes
    /// @return The decoded MintAuthorization struct
    function decodeMintAuthorization(bytes memory data) internal view returns (MintAuthorization memory) {
        bytes29 authView = asMintAuthorization(data);
        return _decodeMintAuthorizationFromView(authView);
    }

    /// @notice Decode a MintAuthorizationSet struct from its byte representation
    /// @param data The encoded MintAuthorizationSet bytes
    /// @return The decoded MintAuthorizationSet struct
    /// @dev Performs validation during decoding:
    ///      1. Minimum header length check.
    ///      2. Magic number check via `asMintAuthorizationSet`.
    ///      3. Iterative decoding and validation of each `MintAuthorization`:
    ///         a. Checks that entire set is long enough for next authorization header.
    ///         b. Checks that entire set is long enough to contain the full next authorization
    ///         c. Checks magic number of the current authorization.
    ///         d. Decodes the `MintAuthorization` using `_decodeMintAuthorizationFromView`,
    ///            which includes nested validation.
    ///      4. Final total length consistency check.
    function decodeMintAuthorizationSet(bytes memory data) internal view returns (MintAuthorizationSet memory) {
        // 1. Minimum header length check
        if (data.length < MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET) {
            revert MalformedMintAuthorizationSet("Data too short for set header");
        }

        // Create view of the MintAuthorizationSet
        // 2. Magic number check
        bytes29 setView = asMintAuthorizationSet(data);

        uint32 numAuths = getMintAuthorizationSetNumAuthorizations(setView);
        MintAuthorization[] memory authorizations = new MintAuthorization[](numAuths);

        // Initial offset is just the fixed header of MintAuthorizationSet before the authorizations themselves
        uint256 currentOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;

        for (uint32 i = 0; i < numAuths; i++) {
            // 3a. Check that the entire set is long enough to contain the next MintAuthorization header
            if (setView.len() < currentOffset + MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET) {
                revert MalformedMintAuthorizationSet("Data too short for next MintAuthorization header");
            }

            // 3b. Check that the entire set is long enough to contain the full next MintAuthorization
            uint32 specLength =
                uint32(setView.indexUint(currentOffset + MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
            uint256 currentAuthTotalLength = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + specLength;
            if (setView.len() < currentOffset + currentAuthTotalLength) {
                revert MalformedMintAuthorizationSet("Data too short for next MintAuthorization");
            }

            // 3c. Check the magic number of the current authorization
            bytes4 actualMagic = bytes4(setView.index(currentOffset + MINT_AUTHORIZATION_MAGIC_OFFSET, BYTES4_BYTES));
            if (actualMagic != MINT_AUTHORIZATION_MAGIC) {
                revert MalformedMintAuthorizationSet("Invalid authorization magic in set");
            }

            // Create a view for the MintAuthorization
            bytes29 authView =
                setView.slice(currentOffset, currentAuthTotalLength, TransferSpecLib._toMemViewType(MINT_AUTHORIZATION_MAGIC));

            // 3d. Validate and decode the MintAuthorization
            authorizations[i] = _decodeMintAuthorizationFromView(authView);

            // Update the offset for the next iteration
            currentOffset += currentAuthTotalLength;
        }

        if (currentOffset != setView.len()) {
            revert MalformedMintAuthorizationSet("Set length mismatch after decoding all elements");
        }

        return MintAuthorizationSet({authorizations: authorizations});
    }

} 