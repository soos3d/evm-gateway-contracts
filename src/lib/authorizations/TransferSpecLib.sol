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
import {
    TransferSpec,
    TRANSFER_SPEC_MAGIC,
    TRANSFER_SPEC_MAGIC_OFFSET,
    TRANSFER_SPEC_VERSION_OFFSET,
    TRANSFER_SPEC_SOURCE_DOMAIN_OFFSET,
    TRANSFER_SPEC_DESTINATION_DOMAIN_OFFSET,
    TRANSFER_SPEC_SOURCE_CONTRACT_OFFSET,
    TRANSFER_SPEC_DESTINATION_CONTRACT_OFFSET,
    TRANSFER_SPEC_SOURCE_TOKEN_OFFSET,
    TRANSFER_SPEC_DESTINATION_TOKEN_OFFSET,
    TRANSFER_SPEC_SOURCE_DEPOSITOR_OFFSET,
    TRANSFER_SPEC_DESTINATION_RECIPIENT_OFFSET,
    TRANSFER_SPEC_SOURCE_SIGNER_OFFSET,
    TRANSFER_SPEC_DESTINATION_CALLER_OFFSET,
    TRANSFER_SPEC_VALUE_OFFSET,
    TRANSFER_SPEC_NONCE_OFFSET,
    TRANSFER_SPEC_METADATA_LENGTH_OFFSET,
    TRANSFER_SPEC_METADATA_OFFSET
    } from "./TransferSpec.sol";

uint8 constant BYTES4_BYTES = 4;
uint8 constant UINT32_BYTES = 4;
uint8 constant UINT256_BYTES = 32;
uint8 constant BYTES32_BYTES = 32;

library TransferSpecLib {
    using TypedMemView for bytes;
    using TypedMemView for bytes29;

    error MalformedTransferSpec(bytes data);
    error MalformedTransferSpecInvalidLength(uint256 expectedMinimumLength, uint256 actualLength);

    function _toMemViewType(bytes4 magic) internal pure returns (uint40) {
        return uint40(uint32(magic));
    }

    modifier onlyTransferSpec(bytes29 ref) {
        ref.assertType(_toMemViewType(TRANSFER_SPEC_MAGIC));
        _;
    }

    // --- Casting ---

    /// @notice Creates a typed memory view for a TransferSpec
    /// @dev Creates a typed view with the proper type encoding and validates the magic number
    /// @param data The raw bytes to create a view into
    /// @return ref A typed memory view referencing the TransferSpec data
    function asTransferSpec(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(_toMemViewType(TRANSFER_SPEC_MAGIC));
        if (ref.index(0, BYTES4_BYTES) != TRANSFER_SPEC_MAGIC) {
            revert MalformedTransferSpec(data);
        }
    }

    // --- Validation ---

    /// @notice Validates the structural integrity of an encoded TransferSpec memory view.
    /// @dev Performs structural validation on a TransferSpec view. Reverts on failure.
    /// Assumes the view has the correct TransferSpec magic number (e.g., checked via `asTransferSpec`).
    /// Validation includes:
    /// 1. Minimum header length check (ensuring enough bytes for fixed fields).
    /// 2. Total length consistency check (ensuring `header_length + declared_metadata_length == total_view_length`).
    /// @dev Reverts with `MalformedTransferSpecInvalidLength` if the structure is invalid.
    /// @param specView The TypedMemView reference to the encoded TransferSpec to validate.
    function validateTransferSpecStructure(bytes29 specView) internal pure onlyTransferSpec(specView) {
        // 1. Minimum header length check
        if (specView.len() < TRANSFER_SPEC_METADATA_OFFSET) {
            revert MalformedTransferSpecInvalidLength(TRANSFER_SPEC_METADATA_OFFSET, specView.len());
        }

        // 2. Total length consistency check
        // (Reads declared metadata length from the view and checks against view's total length)
        uint32 metadataLength = getTransferSpecMetadataLength(specView);
        uint256 expectedInternalSpecLength = TRANSFER_SPEC_METADATA_OFFSET + metadataLength;
        if (specView.len() != expectedInternalSpecLength) {
            revert MalformedTransferSpecInvalidLength(expectedInternalSpecLength, specView.len());
        }
    }

    // --- View field accessors ---

    /// @notice Extract the version from an encoded TransferSpec
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The version field
    function getTransferSpecVersion(bytes29 ref) internal pure onlyTransferSpec(ref) returns (uint32) {
        return uint32(ref.indexUint(TRANSFER_SPEC_VERSION_OFFSET, UINT32_BYTES));
    }

    /// @notice Extract the source domain from an encoded TransferSpec
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The sourceDomain field
    function getTransferSpecSourceDomain(bytes29 ref) internal pure onlyTransferSpec(ref) returns (uint32) {
        return uint32(ref.indexUint(TRANSFER_SPEC_SOURCE_DOMAIN_OFFSET, UINT32_BYTES));
    }

    /// @notice Extract the destination domain from an encoded TransferSpec
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The destinationDomain field
    function getTransferSpecDestinationDomain(bytes29 ref) internal pure onlyTransferSpec(ref) returns (uint32) {
        return uint32(ref.indexUint(TRANSFER_SPEC_DESTINATION_DOMAIN_OFFSET, UINT32_BYTES));
    }

    /// @notice Extract the source contract from an encoded TransferSpec
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The sourceContract field
    function getTransferSpecSourceContract(bytes29 ref) internal pure onlyTransferSpec(ref) returns (bytes32) {
        return ref.index(TRANSFER_SPEC_SOURCE_CONTRACT_OFFSET, BYTES32_BYTES);
    }

    /// @notice Extract the destination contract from an encoded TransferSpec
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The destinationContract field
    function getTransferSpecDestinationContract(bytes29 ref) internal pure onlyTransferSpec(ref) returns (bytes32) {
        return ref.index(TRANSFER_SPEC_DESTINATION_CONTRACT_OFFSET, BYTES32_BYTES);
    }

    /// @notice Extract the source token from an encoded TransferSpec
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The sourceToken field
    function getTransferSpecSourceToken(bytes29 ref) internal pure onlyTransferSpec(ref) returns (bytes32) {
        return ref.index(TRANSFER_SPEC_SOURCE_TOKEN_OFFSET, BYTES32_BYTES);
    }

    /// @notice Extract the destination token from an encoded TransferSpec
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The destinationToken field
    function getTransferSpecDestinationToken(bytes29 ref) internal pure onlyTransferSpec(ref) returns (bytes32) {
        return ref.index(TRANSFER_SPEC_DESTINATION_TOKEN_OFFSET, BYTES32_BYTES);
    }

    /// @notice Extract the source depositor from an encoded TransferSpec
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The sourceDepositor field
    function getTransferSpecSourceDepositor(bytes29 ref) internal pure onlyTransferSpec(ref) returns (bytes32) {
        return ref.index(TRANSFER_SPEC_SOURCE_DEPOSITOR_OFFSET, BYTES32_BYTES);
    }

    /// @notice Extract the destination recipient from an encoded TransferSpec
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The destinationRecipient field
    function getTransferSpecDestinationRecipient(bytes29 ref) internal pure onlyTransferSpec(ref) returns (bytes32) {
        return ref.index(TRANSFER_SPEC_DESTINATION_RECIPIENT_OFFSET, BYTES32_BYTES);
    }

    /// @notice Extract the source signer from an encoded TransferSpec
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The sourceSigner field
    function getTransferSpecSourceSigner(bytes29 ref) internal pure onlyTransferSpec(ref) returns (bytes32) {
        return ref.index(TRANSFER_SPEC_SOURCE_SIGNER_OFFSET, BYTES32_BYTES);
    }

    /// @notice Extract the destination caller from an encoded TransferSpec
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The destinationCaller field
    function getTransferSpecDestinationCaller(bytes29 ref) internal pure onlyTransferSpec(ref) returns (bytes32) {
        return ref.index(TRANSFER_SPEC_DESTINATION_CALLER_OFFSET, BYTES32_BYTES);
    }

    /// @notice Extract the value from an encoded TransferSpec
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The value field
    function getTransferSpecValue(bytes29 ref) internal pure onlyTransferSpec(ref) returns (uint256) {
        return ref.indexUint(TRANSFER_SPEC_VALUE_OFFSET, UINT256_BYTES);
    }

    /// @notice Extract the nonce from an encoded TransferSpec
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The nonce field
    function getTransferSpecNonce(bytes29 ref) internal pure onlyTransferSpec(ref) returns (bytes32) {
        return ref.index(TRANSFER_SPEC_NONCE_OFFSET, BYTES32_BYTES);
    }

    /// @notice Extract the metadata length from an encoded TransferSpec
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The metadata length
    function getTransferSpecMetadataLength(bytes29 ref) internal pure onlyTransferSpec(ref) returns (uint32) {
        return uint32(ref.indexUint(TRANSFER_SPEC_METADATA_LENGTH_OFFSET, UINT32_BYTES));
    }

    /// @notice Extract the metadata from an encoded TransferSpec as bytes
    /// @param ref The TypedMemView reference to the encoded TransferSpec
    /// @return The metadata as bytes
    function getTransferSpecMetadata(bytes29 ref) internal pure onlyTransferSpec(ref) returns (bytes29) {
        uint32 metadataLength = getTransferSpecMetadataLength(ref);
        if (metadataLength > 0) {
            return ref.slice(TRANSFER_SPEC_METADATA_OFFSET, metadataLength, 0);
        }
        // Return an empty slice
        return ref.slice(TRANSFER_SPEC_METADATA_OFFSET, 0, 0);
    }

    // --- Encoding ---

    function _encodeTransferSpecHeader(
        uint32 version,
        uint32 sourceDomain,
        uint32 destinationDomain,
        bytes32 sourceContract,
        bytes32 destinationContract,
        bytes32 sourceToken,
        bytes32 destinationToken,
        bytes32 sourceDepositor
    ) private pure returns (bytes memory) {
        return abi.encodePacked(
            TRANSFER_SPEC_MAGIC,
            version,
            sourceDomain,
            destinationDomain,
            sourceContract,
            destinationContract,
            sourceToken,
            destinationToken,
            sourceDepositor
        );
    }

    function _encodeTransferSpecFooter(
        bytes32 destinationRecipient,
        bytes32 sourceSigner,
        bytes32 destinationCaller,
        uint256 value,
        bytes32 nonce,
        bytes memory metadata
    ) private pure returns (bytes memory) {
        if (metadata.length > type(uint32).max) {
            revert MalformedTransferSpec("Metadata length exceeds maximum allowed (4GB)");
        }

        return abi.encodePacked(
            destinationRecipient,
            sourceSigner,
            destinationCaller,
            value,
            nonce,
            uint32(metadata.length), // 4 bytes
            metadata
        );
    }

    /// @notice Encode a TransferSpec struct into bytes
    /// @dev Encoding is split into two parts to avoid "stack too deep" errors
    /// @param spec The TransferSpec to encode
    /// @return The encoded bytes
    function encodeTransferSpec(TransferSpec memory spec) internal pure returns (bytes memory) {
        bytes memory header = _encodeTransferSpecHeader(
            spec.version,
            spec.sourceDomain,
            spec.destinationDomain,
            spec.sourceContract,
            spec.destinationContract,
            spec.sourceToken,
            spec.destinationToken,
            spec.sourceDepositor
        );
        bytes memory footer = _encodeTransferSpecFooter(
            spec.destinationRecipient, spec.sourceSigner, spec.destinationCaller, spec.value, spec.nonce, spec.metadata
        );
        return bytes.concat(header, footer);
    }

    // --- Hashing ---

    /// @notice Calculate the keccak256 hash of a TransferSpec view.
    /// @param ref The TypedMemView reference to the encoded TransferSpec.
    /// @return The keccak256 hash of the encoded TransferSpec bytes.
    function getTransferSpecHash(bytes29 ref) internal pure onlyTransferSpec(ref) returns (bytes32) {
        return ref.keccak();
    }

}