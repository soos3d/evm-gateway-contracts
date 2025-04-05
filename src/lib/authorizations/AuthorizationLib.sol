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
import {TransferSpec, TRANSFER_SPEC_MAGIC, TRANSFER_SPEC_VERSION} from "./TransferSpec.sol";
import {
    BurnAuthorization,
    BurnAuthorizationSet,
    BURN_AUTHORIZATION_MAGIC,
    BURN_AUTHORIZATION_SET_MAGIC
} from "./BurnAuthorizations.sol";
import {
    MintAuthorization,
    MintAuthorizationSet,
    MINT_AUTHORIZATION_MAGIC,
    MINT_AUTHORIZATION_SET_MAGIC
} from "./MintAuthorizations.sol";

library AuthorizationLib {
    using TypedMemView for bytes;
    using TypedMemView for bytes29;

    error MalformedTransferSpec(bytes data);
    error MalformedTransferSpecInvalidLength(uint256 expectedLength, uint256 actualLength);
    error MalformedBurnAuthorization(bytes data);
    error MalformedBurnAuthorizationSet(bytes data);
    error MalformedBurnAuthorizationInvalidLength(uint256 expectedLength, uint256 actualLength);
    error MalformedMintAuthorization(bytes data);
    error MalformedMintAuthorizationSet(bytes data);
    error MalformedMintAuthorizationInvalidLength(uint256 expectedLength, uint256 actualLength);

    uint8 private constant BYTES4_BYTES = 4;
    uint8 private constant UINT32_BYTES = 4;
    uint8 private constant UINT256_BYTES = 32;
    uint8 private constant BYTES32_BYTES = 32;

    // TransferSpec field offsets
    uint16 private constant TRANSFER_SPEC_MAGIC_OFFSET = 0;
    uint16 private constant TRANSFER_SPEC_VERSION_OFFSET = 4;
    uint16 private constant TRANSFER_SPEC_SOURCE_DOMAIN_OFFSET = 8;
    uint16 private constant TRANSFER_SPEC_DESTINATION_DOMAIN_OFFSET = 12;
    uint16 private constant TRANSFER_SPEC_SOURCE_CONTRACT_OFFSET = 16;
    uint16 private constant TRANSFER_SPEC_DESTINATION_CONTRACT_OFFSET = 48;
    uint16 private constant TRANSFER_SPEC_SOURCE_TOKEN_OFFSET = 80;
    uint16 private constant TRANSFER_SPEC_DESTINATION_TOKEN_OFFSET = 112;
    uint16 private constant TRANSFER_SPEC_SOURCE_DEPOSITOR_OFFSET = 144;
    uint16 private constant TRANSFER_SPEC_DESTINATION_RECIPIENT_OFFSET = 176;
    uint16 private constant TRANSFER_SPEC_SOURCE_SIGNER_OFFSET = 208;
    uint16 private constant TRANSFER_SPEC_DESTINATION_CALLER_OFFSET = 240;
    uint16 private constant TRANSFER_SPEC_VALUE_OFFSET = 272;
    uint16 private constant TRANSFER_SPEC_NONCE_OFFSET = 304;
    uint16 private constant TRANSFER_SPEC_METADATA_LENGTH_OFFSET = 336;
    uint16 private constant TRANSFER_SPEC_METADATA_OFFSET = 340;

    // BurnAuthorization field offsets
    uint16 private constant BURN_AUTHORIZATION_MAGIC_OFFSET = 0;
    uint16 private constant BURN_AUTHORIZATION_MAX_BLOCK_HEIGHT_OFFSET = 4;
    uint16 private constant BURN_AUTHORIZATION_MAX_FEE_OFFSET = 36;
    uint16 private constant BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET = 68;
    uint16 private constant BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET = 72;

    function _toMemViewType(bytes4 magic) private pure returns (uint40) {
        return uint40(uint32(magic));
    }

    // --- Modifiers for type assertions ---

    modifier onlyTransferSpec(bytes29 ref) {
        ref.assertType(_toMemViewType(TRANSFER_SPEC_MAGIC));
        _;
    }

    modifier onlyBurnAuthorization(bytes29 ref) {
        ref.assertType(_toMemViewType(BURN_AUTHORIZATION_MAGIC));
        _;
    }

    modifier onlyMintAuthorization(bytes29 ref) {
        ref.assertType(_toMemViewType(MINT_AUTHORIZATION_MAGIC));
        _;
    }

    modifier onlyBurnAuthorizationSet(bytes29 ref) {
        ref.assertType(_toMemViewType(BURN_AUTHORIZATION_SET_MAGIC));
        _;
    }

    modifier onlyMintAuthorizationSet(bytes29 ref) {
        ref.assertType(_toMemViewType(MINT_AUTHORIZATION_SET_MAGIC));
        _;
    }

    // --- Casting ---

    /// @notice Creates a typed memory view for a BurnAuthorization
    /// @param data The raw bytes to create a view into
    /// @return ref A typed memory view referencing the BurnAuthorization data
    function asBurnAuthorization(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(_toMemViewType(BURN_AUTHORIZATION_MAGIC));
        if (ref.index(0, 4) != BURN_AUTHORIZATION_MAGIC) {
            revert MalformedBurnAuthorization(data);
        }
    }

    /// @notice Creates a typed memory view for a BurnAuthorizationSet
    /// @dev Creates a typed view with the proper type encoding and validates the magic number
    /// @param data The raw bytes to create a view into
    /// @return ref A typed memory view referencing the BurnAuthorizationSet data
    function asBurnAuthorizationSet(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(_toMemViewType(BURN_AUTHORIZATION_SET_MAGIC));
        if (ref.index(0, 4) != BURN_AUTHORIZATION_SET_MAGIC) {
            revert MalformedBurnAuthorizationSet(data);
        }
    }

    /// @notice Creates a typed memory view for a MintAuthorization
    /// @dev Creates a typed view with the proper type encoding and validates the magic number
    /// @param data The raw bytes to create a view into
    /// @return ref A typed memory view referencing the MintAuthorization data
    function asMintAuthorization(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(_toMemViewType(MINT_AUTHORIZATION_MAGIC));
        if (ref.index(0, 4) != MINT_AUTHORIZATION_MAGIC) {
            revert MalformedMintAuthorization(data);
        }
    }

    /// @notice Creates a typed memory view for a MintAuthorizationSet
    /// @dev Creates a typed view with the proper type encoding and validates the magic number
    /// @param data The raw bytes to create a view into
    /// @return ref A typed memory view referencing the MintAuthorizationSet data
    function asMintAuthorizationSet(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(_toMemViewType(MINT_AUTHORIZATION_SET_MAGIC));
        if (ref.index(0, 4) != MINT_AUTHORIZATION_SET_MAGIC) {
            revert MalformedMintAuthorizationSet(data);
        }
    }

    /// @notice Creates a typed memory view for a TransferSpec
    /// @dev Creates a typed view with the proper type encoding and validates the magic number
    /// @param data The raw bytes to create a view into
    /// @return ref A typed memory view referencing the TransferSpec data
    function asTransferSpec(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(_toMemViewType(TRANSFER_SPEC_MAGIC));
        if (ref.index(0, 4) != TRANSFER_SPEC_MAGIC) {
            revert MalformedTransferSpec(data);
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
    function getBurnAuthorizationTransferSpecLength(bytes29 ref) internal pure onlyBurnAuthorization(ref) returns (uint32) {
        return uint32(ref.indexUint(BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET, UINT32_BYTES));
    }

    /// @notice Extract the transfer spec from an encoded BurnAuthorization
    /// @param ref The TypedMemView reference to the encoded BurnAuthorization
    /// @return A TypedMemView reference to the transferSpec portion
    function getBurnAuthorizationTransferSpec(bytes29 ref) internal pure onlyBurnAuthorization(ref) returns (bytes29) {
        uint32 specLength = getBurnAuthorizationTransferSpecLength(ref);
        bytes29 specRef =
            ref.slice(BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET, specLength, _toMemViewType(TRANSFER_SPEC_MAGIC));

        // Validate that the slice contains a valid TransferSpec
        if (specRef.index(0, 4) != TRANSFER_SPEC_MAGIC) {
            revert MalformedTransferSpec("Invalid TransferSpec magic in BurnAuthorization");
        }

        return specRef;
    }

    // --- Encoding Functions ---

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

    /// @notice Encode a BurnAuthorization struct into bytes
    /// @param auth The BurnAuthorization to encode
    /// @return The encoded bytes
    function encodeBurnAuthorization(BurnAuthorization memory auth) internal pure returns (bytes memory) {
        bytes memory specBytes = encodeTransferSpec(auth.spec);
        return abi.encodePacked(
            BURN_AUTHORIZATION_MAGIC,
            auth.maxBlockHeight,
            auth.maxFee,
            uint32(specBytes.length), // 4 bytes
            specBytes
        );
    }

    // --- Decoding Functions ---

    /// @notice Internal helper to decode a TransferSpec struct from its TypedMemView reference
    /// @param specView The TypedMemView reference to the encoded TransferSpec
    /// @return The decoded TransferSpec struct
    function _decodeTransferSpecFromView(bytes29 specView) private view returns (TransferSpec memory) {
        /*
         * Validation steps:
         * 1. Minimum header length check: Verifies the view is long enough (340 bytes)
         *    to contain all fixed-size fields of the TransferSpec struct before the variable-length metadata.
         * 2. Total length consistency check: Reads the metadata length from the TransferSpec view. Verifies that this
         *    metadata length + the TransferSpec fixed header size (340 bytes) exactly matches the view's total length.
         */

        // 1. Minimum header length check
        if (specView.len() < TRANSFER_SPEC_METADATA_OFFSET) {
            revert MalformedTransferSpecInvalidLength(TRANSFER_SPEC_METADATA_OFFSET, specView.len());
        }

        // 2. Total length consistency check
        uint32 metadataLength = getTransferSpecMetadataLength(specView);
        uint256 expectedInternalSpecLength = TRANSFER_SPEC_METADATA_OFFSET + metadataLength;
        if (specView.len() != expectedInternalSpecLength) {
            revert MalformedTransferSpecInvalidLength(expectedInternalSpecLength, specView.len());
        }

        bytes memory metadata;
        if (metadataLength > 0) {
            metadata = getTransferSpecMetadata(specView).clone();
        }

        return TransferSpec({
            version: getTransferSpecVersion(specView),
            sourceDomain: getTransferSpecSourceDomain(specView),
            destinationDomain: getTransferSpecDestinationDomain(specView),
            sourceContract: getTransferSpecSourceContract(specView),
            destinationContract: getTransferSpecDestinationContract(specView),
            sourceToken: getTransferSpecSourceToken(specView),
            destinationToken: getTransferSpecDestinationToken(specView),
            sourceDepositor: getTransferSpecSourceDepositor(specView),
            destinationRecipient: getTransferSpecDestinationRecipient(specView),
            sourceSigner: getTransferSpecSourceSigner(specView),
            destinationCaller: getTransferSpecDestinationCaller(specView),
            value: getTransferSpecValue(specView),
            nonce: getTransferSpecNonce(specView),
            metadata: metadata
        });
    }

    /// @notice Decode a TransferSpec struct from its byte representation
    /// @param data The encoded TransferSpec bytes
    /// @return The decoded TransferSpec struct
    function decodeTransferSpec(bytes memory data) internal view returns (TransferSpec memory) {
        bytes29 specView = asTransferSpec(data);
        return _decodeTransferSpecFromView(specView);
    }

    /// @notice Internal helper to decode a BurnAuthorization struct from its TypedMemView reference
    /// @dev Assumes the authView points to a valid slice within a larger structure or represents the full data.
    /// @param authView The TypedMemView reference to the encoded BurnAuthorization
    /// @return The decoded BurnAuthorization struct
    function _decodeBurnAuthorizationFromView(bytes29 authView) private view returns (BurnAuthorization memory) {
        /*
         * Validation steps:
         * 1. Minimum header length check: Verifies the view is long enough (72 bytes)
         *    to contain all fixed-size fields of the BurnAuthorization struct before the variable-length TransferSpec.
         * 2. Total length consistency check: Reads the declared TransferSpec length from the header within the view
         *    and verifies that the view's length exactly matches the fixed header size (72 bytes) plus this
         *    declared TransferSpec length.
         * 3. Inner TransferSpec magic check: Ensures the TransferSpec magic number is correct
         * 4. Inner TransferSpec validation: Calls _decodeTransferSpecFromView on the inner TransferSpec view,
         *    which performs its own set of validations (magic, min length, total length) on that inner view.
         */

        // 1. Minimum header length check
        if (authView.len() < BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET) {
            revert MalformedBurnAuthorizationInvalidLength(
                BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET, authView.len()
            );
        }

        // 2. Total length consistency check
        uint32 specLengthDeclaredInAuth = getBurnAuthorizationTransferSpecLength(authView);
        uint256 expectedAuthLength = BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET + specLengthDeclaredInAuth;
        if (authView.len() != expectedAuthLength) {
            revert MalformedBurnAuthorizationInvalidLength(expectedAuthLength, authView.len());
        }

        // Create view of internal TransferSpec
        // 3. Asserts the TransferSpec magic number is correct
        bytes29 specView = getBurnAuthorizationTransferSpec(authView);

        // 4. Inner TransferSpec Validation & Decoding
        TransferSpec memory decodedSpec = _decodeTransferSpecFromView(specView);

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

}
