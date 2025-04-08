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

library AuthorizationLib {
    using TypedMemView for bytes;
    using TypedMemView for bytes29;

    uint8 private constant BYTES4_BYTES = 4;
    uint8 private constant UINT32_BYTES = 4;
    uint8 private constant UINT256_BYTES = 32;
    uint8 private constant BYTES32_BYTES = 32;

    // TransferSpec decoding errors
    error MalformedTransferSpec(bytes data);
    error MalformedTransferSpecInvalidLength(uint256 expectedLength, uint256 actualLength);

    // BurnAuthorization decoding errors
    error MalformedBurnAuthorization(bytes data);
    error MalformedBurnAuthorizationInvalidLength(uint256 expectedLength, uint256 actualLength);
    error MalformedBurnAuthorizationSet(bytes data);

    // MintAuthorization decoding errors
    error MalformedMintAuthorization(bytes data);
    error MalformedMintAuthorizationInvalidLength(uint256 expectedLength, uint256 actualLength);
    error MalformedMintAuthorizationSet(bytes data);

    function _toMemViewType(bytes4 magic) private pure returns (uint40) {
        return uint40(uint32(magic));
    }

    // --- Type assertion modifiers ---

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

    /// @notice Checks if the provided data likely represents an authorization set (Burn or Mint).
    /// @param data The raw byte data to check.
    /// @return true if the magic number matches BurnAuthorizationSet or MintAuthorizationSet, false otherwise.
    function isAuthorizationSet(bytes memory data) internal pure returns (bool) {
        bytes29 ref = data.ref(0);
        bytes4 magic = bytes4(ref.index(0, BYTES4_BYTES));
        return magic == BURN_AUTHORIZATION_SET_MAGIC || magic == MINT_AUTHORIZATION_SET_MAGIC;
    }

    /// @notice Creates a typed memory view for a BurnAuthorization
    /// @dev Creates a typed view with the proper type encoding and validates the magic number
    /// @param data The raw bytes to create a view into
    /// @return ref A typed memory view referencing the BurnAuthorization data
    function asBurnAuthorization(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(_toMemViewType(BURN_AUTHORIZATION_MAGIC));
        if (ref.index(0, BYTES4_BYTES) != BURN_AUTHORIZATION_MAGIC) {
            revert MalformedBurnAuthorization(data);
        }
    }

    /// @notice Creates a typed memory view for a BurnAuthorizationSet
    /// @dev Creates a typed view with the proper type encoding and validates the magic number
    /// @param data The raw bytes to create a view into
    /// @return ref A typed memory view referencing the BurnAuthorizationSet data
    function asBurnAuthorizationSet(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(_toMemViewType(BURN_AUTHORIZATION_SET_MAGIC));
        if (ref.index(0, BYTES4_BYTES) != BURN_AUTHORIZATION_SET_MAGIC) {
            revert MalformedBurnAuthorizationSet(data);
        }
    }

    /// @notice Creates a typed memory view for a MintAuthorization
    /// @dev Creates a typed view with the proper type encoding and validates the magic number
    /// @param data The raw bytes to create a view into
    /// @return ref A typed memory view referencing the MintAuthorization data
    function asMintAuthorization(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(_toMemViewType(MINT_AUTHORIZATION_MAGIC));
        if (ref.index(0, BYTES4_BYTES) != MINT_AUTHORIZATION_MAGIC) {
            revert MalformedMintAuthorization(data);
        }
    }

    /// @notice Creates a typed memory view for a MintAuthorizationSet
    /// @dev Creates a typed view with the proper type encoding and validates the magic number
    /// @param data The raw bytes to create a view into
    /// @return ref A typed memory view referencing the MintAuthorizationSet data
    function asMintAuthorizationSet(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(_toMemViewType(MINT_AUTHORIZATION_SET_MAGIC));
        if (ref.index(0, BYTES4_BYTES) != MINT_AUTHORIZATION_SET_MAGIC) {
            revert MalformedMintAuthorizationSet(data);
        }
    }

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

    // --- Validators ---

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
        validateTransferSpecStructure(specView);
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
                setView.slice(currentOffset, currentAuthTotalLength, _toMemViewType(BURN_AUTHORIZATION_MAGIC));
            validateBurnAuthorization(authView);

            // Update offset for the next iteration
            currentOffset += currentAuthTotalLength;
        }

        // 4. Final total length consistency check
        if (currentOffset != setView.len()) {
            revert MalformedBurnAuthorizationSet("Set length mismatch after validating all elements");
        }
    }

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
        validateTransferSpecStructure(specView);
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
                setView.slice(currentOffset, currentAuthTotalLength, _toMemViewType(MINT_AUTHORIZATION_MAGIC));
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
            ref.slice(BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET, specLength, _toMemViewType(TRANSFER_SPEC_MAGIC));

        // Validate that the slice contains a valid TransferSpec
        if (specRef.index(0, BYTES4_BYTES) != TRANSFER_SPEC_MAGIC) {
            revert MalformedTransferSpec("Invalid TransferSpec magic in BurnAuthorization");
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
        bytes29 authView = ref.slice(offset, authSize, _toMemViewType(BURN_AUTHORIZATION_MAGIC));
        return authView;
    }

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
            ref.slice(MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET, specLength, _toMemViewType(TRANSFER_SPEC_MAGIC));

        // Validate that the slice contains a valid TransferSpec
        if (specRef.index(0, BYTES4_BYTES) != TRANSFER_SPEC_MAGIC) {
            revert MalformedTransferSpec("Invalid TransferSpec magic in MintAuthorization");
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
        bytes29 authView = ref.slice(offset, authSize, _toMemViewType(MINT_AUTHORIZATION_MAGIC));
        return authView;
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

    /// @notice Encode a MintAuthorization struct into bytes
    /// @param auth The MintAuthorization to encode
    /// @return The encoded bytes
    function encodeMintAuthorization(MintAuthorization memory auth) internal pure returns (bytes memory) {
        bytes memory specBytes = encodeTransferSpec(auth.spec);

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

    // --- Hash Utilities ---

    /// @notice Calculate the keccak256 hash of an encoded TransferSpec.
    /// @param encodedSpec The raw bytes of the encoded TransferSpec.
    /// @return The keccak256 hash of the encoded TransferSpec bytes.
    function getTransferSpecHash(bytes memory encodedSpec) internal pure returns (bytes32) {
        return keccak256(encodedSpec);
    }

    // --- Decoding Functions ---

    /// @notice Internal helper to decode a TransferSpec struct from its TypedMemView reference
    /// @param specView The TypedMemView reference to the encoded TransferSpec
    /// @return The decoded TransferSpec struct
    function _decodeTransferSpecFromView(bytes29 specView) private view returns (TransferSpec memory) {
        validateTransferSpecStructure(specView);

        bytes memory metadata;
        uint32 metadataLength = getTransferSpecMetadataLength(specView);
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
        _validateBurnAuthorizationOuterStructure(authView);
        bytes29 specView = getBurnAuthorizationTransferSpec(authView);
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
                setView.slice(currentOffset, currentAuthTotalLength, _toMemViewType(BURN_AUTHORIZATION_MAGIC));

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

    /// @notice Internal helper to decode a MintAuthorization struct from its TypedMemView reference
    /// @dev Assumes the authView points to a valid slice within a larger structure or represents the full data.
    /// @param authView The TypedMemView reference to the encoded MintAuthorization
    /// @return The decoded MintAuthorization struct
    function _decodeMintAuthorizationFromView(bytes29 authView) private view returns (MintAuthorization memory) {
        _validateMintAuthorizationOuterStructure(authView);
        bytes29 specView = getMintAuthorizationTransferSpec(authView);
        TransferSpec memory decodedSpec = _decodeTransferSpecFromView(specView);
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
                setView.slice(currentOffset, currentAuthTotalLength, _toMemViewType(MINT_AUTHORIZATION_MAGIC));

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
