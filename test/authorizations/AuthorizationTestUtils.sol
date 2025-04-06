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

import {Test} from "forge-std/Test.sol";
import {TypedMemView} from "@memview-sol/TypedMemView.sol";
import {TransferSpec} from "src/lib/authorizations/TransferSpec.sol";
import {BurnAuthorization} from "src/lib/authorizations/BurnAuthorizations.sol";
import {MintAuthorization} from "src/lib/authorizations/MintAuthorizations.sol";
import {AuthorizationLib} from "src/lib/authorizations/AuthorizationLib.sol";

contract AuthorizationTestUtils is Test {
    using AuthorizationLib for bytes;
    using AuthorizationLib for bytes29;
    using TypedMemView for bytes29; // For keccak/len on views

    uint16 internal constant TRANSFER_SPEC_METADATA_LENGTH_OFFSET = 336;
    uint16 internal constant TRANSFER_SPEC_METADATA_OFFSET = 340;

    bytes internal constant SHORT_METADATA = "Test metadata";
    bytes internal constant LONG_METADATA = "This is a longer metadata string to test larger metadata payloads";

    function cloneBytes(bytes memory source) internal pure returns (bytes memory target) {
        target = new bytes(source.length);
        for (uint256 i = 0; i < source.length; i++) {
            target[i] = source[i];
        }
    }

    // Helper to create data with specific magic bytes
    function _magic(string memory label) internal pure returns (bytes memory, uint40) {
        bytes4 magic = bytes4(keccak256(bytes(label)));
        return (abi.encodePacked(magic), uint40(uint32(magic)));
    }

    // Compares two TransferSpec structs field-by-field
    function _assertTransferSpecsEqual(TransferSpec memory a, TransferSpec memory b) internal pure {
        assertEq(a.version, b.version, "Eq Fail: version");
        assertEq(a.sourceDomain, b.sourceDomain, "Eq Fail: sourceDomain");
        assertEq(a.destinationDomain, b.destinationDomain, "Eq Fail: destinationDomain");
        assertEq(a.sourceContract, b.sourceContract, "Eq Fail: sourceContract");
        assertEq(a.destinationContract, b.destinationContract, "Eq Fail: destinationContract");
        assertEq(a.sourceToken, b.sourceToken, "Eq Fail: sourceToken");
        assertEq(a.destinationToken, b.destinationToken, "Eq Fail: destinationToken");
        assertEq(a.sourceDepositor, b.sourceDepositor, "Eq Fail: sourceDepositor");
        assertEq(a.destinationRecipient, b.destinationRecipient, "Eq Fail: destinationRecipient");
        assertEq(a.sourceSigner, b.sourceSigner, "Eq Fail: sourceSigner");
        assertEq(a.destinationCaller, b.destinationCaller, "Eq Fail: destinationCaller");
        assertEq(a.value, b.value, "Eq Fail: value");
        assertEq(a.nonce, b.nonce, "Eq Fail: nonce");
        assertEq(keccak256(a.metadata), keccak256(b.metadata), "Eq Fail: metadata keccak");
    }

    function _assertBurnAuthorizationsEqual(BurnAuthorization memory a, BurnAuthorization memory b) internal pure {
        assertEq(a.maxBlockHeight, b.maxBlockHeight, "Eq Fail: maxBlockHeight");
        assertEq(a.maxFee, b.maxFee, "Eq Fail: maxFee");
        _assertTransferSpecsEqual(a.spec, b.spec);
    }

    function _assertMintAuthorizationsEqual(MintAuthorization memory a, MintAuthorization memory b) internal pure {
        assertEq(a.maxBlockHeight, b.maxBlockHeight, "Eq Fail: maxBlockHeight");
        _assertTransferSpecsEqual(a.spec, b.spec);
    }

    // Verifies all fields read from a TransferSpec view match the original struct
    function _verifyTransferSpecFieldsFromView(bytes29 ref, TransferSpec memory spec) internal pure {
        assertEq(ref.getTransferSpecVersion(), spec.version, "Eq Fail: version");
        assertEq(ref.getTransferSpecSourceDomain(), spec.sourceDomain, "Eq Fail: sourceDomain");
        assertEq(ref.getTransferSpecDestinationDomain(), spec.destinationDomain, "Eq Fail: destinationDomain");
        assertEq(ref.getTransferSpecSourceContract(), spec.sourceContract, "Eq Fail: sourceContract");
        assertEq(ref.getTransferSpecDestinationContract(), spec.destinationContract, "Eq Fail: destinationContract");
        assertEq(ref.getTransferSpecSourceToken(), spec.sourceToken, "Eq Fail: sourceToken");
        assertEq(ref.getTransferSpecDestinationToken(), spec.destinationToken, "Eq Fail: destinationToken");
        assertEq(ref.getTransferSpecSourceDepositor(), spec.sourceDepositor, "Eq Fail: sourceDepositor");
        assertEq(ref.getTransferSpecDestinationRecipient(), spec.destinationRecipient, "Eq Fail: destinationRecipient");
        assertEq(ref.getTransferSpecSourceSigner(), spec.sourceSigner, "Eq Fail: sourceSigner");
        assertEq(ref.getTransferSpecDestinationCaller(), spec.destinationCaller, "Eq Fail: destinationCaller");
        assertEq(ref.getTransferSpecValue(), spec.value, "Eq Fail: value");
        assertEq(ref.getTransferSpecNonce(), spec.nonce, "Eq Fail: nonce");

        // Metadata checks
        uint32 metadataLength = ref.getTransferSpecMetadataLength();
        assertEq(metadataLength, spec.metadata.length, "Mismatch: metadata.length");
        bytes29 metadataView = ref.getTransferSpecMetadata();
        if (metadataLength > 0) {
            assertEq(metadataView.keccak(), keccak256(spec.metadata), "Mismatch: metadata keccak");
        } else {
            assertEq(metadataView.len(), 0, "Mismatch: empty metadataView length");
        }
    }

    // Verifies all fields read from a BurnAuthorization view match the original struct
    function _verifyBurnAuthorizationFieldsFromView(bytes29 ref, BurnAuthorization memory auth) internal pure {
        assertEq(ref.getBurnAuthorizationMaxBlockHeight(), auth.maxBlockHeight, "Eq Fail: maxBlockHeight");
        assertEq(ref.getBurnAuthorizationMaxFee(), auth.maxFee, "Eq Fail: maxFee");
        bytes29 specRef = ref.getBurnAuthorizationTransferSpec();
        _verifyTransferSpecFieldsFromView(specRef, auth.spec);
    }

    // Verifies all fields read from a MintAuthorization view match the original struct
    function _verifyMintAuthorizationFieldsFromView(bytes29 ref, MintAuthorization memory auth) internal pure {
        assertEq(ref.getMintAuthorizationMaxBlockHeight(), auth.maxBlockHeight, "Eq Fail: maxBlockHeight");
        bytes29 specRef = ref.getMintAuthorizationTransferSpec();
        _verifyTransferSpecFieldsFromView(specRef, auth.spec);
    }

    /// @notice Creates corrupted TransferSpec data by modifying the inner spec's declared metadata length.
    ///         Useful for testing direct `TransferSpec` decoding or decoding of structs containing an embedded `TransferSpec`.
    /// @param encodedStruct The original encoded data containing the TransferSpec.
    /// @param specOffset The starting offset of the inner TransferSpec within `encodedStruct` (0 for direct TransferSpec tests).
    /// @param originalMetadataLength The actual length of the metadata in the original `spec`.
    /// @param makeLengthBigger If true, corrupts the length field to be larger; otherwise, makes it smaller.
    /// @return corruptedData The modified byte array with the corrupted metadata length.
    /// @return corruptedMetadataLength The artificially inflated/deflated metadata length value written into the corrupted data.
    function _getCorruptedInnerSpecMetadataLengthData(
        bytes memory encodedStruct,
        uint32 specOffset,
        uint32 originalMetadataLength,
        bool makeLengthBigger
    ) internal pure returns (bytes memory corruptedData, uint32 corruptedMetadataLength) {
        uint256 innerMetadataLengthOffset = specOffset + TRANSFER_SPEC_METADATA_LENGTH_OFFSET;
        corruptedData = cloneBytes(encodedStruct);

        if (makeLengthBigger) {
            corruptedMetadataLength = originalMetadataLength * 2;
        } else {
            corruptedMetadataLength = originalMetadataLength / 2;
        }

        bytes4 encodedInvalidLength = bytes4(corruptedMetadataLength);
        for (uint8 i = 0; i < 4; i++) {
            corruptedData[innerMetadataLengthOffset + i] = encodedInvalidLength[i];
        }

        return (corruptedData, corruptedMetadataLength);
    }
}
