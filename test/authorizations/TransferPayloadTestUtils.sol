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
import {Test} from "forge-std/Test.sol";
import {BurnIntentLib} from "src/lib/BurnIntentLib.sol";
import {BurnIntent, BURN_INTENT_MAGIC} from "src/lib/BurnIntents.sol";
import {AttestationLib} from "src/lib/AttestationLib.sol";
import {Attestation, ATTESTATION_MAGIC} from "src/lib/Attestations.sol";
import {TransferSpec, TRANSFER_SPEC_MAGIC} from "src/lib/TransferSpec.sol";
import {TransferSpecLib, BYTES4_BYTES} from "src/lib/TransferSpecLib.sol";

contract TransferPayloadTestUtils is Test {
    using TypedMemView for bytes29; // For keccak/len on views

    uint16 internal constant TRANSFER_SPEC_METADATA_LENGTH_OFFSET = 336;
    uint16 internal constant TRANSFER_SPEC_METADATA_OFFSET = 340;
    uint16 internal constant BURN_INTENT_TRANSFER_SPEC_LENGTH_OFFSET = 68;
    uint16 internal constant BURN_INTENT_TRANSFER_SPEC_OFFSET = 72;
    uint16 internal constant ATTESTATION_TRANSFER_SPEC_LENGTH_OFFSET = 36;
    uint16 internal constant ATTESTATION_TRANSFER_SPEC_OFFSET = 40;

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

    // Verifies all fields read from a TransferSpec view match the original struct
    function _verifyTransferSpecFieldsFromView(bytes29 ref, TransferSpec memory spec) internal pure {
        ref.assertType(TransferSpecLib._toMemViewType(TRANSFER_SPEC_MAGIC));
        assertEq(TransferSpecLib.getVersion(ref), spec.version, "Eq Fail: version");
        assertEq(TransferSpecLib.getSourceDomain(ref), spec.sourceDomain, "Eq Fail: sourceDomain");
        assertEq(TransferSpecLib.getDestinationDomain(ref), spec.destinationDomain, "Eq Fail: destinationDomain");
        assertEq(TransferSpecLib.getSourceContract(ref), spec.sourceContract, "Eq Fail: sourceContract");
        assertEq(TransferSpecLib.getDestinationContract(ref), spec.destinationContract, "Eq Fail: destinationContract");
        assertEq(TransferSpecLib.getSourceToken(ref), spec.sourceToken, "Eq Fail: sourceToken");
        assertEq(TransferSpecLib.getDestinationToken(ref), spec.destinationToken, "Eq Fail: destinationToken");
        assertEq(TransferSpecLib.getSourceDepositor(ref), spec.sourceDepositor, "Eq Fail: sourceDepositor");
        assertEq(
            TransferSpecLib.getDestinationRecipient(ref), spec.destinationRecipient, "Eq Fail: destinationRecipient"
        );
        assertEq(TransferSpecLib.getSourceSigner(ref), spec.sourceSigner, "Eq Fail: sourceSigner");
        assertEq(TransferSpecLib.getDestinationCaller(ref), spec.destinationCaller, "Eq Fail: destinationCaller");
        assertEq(TransferSpecLib.getValue(ref), spec.value, "Eq Fail: value");
        assertEq(TransferSpecLib.getNonce(ref), spec.nonce, "Eq Fail: nonce");

        // Metadata checks
        uint32 metadataLength = TransferSpecLib.getMetadataLength(ref);
        assertEq(metadataLength, spec.metadata.length, "Mismatch: metadata.length");
        bytes29 metadataView = TransferSpecLib.getMetadata(ref);
        if (metadataLength > 0) {
            assertEq(metadataView.keccak(), keccak256(spec.metadata), "Mismatch: metadata keccak");
        } else {
            assertEq(metadataView.len(), 0, "Mismatch: empty metadataView length");
        }
    }

    // Verifies all fields read from a BurnIntent view match the original struct
    function _verifyBurnIntentFieldsFromView(bytes29 ref, BurnIntent memory auth) internal pure {
        ref.assertType(TransferSpecLib._toMemViewType(BURN_INTENT_MAGIC));
        assertEq(BurnIntentLib.getMaxBlockHeight(ref), auth.maxBlockHeight, "Eq Fail: maxBlockHeight");
        assertEq(BurnIntentLib.getMaxFee(ref), auth.maxFee, "Eq Fail: maxFee");
        bytes29 specRef = BurnIntentLib.getTransferSpec(ref);
        _verifyTransferSpecFieldsFromView(specRef, auth.spec);
    }

    // Verifies all fields read from a Attestation view match the original struct
    function _verifyAttestationFieldsFromView(bytes29 ref, Attestation memory auth) internal pure {
        ref.assertType(TransferSpecLib._toMemViewType(ATTESTATION_MAGIC));
        assertEq(AttestationLib.getMaxBlockHeight(ref), auth.maxBlockHeight, "Eq Fail: maxBlockHeight");
        bytes29 specRef = AttestationLib.getTransferSpec(ref);
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
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            corruptedData[innerMetadataLengthOffset + i] = encodedInvalidLength[i];
        }

        return (corruptedData, corruptedMetadataLength);
    }
}
