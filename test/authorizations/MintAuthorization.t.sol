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
import {AttestationLib} from "src/lib/AttestationLib.sol";
import {Attestation, ATTESTATION_MAGIC} from "src/lib/Attestations.sol";
import {Cursor} from "src/lib/Cursor.sol";
import {TRANSFER_SPEC_VERSION, TRANSFER_SPEC_MAGIC} from "src/lib/TransferSpec.sol";
import {TransferSpecLib} from "src/lib/TransferSpecLib.sol";
import {BYTES4_BYTES} from "src/lib/TransferSpecLib.sol";
import {TransferPayloadTestUtils} from "./TransferPayloadTestUtils.sol";

contract AttestationTest is TransferPayloadTestUtils {
    using AttestationLib for bytes29;
    using AttestationLib for Cursor;

    // ===== Casting Tests =====

    function test_asAttestationOrSetView_successAttestation() public pure {
        (bytes memory data, uint40 magicType) = _magic("circle.gateway.Attestation");
        bytes29 ref = AttestationLib._asAttestationOrSetView(data);
        assertEq(TypedMemView.typeOf(ref), magicType);
        assertEq(bytes4(uint32(magicType)), ATTESTATION_MAGIC);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asAttestationOrSetView_revertsOnShortData() public {
        bytes memory shortData = hex"1122";
        vm.expectRevert(
            abi.encodeWithSelector(TransferSpecLib.TransferPayloadDataTooShort.selector, BYTES4_BYTES, shortData.length)
        );
        AttestationLib._asAttestationOrSetView(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asAttestationOrSetView_revertsOnInvalidMagic4Bytes() public {
        (bytes memory invalidMagicData,) = _magic("not a valid magic");
        bytes4 incorrectMagic = bytes4(invalidMagicData);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidTransferPayloadMagic.selector, incorrectMagic));
        AttestationLib._asAttestationOrSetView(invalidMagicData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asAttestationOrSetView_revertsOnInvalidMagicLonger() public {
        (bytes memory invalidMagicData,) = _magic("not a valid magic");
        bytes memory longerInvalidMagic = bytes.concat(invalidMagicData, hex"01020304");
        bytes4 incorrectMagic = bytes4(longerInvalidMagic);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidTransferPayloadMagic.selector, incorrectMagic));
        AttestationLib._asAttestationOrSetView(longerInvalidMagic);
    }

    // ===== Validation Tests =====

    function test_validate_successFuzz(Attestation memory attestation) public pure {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.metadata = LONG_METADATA;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        AttestationLib._validate(encodedAttestation);
    }

    // ===== Validation Failures: Attestation Structure =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_attestation_revertsOnDataTooShortForHeaderFuzz(Attestation memory attestation) public {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        bytes memory validEncodedAttestation = AttestationLib.encodeAttestation(attestation);

        uint16 truncatedLength = ATTESTATION_TRANSFER_SPEC_OFFSET - 1;
        bytes memory shortData = new bytes(truncatedLength);
        for (uint16 i = 0; i < truncatedLength; i++) {
            shortData[i] = validEncodedAttestation[i];
        }
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadHeaderTooShort.selector, ATTESTATION_TRANSFER_SPEC_OFFSET, shortData.length
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_attestation_revertsOnDeclaredSpecLengthTooBigFuzz(Attestation memory attestation) public {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.metadata = LONG_METADATA;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        uint256 originalAttestationLength = encodedAttestation.length;
        uint32 originalSpecLength = uint32(originalAttestationLength - ATTESTATION_TRANSFER_SPEC_OFFSET);

        uint32 invalidSpecLength = originalSpecLength + 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        bytes memory corruptedData = cloneBytes(encodedAttestation);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            corruptedData[ATTESTATION_TRANSFER_SPEC_LENGTH_OFFSET + i] = encodedInvalidLength[i];
        }

        uint256 expectedAttestationLengthBasedOnCorruption = ATTESTATION_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadOverallLengthMismatch.selector,
            expectedAttestationLengthBasedOnCorruption,
            originalAttestationLength
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_attestation_revertsOnDeclaredSpecLengthTooSmallFuzz(Attestation memory attestation) public {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.metadata = LONG_METADATA;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        uint256 originalAttestationLength = encodedAttestation.length;
        uint32 originalSpecLength = uint32(originalAttestationLength - ATTESTATION_TRANSFER_SPEC_OFFSET);

        uint32 invalidSpecLength = originalSpecLength - 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        bytes memory corruptedData = cloneBytes(encodedAttestation);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            corruptedData[ATTESTATION_TRANSFER_SPEC_LENGTH_OFFSET + i] = encodedInvalidLength[i];
        }

        uint256 expectedAttestationLengthBasedOnCorruption = ATTESTATION_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadOverallLengthMismatch.selector,
            expectedAttestationLengthBasedOnCorruption,
            originalAttestationLength
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_attestation_revertsOnTruncatedDataFuzz(Attestation memory attestation) public {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.metadata = LONG_METADATA;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        uint256 expectedLength = encodedAttestation.length;

        bytes memory truncatedData = new bytes(expectedLength - 1);
        for (uint256 i = 0; i < truncatedData.length; i++) {
            truncatedData[i] = encodedAttestation[i];
        }
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadOverallLengthMismatch.selector, expectedLength, truncatedData.length
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_attestation_revertsOnTrailingBytesFuzz(Attestation memory attestation) public {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.metadata = LONG_METADATA;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        uint256 originalAttestationLength = encodedAttestation.length;

        bytes memory corruptedData = bytes.concat(encodedAttestation, hex"FFFF");
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadOverallLengthMismatch.selector,
            originalAttestationLength,
            corruptedData.length
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(corruptedData);
    }

    // ===== Validation Failures: Inner TransferSpec Consistency =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDataTooShortForMagic() public {
        uint256 fixedMaxBlockHeight = 1;
        uint32 incorrectSpecLength = 2;

        bytes memory corruptedData =
            abi.encodePacked(ATTESTATION_MAGIC, fixedMaxBlockHeight, incorrectSpecLength, hex"0000");

        bytes memory expectedRevertData = bytes(
            string.concat(
                "TypedMemView/index - Overran the view. ",
                "Slice is at 0x0000c8 with length 0x000002. ", // The length is the incorrectSpecLength (2)
                "Attempted to index at offset 0x000000 with length 0x000004." // Trying to read 4 byte magic
            )
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnCorruptedMagicFuzz(Attestation memory attestation) public {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.metadata = LONG_METADATA;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);

        encodedAttestation[ATTESTATION_TRANSFER_SPEC_OFFSET] = hex"00";

        bytes4 corruptedMagic;
        uint256 offset = ATTESTATION_TRANSFER_SPEC_OFFSET;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedAttestation[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData =
            abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecMagic.selector, corruptedMagic);

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(encodedAttestation);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDataTooShortForHeaderFuzz(Attestation memory attestation) public {
        uint32 incorrectSpecLength = TRANSFER_SPEC_METADATA_OFFSET - 1;
        bytes memory dummySpecData =
            abi.encodePacked(TRANSFER_SPEC_MAGIC, new bytes(incorrectSpecLength - BYTES4_BYTES));
        bytes memory corruptedData =
            abi.encodePacked(ATTESTATION_MAGIC, attestation.maxBlockHeight, incorrectSpecLength, dummySpecData);
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecHeaderTooShort.selector, TRANSFER_SPEC_METADATA_OFFSET, incorrectSpecLength
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnInvalidVersionFuzz(Attestation memory attestation) public {
        uint32 invalidVersion = TRANSFER_SPEC_VERSION + 1;
        attestation.spec.version = invalidVersion;
        attestation.spec.metadata = LONG_METADATA;

        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecVersion.selector, invalidVersion));
        AttestationLib._validate(encodedAttestation);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDeclaredMetadataLengthTooBigFuzz(Attestation memory attestation) public {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.metadata = LONG_METADATA;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        uint32 originalMetadataLength = uint32(attestation.spec.metadata.length);
        uint32 originalInnerSpecLength = uint32(encodedAttestation.length - ATTESTATION_TRANSFER_SPEC_OFFSET);

        (bytes memory corruptedData, uint32 corruptedMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedAttestation,
            ATTESTATION_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within Attestation
            originalMetadataLength, // Original metadata length
            true // Inflate the metadata length field
        );

        uint256 expectedInnerSpecLength = TRANSFER_SPEC_METADATA_OFFSET + corruptedMetadataLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecOverallLengthMismatch.selector,
            expectedInnerSpecLength, // The incorrect length expected based on corrupted field
            originalInnerSpecLength // The actual length of the original spec view
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDeclaredMetadataLengthTooSmallFuzz(Attestation memory attestation)
        public
    {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.metadata = LONG_METADATA;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        uint32 originalMetadataLength = uint32(attestation.spec.metadata.length);
        uint32 originalInnerSpecLength = uint32(encodedAttestation.length - ATTESTATION_TRANSFER_SPEC_OFFSET);

        (bytes memory corruptedData, uint32 corruptedMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedAttestation,
            ATTESTATION_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within Attestation
            originalMetadataLength, // Original metadata length
            false // Make the metadata length field smaller
        );

        uint256 expectedInnerSpecLength = TRANSFER_SPEC_METADATA_OFFSET + corruptedMetadataLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecOverallLengthMismatch.selector,
            expectedInnerSpecLength, // The incorrect length expected based on corrupted field
            originalInnerSpecLength // The actual length of the original spec view
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(corruptedData);
    }

    // ===== Iteration Tests =====

    function test_cursor_successFuzz(Attestation memory attestation) public pure {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.metadata = LONG_METADATA;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        bytes29 attestationView = AttestationLib._asAttestationOrSetView(encodedAttestation);

        // Initial state
        Cursor memory cursor = AttestationLib.cursor(encodedAttestation);
        assertEq(cursor.memView, attestationView);
        assertEq(cursor.offset, 0);
        assertEq(cursor.numElements, 1);
        assertEq(cursor.index, 0);
        assertEq(cursor.done, false);

        // Advance the cursor
        bytes29 currentAttestation = cursor.next();
        assertEq(currentAttestation, attestationView);
        assertEq(cursor.memView, attestationView);
        assertEq(cursor.offset, encodedAttestation.length);
        assertEq(cursor.numElements, 1);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDoneFuzz(Attestation memory attestation) public {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.metadata = LONG_METADATA;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);

        Cursor memory cursor = AttestationLib.cursor(encodedAttestation);
        cursor.next();
        assertEq(cursor.done, true);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    // ===== Field Accessor Tests =====

    function test_attestation_readAllFieldsEmptyMetadataFuzz(Attestation memory attestation) public pure {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.metadata = new bytes(0);
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        bytes29 ref = AttestationLib._asAttestationOrSetView(encodedAttestation);
        _verifyAttestationFieldsFromView(ref, attestation);
    }

    function test_attestation_readAllFieldsShortMetadataFuzz(Attestation memory attestation) public pure {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.metadata = SHORT_METADATA;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        bytes29 ref = AttestationLib._asAttestationOrSetView(encodedAttestation);
        _verifyAttestationFieldsFromView(ref, attestation);
    }

    function test_attestation_readAllFieldsLongMetadataFuzz(Attestation memory attestation) public pure {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.metadata = LONG_METADATA;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        bytes29 ref = AttestationLib._asAttestationOrSetView(encodedAttestation);
        _verifyAttestationFieldsFromView(ref, attestation);
    }
}
