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
import {
    Attestation,
    AttestationSet,
    ATTESTATION_SET_MAGIC,
    ATTESTATION_MAGIC_OFFSET,
    ATTESTATION_SET_ATTESTATIONS_OFFSET,
    ATTESTATION_TRANSFER_SPEC_LENGTH_OFFSET,
    ATTESTATION_TRANSFER_SPEC_OFFSET
} from "src/lib/Attestations.sol";
import {Cursor} from "src/lib/Cursor.sol";
import {TRANSFER_SPEC_VERSION} from "src/lib/TransferSpec.sol";
import {TransferSpecLib} from "src/lib/TransferSpecLib.sol";
import {BYTES4_BYTES, TRANSFER_SPEC_HOOK_DATA_OFFSET} from "src/lib/TransferSpecLib.sol";
import {TransferPayloadTestUtils} from "test/util/TransferPayloadTestUtils.sol";

contract AttestationSetTest is TransferPayloadTestUtils {
    using AttestationLib for bytes29;
    using AttestationLib for Cursor;

    /// @notice Helper to create a AttestationSet with two attestations and specified hook data.
    function _createAttestationSet(
        Attestation memory attestation1,
        Attestation memory attestation2,
        bytes memory hookData
    ) internal pure returns (AttestationSet memory) {
        attestation1.spec.version = TRANSFER_SPEC_VERSION;
        attestation1.spec.hookData = hookData;
        attestation2.spec.version = TRANSFER_SPEC_VERSION;
        attestation2.spec.hookData = hookData;

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = attestation1;
        attestations[1] = attestation2;

        return AttestationSet({attestations: attestations});
    }

    /// @notice Internal helper to verify all fields from encoded set bytes match the original struct.
    function _verifyEncodedSetFieldsAgainstStruct(
        bytes memory encodedAttestationSet,
        AttestationSet memory attestationSet
    ) internal pure {
        bytes29 setRef = AttestationLib._asAttestationOrSetView(encodedAttestationSet);
        uint32 numAttestations = setRef.getNumAttestations();
        assertEq(numAttestations, attestationSet.attestations.length, "Eq Fail: numAttestations");

        Cursor memory cursor = AttestationLib.cursor(encodedAttestationSet);
        uint32 i = 0;
        bytes29 attestationRef;
        while (!cursor.done) {
            attestationRef = cursor.next();
            _verifyAttestationFieldsFromView(attestationRef, attestationSet.attestations[i]);
            i++;
        }
        assertEq(i, numAttestations, "Loop iteration count mismatch");
    }

    // ===== Casting Tests =====

    function test_asAttestationOrSetView_successMintAttestationSet() public pure {
        (bytes memory data, uint40 expectedType) = _magic("circle.gateway.AttestationSet");
        bytes29 ref = AttestationLib._asAttestationOrSetView(data);
        assertEq(TypedMemView.typeOf(ref), expectedType);
        assertEq(bytes4(uint32(expectedType)), ATTESTATION_SET_MAGIC);
    }

    // ===== Validation Tests =====

    function test_validateAttestationSet_successFuzz(Attestation memory attestation1, Attestation memory attestation2)
        public
        pure
    {
        AttestationSet memory attestationSet = _createAttestationSet(attestation1, attestation2, LONG_HOOK_DATA);
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);
        AttestationLib._validate(encodedAttestationSet);
    }

    // ===== Validation Failures: Set Structure =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_encode_tooLongSet() public {
        // Create an empty AttestationSet
        Attestation[] memory attestations = new Attestation[](0);
        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});

        // Simulate an array with a size of `type(uint32).max + 1`
        uint256 maxSize = uint256(type(uint32).max);
        assembly {
            mstore(attestations, add(maxSize, 1))
        }

        // Expect it to revert since the array is too long
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.TransferPayloadSetTooManyElements.selector, maxSize));
        AttestationLib.encodeAttestationSet(attestationSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnDataTooShortForHeader() public {
        // Length is > magic (4) but < header (8)
        bytes memory shortData = abi.encodePacked(ATTESTATION_SET_MAGIC, hex"112233"); // 7 bytes
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetHeaderTooShort.selector,
            ATTESTATION_SET_ATTESTATIONS_OFFSET,
            shortData.length
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnEmptyAttestationsWithTrailingBytes() public {
        bytes memory encodedSetHeader = abi.encodePacked(
            ATTESTATION_SET_MAGIC,
            uint32(0) // numAttestations = 0
        );
        bytes memory trailingBytesData = bytes.concat(encodedSetHeader, hex"FFFF");

        uint256 expectedLength = encodedSetHeader.length;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetOverallLengthMismatch.selector, expectedLength, trailingBytesData.length
        );
        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(trailingBytesData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BeforeFirstAttestationHeader() public {
        // Set numAttestations = 1 but provide only the set header
        bytes memory encodedSetHeaderOnly = abi.encodePacked(
            ATTESTATION_SET_MAGIC,
            uint32(1) // numAttestations = 1
        ); // 8 bytes total
        uint32 elementIndex = 0;
        uint256 requiredOffset = ATTESTATION_SET_ATTESTATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_OFFSET;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetElementHeaderTooShort.selector,
            elementIndex,
            encodedSetHeaderOnly.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(encodedSetHeaderOnly);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_WithinFirstAttestationHeaderFuzz(
        Attestation memory attestation1
    ) public {
        // Set numAttestations = 1, provide set header + partial attestation header
        attestation1.spec.version = TRANSFER_SPEC_VERSION;
        attestation1.spec.hookData = new bytes(0);
        bytes memory encodedAttestation1 = AttestationLib.encodeAttestation(attestation1);

        bytes memory encodedSetHeader = abi.encodePacked(
            ATTESTATION_SET_MAGIC,
            uint32(1) // numAttestations = 1
        );

        // Truncate the first attestation header (e.g., provide only 10 bytes of it)
        uint256 partialAttestationHeaderLength = ATTESTATION_TRANSFER_SPEC_OFFSET - 1; // Ensure it's too short
        bytes memory partialAttestationData = new bytes(partialAttestationHeaderLength);
        for (uint256 i = 0; i < partialAttestationHeaderLength; i++) {
            partialAttestationData[i] = encodedAttestation1[i];
        }

        bytes memory truncatedData = bytes.concat(encodedSetHeader, partialAttestationData);

        uint32 elementIndex = 0;
        uint256 requiredOffset = ATTESTATION_SET_ATTESTATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_OFFSET;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetElementHeaderTooShort.selector,
            elementIndex,
            truncatedData.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BasedOnFirstAttestationSpecLengthFuzz(
        Attestation memory attestation1
    ) public {
        // Set numAttestations = 1, provide set header + full attestation header + partial spec
        attestation1.spec.version = TRANSFER_SPEC_VERSION;
        attestation1.spec.hookData = LONG_HOOK_DATA;
        bytes memory encodedAttestation1 = AttestationLib.encodeAttestation(attestation1);

        bytes memory encodedSetHeader = abi.encodePacked(
            ATTESTATION_SET_MAGIC,
            uint32(1) // numAttestations = 1
        );

        // Truncate the overall data just before the end of the first attestation's spec
        uint256 truncatedLength = encodedSetHeader.length + encodedAttestation1.length - 1;
        bytes memory truncatedData = new bytes(truncatedLength);
        bytes memory combined = bytes.concat(encodedSetHeader, encodedAttestation1);
        for (uint256 i = 0; i < truncatedLength; i++) {
            truncatedData[i] = combined[i];
        }

        uint32 elementIndex = 0;
        uint256 requiredOffset = encodedSetHeader.length + encodedAttestation1.length;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetElementTooShort.selector,
            elementIndex,
            truncatedData.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BetweenAttestationsFuzz(
        Attestation memory attestation1,
        Attestation memory attestation2
    ) public {
        // Set numAttestations = 2, provide set header + attestation1 + partial attestation2 header
        attestation1.spec.version = TRANSFER_SPEC_VERSION;
        attestation1.spec.hookData = new bytes(0);
        attestation2.spec.version = TRANSFER_SPEC_VERSION;
        attestation2.spec.hookData = new bytes(0);

        bytes memory encodedAttestation1 = AttestationLib.encodeAttestation(attestation1);
        bytes memory encodedAttestation2 = AttestationLib.encodeAttestation(attestation2);

        bytes memory encodedSetHeader = abi.encodePacked(
            ATTESTATION_SET_MAGIC,
            uint32(2) // numAttestations = 2
        );

        // Truncate data after attestation1 and partway into attestation2's header
        uint256 partialAttestation2HeaderLength = ATTESTATION_TRANSFER_SPEC_OFFSET - 1;
        bytes memory partialAttestation2Data = new bytes(partialAttestation2HeaderLength);
        for (uint256 i = 0; i < partialAttestation2HeaderLength; i++) {
            partialAttestation2Data[i] = encodedAttestation2[i];
        }

        bytes memory truncatedData = bytes.concat(encodedSetHeader, encodedAttestation1, partialAttestation2Data);

        uint32 elementIndex = 1;
        uint256 requiredOffset =
            ATTESTATION_SET_ATTESTATIONS_OFFSET + encodedAttestation1.length + ATTESTATION_TRANSFER_SPEC_OFFSET;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetElementHeaderTooShort.selector,
            elementIndex,
            truncatedData.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_WithinSecondAttestationFuzz(
        Attestation memory attestation1,
        Attestation memory attestation2
    ) public {
        // Set numAttestations = 2, provide set header + attestation1 + attestation2 header + partial attestation2 spec
        attestation1.spec.version = TRANSFER_SPEC_VERSION;
        attestation1.spec.hookData = new bytes(0);
        attestation2.spec.version = TRANSFER_SPEC_VERSION;
        attestation2.spec.hookData = new bytes(0);

        bytes memory encodedAttestation1 = AttestationLib.encodeAttestation(attestation1);
        bytes memory encodedAttestation2 = AttestationLib.encodeAttestation(attestation2);

        bytes memory encodedSetHeader = abi.encodePacked(
            ATTESTATION_SET_MAGIC,
            uint32(2) // numAttestations = 2
        );

        // Truncate data partway through the second attestation's spec
        uint256 truncatedLength = encodedSetHeader.length + encodedAttestation1.length + encodedAttestation2.length - 1;
        bytes memory truncatedData = new bytes(truncatedLength);
        bytes memory combined = bytes.concat(encodedSetHeader, encodedAttestation1, encodedAttestation2);
        for (uint256 i = 0; i < truncatedLength; i++) {
            truncatedData[i] = combined[i];
        }

        uint32 elementIndex = 1;
        uint256 requiredOffset = encodedSetHeader.length + encodedAttestation1.length + encodedAttestation2.length;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetElementTooShort.selector,
            elementIndex,
            truncatedData.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnTrailingBytes_AfterAllAttestationsFuzz(
        Attestation memory attestation1,
        Attestation memory attestation2
    ) public {
        attestation1.spec.version = TRANSFER_SPEC_VERSION;
        attestation1.spec.hookData = new bytes(0);
        attestation2.spec.version = TRANSFER_SPEC_VERSION;
        attestation2.spec.hookData = new bytes(0);
        AttestationSet memory attestationSet = _createAttestationSet(attestation1, attestation2, new bytes(0));
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);

        // Add trailing bytes
        bytes memory trailingBytesData = bytes.concat(encodedAttestationSet, hex"FFFF");

        uint256 expectedLength = encodedAttestationSet.length;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetOverallLengthMismatch.selector, expectedLength, trailingBytesData.length
        );
        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(trailingBytesData);
    }

    // ===== Validation Failures: Inner Attestation Consistency =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAttestation_CorruptedMagic_InFirstFuzz(
        Attestation memory attestation1,
        Attestation memory attestation2
    ) public {
        attestation1.spec.version = TRANSFER_SPEC_VERSION;
        attestation1.spec.hookData = new bytes(0);
        attestation2.spec.version = TRANSFER_SPEC_VERSION;
        attestation2.spec.hookData = new bytes(0);
        AttestationSet memory attestationSet = _createAttestationSet(attestation1, attestation2, new bytes(0));
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);

        // Corrupt the magic of the first attestation (at offset 8)
        encodedAttestationSet[ATTESTATION_SET_ATTESTATIONS_OFFSET] = hex"00";

        uint32 elementIndex = 0;
        bytes4 corruptedMagic;
        uint256 offset = ATTESTATION_SET_ATTESTATIONS_OFFSET + ATTESTATION_MAGIC_OFFSET;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedAttestationSet[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetInvalidElementMagic.selector, elementIndex, corruptedMagic
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(encodedAttestationSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAttestation_CorruptedMagic_InSecondFuzz(
        Attestation memory attestation1,
        Attestation memory attestation2
    ) public {
        attestation1.spec.version = TRANSFER_SPEC_VERSION;
        attestation1.spec.hookData = new bytes(0);
        attestation2.spec.version = TRANSFER_SPEC_VERSION;
        attestation2.spec.hookData = new bytes(0);
        AttestationSet memory attestationSet = _createAttestationSet(attestation1, attestation2, new bytes(0));
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);

        // Calculate offset of second attestation's magic
        bytes memory encodedAttestation1 = AttestationLib.encodeAttestation(attestationSet.attestations[0]);
        uint256 secondAttestationOffset = ATTESTATION_SET_ATTESTATIONS_OFFSET + encodedAttestation1.length;

        // Corrupt the magic of the second attestation
        encodedAttestationSet[secondAttestationOffset] = hex"00";

        uint32 elementIndex = 1;
        bytes4 corruptedMagic;
        uint256 offset = secondAttestationOffset + ATTESTATION_MAGIC_OFFSET;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedAttestationSet[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetInvalidElementMagic.selector, elementIndex, corruptedMagic
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(encodedAttestationSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAttestation_DeclaredSpecLengthTooSmallFuzz(Attestation memory attestation1)
        public
    {
        attestation1.spec.version = TRANSFER_SPEC_VERSION;
        attestation1.spec.hookData = LONG_HOOK_DATA;

        Attestation[] memory attestations = new Attestation[](1);
        attestations[0] = attestation1;
        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);

        bytes memory encodedAttestation1 = AttestationLib.encodeAttestation(attestation1);
        uint256 originalAttestationLength = encodedAttestation1.length;
        uint32 originalSpecLength = uint32(originalAttestationLength - ATTESTATION_TRANSFER_SPEC_OFFSET);
        uint32 originalHookDataLength = uint32(attestation1.spec.hookData.length);

        // Corrupt the outer Attestation's declared spec length (make it smaller)
        uint256 outerSpecLengthOffset = ATTESTATION_SET_ATTESTATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_LENGTH_OFFSET;
        uint32 invalidSpecLength = originalSpecLength - 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            encodedAttestationSet[outerSpecLengthOffset + i] = encodedInvalidLength[i];
        }

        // The failure occurs inside the TransferSpec validation because the outer corruption
        // leads to providing a truncated spec slice.
        uint256 expectedInnerSpecLengthBasedOnHookData = TRANSFER_SPEC_HOOK_DATA_OFFSET + originalHookDataLength;

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecOverallLengthMismatch.selector,
            expectedInnerSpecLengthBasedOnHookData, // Length expected by inner spec based on its hook data
            invalidSpecLength // Actual length of the spec slice provided due to outer corruption
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(encodedAttestationSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAttestation_DeclaredSpecLengthTooBigFuzz(Attestation memory attestation1)
        public
    {
        attestation1.spec.version = TRANSFER_SPEC_VERSION;
        attestation1.spec.hookData = LONG_HOOK_DATA;

        Attestation[] memory attestations = new Attestation[](1);
        attestations[0] = attestation1;
        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);

        bytes memory encodedAttestation1 = AttestationLib.encodeAttestation(attestation1);
        uint256 originalAttestationLength = encodedAttestation1.length;
        uint32 originalSpecLength = uint32(originalAttestationLength - ATTESTATION_TRANSFER_SPEC_OFFSET);

        // Corrupt the outer Attestation's declared spec length (make it larger)
        uint256 outerSpecLengthOffset = ATTESTATION_SET_ATTESTATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_LENGTH_OFFSET;
        uint32 invalidSpecLength = originalSpecLength + 1; // Make it larger than actual
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            encodedAttestationSet[outerSpecLengthOffset + i] = encodedInvalidLength[i];
        }

        // The failure occurs in the main validation loop when checking if the set data
        // is long enough to contain the attestation based on its inflated declared length.
        uint32 elementIndex = 0;
        uint256 requiredOffset =
            ATTESTATION_SET_ATTESTATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetElementTooShort.selector,
            elementIndex,
            encodedAttestationSet.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(encodedAttestationSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_CorruptedMagicFuzz(Attestation memory attestation1) public {
        attestation1.spec.version = TRANSFER_SPEC_VERSION;
        attestation1.spec.hookData = LONG_HOOK_DATA;

        Attestation[] memory attestations = new Attestation[](1);
        attestations[0] = attestation1;
        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);

        // Corrupt the inner TransferSpec magic within the first attestation
        uint256 innerSpecMagicOffset = ATTESTATION_SET_ATTESTATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_OFFSET;
        encodedAttestationSet[innerSpecMagicOffset] = hex"00";

        bytes4 corruptedMagic;
        uint256 offset = innerSpecMagicOffset;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedAttestationSet[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData =
            abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecMagic.selector, corruptedMagic);

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(encodedAttestationSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_InvalidVersionFuzz(
        Attestation memory attestation1,
        Attestation memory attestation2
    ) public {
        // The inner TransferSpec of the second attestation has an invalid version
        uint32 invalidVersion = TRANSFER_SPEC_VERSION + 1;
        attestation1.spec.version = TRANSFER_SPEC_VERSION;
        attestation1.spec.hookData = new bytes(0);
        attestation2.spec.version = invalidVersion;
        attestation2.spec.hookData = new bytes(0);

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = attestation1;
        attestations[1] = attestation2;
        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecVersion.selector, invalidVersion));
        AttestationLib._validate(encodedAttestationSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_DeclaredHookDataLengthTooBigFuzz(Attestation memory attestation1)
        public
    {
        attestation1.spec.version = TRANSFER_SPEC_VERSION;
        attestation1.spec.hookData = LONG_HOOK_DATA;

        Attestation[] memory attestations = new Attestation[](1);
        attestations[0] = attestation1;
        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);

        uint32 originalHookDataLength = uint32(attestation1.spec.hookData.length);
        uint256 encodedAttestation1Length = encodedAttestationSet.length - ATTESTATION_SET_ATTESTATIONS_OFFSET;
        uint32 actualInnerSpecLength = uint32(encodedAttestation1Length - ATTESTATION_TRANSFER_SPEC_OFFSET);

        uint32 specOffset = ATTESTATION_SET_ATTESTATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_OFFSET;
        (bytes memory corruptedEncodedAttestationSet, uint32 invalidHookDataLength) =
        _getCorruptedInnerSpecHookDataLengthData(
            encodedAttestationSet,
            specOffset,
            originalHookDataLength,
            true // makeLengthBigger = true
        );

        uint256 expectedInnerSpecLength = TRANSFER_SPEC_HOOK_DATA_OFFSET + invalidHookDataLength;

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecOverallLengthMismatch.selector, expectedInnerSpecLength, actualInnerSpecLength
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(corruptedEncodedAttestationSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_DeclaredHookDataLengthTooSmallFuzz(Attestation memory attestation1)
        public
    {
        attestation1.spec.version = TRANSFER_SPEC_VERSION;
        attestation1.spec.hookData = LONG_HOOK_DATA;

        Attestation[] memory attestations = new Attestation[](1);
        attestations[0] = attestation1;
        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);

        uint32 originalHookDataLength = uint32(attestation1.spec.hookData.length);
        uint256 encodedAttestation1Length = encodedAttestationSet.length - ATTESTATION_SET_ATTESTATIONS_OFFSET;
        uint32 actualInnerSpecLength = uint32(encodedAttestation1Length - ATTESTATION_TRANSFER_SPEC_OFFSET);

        uint32 specOffset = ATTESTATION_SET_ATTESTATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_OFFSET;
        (bytes memory corruptedEncodedAttestationSet, uint32 invalidHookDataLength) =
        _getCorruptedInnerSpecHookDataLengthData(
            encodedAttestationSet,
            specOffset,
            originalHookDataLength,
            false // makeLengthBigger = false
        );

        uint256 expectedInnerSpecLength = TRANSFER_SPEC_HOOK_DATA_OFFSET + invalidHookDataLength;

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecOverallLengthMismatch.selector, expectedInnerSpecLength, actualInnerSpecLength
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(corruptedEncodedAttestationSet);
    }

    // ===== Iteration Tests =====

    function test_cursor_emptySet() public pure {
        Attestation[] memory attestations = new Attestation[](0);
        AttestationSet memory set = AttestationSet({attestations: attestations});
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(set);
        Cursor memory cursor = AttestationLib.cursor(encodedAttestationSet);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenEmptySet() public {
        Attestation[] memory attestations = new Attestation[](0);
        AttestationSet memory set = AttestationSet({attestations: attestations});
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(set);
        Cursor memory cursor = AttestationLib.cursor(encodedAttestationSet);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    function test_cursor_singleAttestationInSetFuzz(Attestation memory attestation) public pure {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.hookData = LONG_HOOK_DATA;

        Attestation[] memory attestations = new Attestation[](1);
        attestations[0] = attestation;
        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);
        bytes29 setRef = AttestationLib._asAttestationOrSetView(encodedAttestationSet);

        Cursor memory cursor = AttestationLib.cursor(encodedAttestationSet);

        // Initial state
        assertEq(cursor.done, false);
        assertEq(cursor.memView, setRef);
        assertEq(cursor.offset, ATTESTATION_SET_ATTESTATIONS_OFFSET);
        assertEq(cursor.numElements, 1);
        assertEq(cursor.index, 0);

        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        uint256 expectedOffset = ATTESTATION_SET_ATTESTATIONS_OFFSET + encodedAttestation.length;

        // Advance cursor and verify first attestation
        bytes29 currentAttestation = cursor.next();
        _verifyAttestationFieldsFromView(currentAttestation, attestation);
        assertEq(cursor.memView, setRef);
        assertEq(cursor.offset, expectedOffset);
        assertEq(cursor.numElements, 1);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDone_SingleAttestationFuzz(Attestation memory attestation) public {
        attestation.spec.version = TRANSFER_SPEC_VERSION;
        attestation.spec.hookData = LONG_HOOK_DATA;
        Attestation[] memory attestations = new Attestation[](1);
        attestations[0] = attestation;
        AttestationSet memory set = AttestationSet({attestations: attestations});
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(set);

        Cursor memory cursor = AttestationLib.cursor(encodedAttestationSet);
        cursor.next();
        assertEq(cursor.done, true);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    function test_cursor_multipleAttestationsInSetFuzz(Attestation memory attestation1, Attestation memory attestation2)
        public
        pure
    {
        AttestationSet memory attestationSet = _createAttestationSet(attestation1, attestation2, LONG_HOOK_DATA);
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);
        bytes29 setRef = AttestationLib._asAttestationOrSetView(encodedAttestationSet);
        Cursor memory cursor = AttestationLib.cursor(encodedAttestationSet);

        // Initial state
        assertEq(cursor.done, false);
        assertEq(cursor.memView, setRef);
        assertEq(cursor.offset, ATTESTATION_SET_ATTESTATIONS_OFFSET);
        assertEq(cursor.numElements, 2);
        assertEq(cursor.index, 0);

        bytes memory encodedAttestation1 = AttestationLib.encodeAttestation(attestation1);
        uint256 expectedOffset = ATTESTATION_SET_ATTESTATIONS_OFFSET + encodedAttestation1.length;

        // Advance cursor and verify first attestation
        bytes29 currentAttestation = cursor.next();
        _verifyAttestationFieldsFromView(currentAttestation, attestation1);
        assertEq(cursor.memView, setRef);
        assertEq(cursor.offset, expectedOffset);
        assertEq(cursor.numElements, 2);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, false);

        bytes memory encodedAttestation2 = AttestationLib.encodeAttestation(attestation2);
        uint256 expectedUpdatedOffset = expectedOffset + encodedAttestation2.length;

        // Advance cursor and verify second attestation
        currentAttestation = cursor.next();
        _verifyAttestationFieldsFromView(currentAttestation, attestation2);
        assertEq(cursor.memView, setRef);
        assertEq(cursor.offset, expectedUpdatedOffset);
        assertEq(cursor.numElements, 2);
        assertEq(cursor.index, 2);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDone_MultipleAttestationsFuzz(
        Attestation memory attestation1,
        Attestation memory attestation2
    ) public {
        AttestationSet memory attestationSet = _createAttestationSet(attestation1, attestation2, LONG_HOOK_DATA);
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);
        Cursor memory cursor = AttestationLib.cursor(encodedAttestationSet);
        cursor.next();
        cursor.next();
        assertEq(cursor.done, true);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    // ===== Field Accessor / Set Iteration Tests =====

    function test_mintAttestationSet_readsAllFieldsEmptySet() public pure {
        Attestation[] memory attestations = new Attestation[](0);
        AttestationSet memory set = AttestationSet({attestations: attestations});
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(set);
        _verifyEncodedSetFieldsAgainstStruct(encodedAttestationSet, set);
    }

    function test_mintAttestationSet_readAllFieldsEmptyHookDataFuzz(
        Attestation memory attestation1,
        Attestation memory attestation2
    ) public pure {
        AttestationSet memory attestationSet = _createAttestationSet(attestation1, attestation2, new bytes(0));
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedAttestationSet, attestationSet);
    }

    function test_mintAttestationSet_readAllFieldsShortHookDataFuzz(
        Attestation memory attestation1,
        Attestation memory attestation2
    ) public pure {
        AttestationSet memory attestationSet = _createAttestationSet(attestation1, attestation2, SHORT_HOOK_DATA);
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedAttestationSet, attestationSet);
    }

    function test_mintAttestationSet_readAllFieldsLongHookDataFuzz(
        Attestation memory attestation1,
        Attestation memory attestation2
    ) public pure {
        AttestationSet memory attestationSet = _createAttestationSet(attestation1, attestation2, LONG_HOOK_DATA);
        bytes memory encodedAttestationSet = AttestationLib.encodeAttestationSet(attestationSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedAttestationSet, attestationSet);
    }
}
