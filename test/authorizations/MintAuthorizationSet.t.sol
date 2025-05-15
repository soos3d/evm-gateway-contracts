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
import {Cursor} from "src/lib/Cursor.sol";
import {AttestationLib} from "src/lib/AttestationLib.sol";
import {
    Attestation,
    AttestationSet,
    ATTESTATION_SET_MAGIC,
    ATTESTATION_MAGIC_OFFSET
} from "src/lib/Attestations.sol";
import {TRANSFER_SPEC_VERSION} from "src/lib/TransferSpec.sol";
import {TransferSpecLib} from "src/lib/TransferSpecLib.sol";
import {BYTES4_BYTES, TRANSFER_SPEC_METADATA_OFFSET} from "src/lib/TransferSpecLib.sol";
import {AuthorizationTestUtils} from "./AuthorizationTestUtils.sol";

contract AttestationSetTest is AuthorizationTestUtils {
    using AttestationLib for bytes29;
    using AttestationLib for Cursor;

    uint16 private constant ATTESTATION_SET_AUTHORIZATIONS_OFFSET = 8;

    /// @notice Helper to create a AttestationSet with two authorizations and specified metadata.
    function _createMintAuthSet(Attestation memory auth1, Attestation memory auth2, bytes memory metadata)
        internal
        pure
        returns (AttestationSet memory)
    {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = metadata;
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = metadata;

        Attestation[] memory authorizations = new Attestation[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;

        return AttestationSet({authorizations: authorizations});
    }

    /// @notice Internal helper to verify all fields from encoded set bytes match the original struct.
    function _verifyEncodedSetFieldsAgainstStruct(bytes memory encodedAuthSet, AttestationSet memory authSet)
        internal
        pure
    {
        bytes29 setRef = AttestationLib._asAuthOrSetView(encodedAuthSet);
        uint32 numAuths = setRef.getNumAuthorizations();
        assertEq(numAuths, authSet.authorizations.length, "Eq Fail: numAuths");

        Cursor memory cursor = AttestationLib.cursor(encodedAuthSet);
        uint32 i = 0;
        bytes29 authRef;
        while (!cursor.done) {
            authRef = cursor.next();
            _verifyAttestationFieldsFromView(authRef, authSet.authorizations[i]);
            i++;
        }
        assertEq(i, numAuths, "Loop iteration count mismatch");
    }

    // ===== Casting Tests =====

    function test_asAuthOrSetView_successMintAuthSet() public pure {
        (bytes memory data, uint40 expectedType) = _magic("circle.gateway.AttestationSet");
        bytes29 ref = AttestationLib._asAuthOrSetView(data);
        assertEq(TypedMemView.typeOf(ref), expectedType);
        assertEq(bytes4(uint32(expectedType)), ATTESTATION_SET_MAGIC);
    }

    // ===== Validation Tests =====

    function test_validateAttestationSet_successFuzz(
        Attestation memory auth1,
        Attestation memory auth2
    ) public pure {
        AttestationSet memory authSet = _createMintAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);
        AttestationLib._validate(encodedAuthSet);
    }

    // ===== Validation Failures: Set Structure =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_encode_tooLongSet() public {
        // Create an empty AttestationSet
        Attestation[] memory auths = new Attestation[](0);
        AttestationSet memory authSet = AttestationSet({authorizations: auths});

        // Simulate an array with a size of `type(uint32).max + 1`
        uint256 maxSize = uint256(type(uint32).max);
        assembly {
            mstore(auths, add(maxSize, 1))
        }

        // Expect it to revert since the array is too long
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.AuthorizationSetTooManyElements.selector, maxSize));
        AttestationLib.encodeAttestationSet(authSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnDataTooShortForHeader() public {
        // Length is > magic (4) but < header (8)
        bytes memory shortData = abi.encodePacked(ATTESTATION_SET_MAGIC, hex"112233"); // 7 bytes
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetHeaderTooShort.selector,
            ATTESTATION_SET_AUTHORIZATIONS_OFFSET,
            shortData.length
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnEmptyAuthorizationsWithTrailingBytes() public {
        bytes memory encodedSetHeader = abi.encodePacked(
            ATTESTATION_SET_MAGIC,
            uint32(0) // numAuthorizations = 0
        );
        bytes memory trailingBytesData = bytes.concat(encodedSetHeader, hex"FFFF");

        uint256 expectedLength = encodedSetHeader.length;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetOverallLengthMismatch.selector, expectedLength, trailingBytesData.length
        );
        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(trailingBytesData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BeforeFirstAuthHeader() public {
        // Set numAuthorizations = 1 but provide only the set header
        bytes memory encodedSetHeaderOnly = abi.encodePacked(
            ATTESTATION_SET_MAGIC,
            uint32(1) // numAuthorizations = 1
        ); // 8 bytes total
        uint32 elementIndex = 0;
        uint256 requiredOffset = ATTESTATION_SET_AUTHORIZATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_OFFSET;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetElementHeaderTooShort.selector,
            elementIndex,
            encodedSetHeaderOnly.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(encodedSetHeaderOnly);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_WithinFirstAuthHeaderFuzz(Attestation memory auth1)
        public
    {
        // Set numAuthorizations = 1, provide set header + partial auth header
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        bytes memory encodedAuth1 = AttestationLib.encodeAttestation(auth1);

        bytes memory encodedSetHeader = abi.encodePacked(
            ATTESTATION_SET_MAGIC,
            uint32(1) // numAuthorizations = 1
        );

        // Truncate the first auth header (e.g., provide only 10 bytes of it)
        uint256 partialAuthHeaderLength = ATTESTATION_TRANSFER_SPEC_OFFSET - 1; // Ensure it's too short
        bytes memory partialAuthData = new bytes(partialAuthHeaderLength);
        for (uint256 i = 0; i < partialAuthHeaderLength; i++) {
            partialAuthData[i] = encodedAuth1[i];
        }

        bytes memory truncatedData = bytes.concat(encodedSetHeader, partialAuthData);

        uint32 elementIndex = 0;
        uint256 requiredOffset = ATTESTATION_SET_AUTHORIZATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_OFFSET;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetElementHeaderTooShort.selector,
            elementIndex,
            truncatedData.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BasedOnFirstAuthSpecLengthFuzz(
        Attestation memory auth1
    ) public {
        // Set numAuthorizations = 1, provide set header + full auth header + partial spec
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth1 = AttestationLib.encodeAttestation(auth1);

        bytes memory encodedSetHeader = abi.encodePacked(
            ATTESTATION_SET_MAGIC,
            uint32(1) // numAuthorizations = 1
        );

        // Truncate the overall data just before the end of the first auth's spec
        uint256 truncatedLength = encodedSetHeader.length + encodedAuth1.length - 1;
        bytes memory truncatedData = new bytes(truncatedLength);
        bytes memory combined = bytes.concat(encodedSetHeader, encodedAuth1);
        for (uint256 i = 0; i < truncatedLength; i++) {
            truncatedData[i] = combined[i];
        }

        uint32 elementIndex = 0;
        uint256 requiredOffset = encodedSetHeader.length + encodedAuth1.length;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetElementTooShort.selector, elementIndex, truncatedData.length, requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BetweenAuthorizationsFuzz(
        Attestation memory auth1,
        Attestation memory auth2
    ) public {
        // Set numAuthorizations = 2, provide set header + auth1 + partial auth2 header
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);

        bytes memory encodedAuth1 = AttestationLib.encodeAttestation(auth1);
        bytes memory encodedAuth2 = AttestationLib.encodeAttestation(auth2);

        bytes memory encodedSetHeader = abi.encodePacked(
            ATTESTATION_SET_MAGIC,
            uint32(2) // numAuthorizations = 2
        );

        // Truncate data after auth1 and partway into auth2's header
        uint256 partialAuth2HeaderLength = ATTESTATION_TRANSFER_SPEC_OFFSET - 1;
        bytes memory partialAuth2Data = new bytes(partialAuth2HeaderLength);
        for (uint256 i = 0; i < partialAuth2HeaderLength; i++) {
            partialAuth2Data[i] = encodedAuth2[i];
        }

        bytes memory truncatedData = bytes.concat(encodedSetHeader, encodedAuth1, partialAuth2Data);

        uint32 elementIndex = 1;
        uint256 requiredOffset =
            ATTESTATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth1.length + ATTESTATION_TRANSFER_SPEC_OFFSET;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetElementHeaderTooShort.selector,
            elementIndex,
            truncatedData.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_WithinSecondAuthorizationFuzz(
        Attestation memory auth1,
        Attestation memory auth2
    ) public {
        // Set numAuthorizations = 2, provide set header + auth1 + auth2 header + partial auth2 spec
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);

        bytes memory encodedAuth1 = AttestationLib.encodeAttestation(auth1);
        bytes memory encodedAuth2 = AttestationLib.encodeAttestation(auth2);

        bytes memory encodedSetHeader = abi.encodePacked(
            ATTESTATION_SET_MAGIC,
            uint32(2) // numAuthorizations = 2
        );

        // Truncate data partway through the second authorization's spec
        uint256 truncatedLength = encodedSetHeader.length + encodedAuth1.length + encodedAuth2.length - 1;
        bytes memory truncatedData = new bytes(truncatedLength);
        bytes memory combined = bytes.concat(encodedSetHeader, encodedAuth1, encodedAuth2);
        for (uint256 i = 0; i < truncatedLength; i++) {
            truncatedData[i] = combined[i];
        }

        uint32 elementIndex = 1;
        uint256 requiredOffset = encodedSetHeader.length + encodedAuth1.length + encodedAuth2.length;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetElementTooShort.selector, elementIndex, truncatedData.length, requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnTrailingBytes_AfterAllAuthsFuzz(
        Attestation memory auth1,
        Attestation memory auth2
    ) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        AttestationSet memory authSet = _createMintAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);

        // Add trailing bytes
        bytes memory trailingBytesData = bytes.concat(encodedAuthSet, hex"FFFF");

        uint256 expectedLength = encodedAuthSet.length;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetOverallLengthMismatch.selector, expectedLength, trailingBytesData.length
        );
        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(trailingBytesData);
    }

    // ===== Validation Failures: Inner Authorization Consistency =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAuth_CorruptedMagic_InFirstFuzz(
        Attestation memory auth1,
        Attestation memory auth2
    ) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        AttestationSet memory authSet = _createMintAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);

        // Corrupt the magic of the first authorization (at offset 8)
        encodedAuthSet[ATTESTATION_SET_AUTHORIZATIONS_OFFSET] = hex"00";

        uint32 elementIndex = 0;
        bytes4 corruptedMagic;
        uint256 offset = ATTESTATION_SET_AUTHORIZATIONS_OFFSET + ATTESTATION_MAGIC_OFFSET;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedAuthSet[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetInvalidElementMagic.selector, elementIndex, corruptedMagic
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAuth_CorruptedMagic_InSecondFuzz(
        Attestation memory auth1,
        Attestation memory auth2
    ) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        AttestationSet memory authSet = _createMintAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);

        // Calculate offset of second authorization's magic
        bytes memory encodedAuth1 = AttestationLib.encodeAttestation(authSet.authorizations[0]);
        uint256 secondAuthOffset = ATTESTATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth1.length;

        // Corrupt the magic of the second authorization
        encodedAuthSet[secondAuthOffset] = hex"00";

        uint32 elementIndex = 1;
        bytes4 corruptedMagic;
        uint256 offset = secondAuthOffset + ATTESTATION_MAGIC_OFFSET;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedAuthSet[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetInvalidElementMagic.selector, elementIndex, corruptedMagic
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAuth_DeclaredSpecLengthTooSmallFuzz(Attestation memory auth1)
        public
    {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        Attestation[] memory authorizations = new Attestation[](1);
        authorizations[0] = auth1;
        AttestationSet memory authSet = AttestationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);

        bytes memory encodedAuth1 = AttestationLib.encodeAttestation(auth1);
        uint256 originalAuthLength = encodedAuth1.length;
        uint32 originalSpecLength = uint32(originalAuthLength - ATTESTATION_TRANSFER_SPEC_OFFSET);
        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);

        // Corrupt the outer Attestation's declared spec length (make it smaller)
        uint256 outerSpecLengthOffset =
            ATTESTATION_SET_AUTHORIZATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_LENGTH_OFFSET;
        uint32 invalidSpecLength = originalSpecLength - 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            encodedAuthSet[outerSpecLengthOffset + i] = encodedInvalidLength[i];
        }

        // The failure occurs inside the TransferSpec validation because the outer corruption
        // leads to providing a truncated spec slice.
        uint256 expectedInnerSpecLengthBasedOnMetadata = TRANSFER_SPEC_METADATA_OFFSET + originalMetadataLength;

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecOverallLengthMismatch.selector,
            expectedInnerSpecLengthBasedOnMetadata, // Length expected by inner spec based on its metadata
            invalidSpecLength // Actual length of the spec slice provided due to outer corruption
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAuth_DeclaredSpecLengthTooBigFuzz(Attestation memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        Attestation[] memory authorizations = new Attestation[](1);
        authorizations[0] = auth1;
        AttestationSet memory authSet = AttestationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);

        bytes memory encodedAuth1 = AttestationLib.encodeAttestation(auth1);
        uint256 originalAuthLength = encodedAuth1.length;
        uint32 originalSpecLength = uint32(originalAuthLength - ATTESTATION_TRANSFER_SPEC_OFFSET);

        // Corrupt the outer Attestation's declared spec length (make it larger)
        uint256 outerSpecLengthOffset =
            ATTESTATION_SET_AUTHORIZATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_LENGTH_OFFSET;
        uint32 invalidSpecLength = originalSpecLength + 1; // Make it larger than actual
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            encodedAuthSet[outerSpecLengthOffset + i] = encodedInvalidLength[i];
        }

        // The failure occurs in the main validation loop when checking if the set data
        // is long enough to contain the authorization based on its inflated declared length.
        uint32 elementIndex = 0;
        uint256 requiredOffset =
            ATTESTATION_SET_AUTHORIZATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetElementTooShort.selector,
            elementIndex,
            encodedAuthSet.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_CorruptedMagicFuzz(Attestation memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        Attestation[] memory authorizations = new Attestation[](1);
        authorizations[0] = auth1;
        AttestationSet memory authSet = AttestationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);

        // Corrupt the inner TransferSpec magic within the first authorization
        uint256 innerSpecMagicOffset =
            ATTESTATION_SET_AUTHORIZATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_OFFSET;
        encodedAuthSet[innerSpecMagicOffset] = hex"00";

        bytes4 corruptedMagic;
        uint256 offset = innerSpecMagicOffset;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedAuthSet[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData =
            abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecMagic.selector, corruptedMagic);

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_InvalidVersionFuzz(
        Attestation memory auth1,
        Attestation memory auth2
    ) public {
        // The inner TransferSpec of the second auth has an invalid version
        uint32 invalidVersion = TRANSFER_SPEC_VERSION + 1;
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = invalidVersion;
        auth2.spec.metadata = new bytes(0);

        Attestation[] memory authorizations = new Attestation[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;
        AttestationSet memory authSet = AttestationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecVersion.selector, invalidVersion));
        AttestationLib._validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_DeclaredMetadataLengthTooBigFuzz(Attestation memory auth1)
        public
    {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        Attestation[] memory authorizations = new Attestation[](1);
        authorizations[0] = auth1;
        AttestationSet memory authSet = AttestationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);

        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);
        uint256 encodedAuth1Length = encodedAuthSet.length - ATTESTATION_SET_AUTHORIZATIONS_OFFSET;
        uint32 actualInnerSpecLength = uint32(encodedAuth1Length - ATTESTATION_TRANSFER_SPEC_OFFSET);

        uint32 specOffset = ATTESTATION_SET_AUTHORIZATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_OFFSET;
        (bytes memory corruptedEncodedAuthSet, uint32 invalidMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedAuthSet,
            specOffset,
            originalMetadataLength,
            true // makeLengthBigger = true
        );

        uint256 expectedInnerSpecLength = TRANSFER_SPEC_METADATA_OFFSET + invalidMetadataLength;

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecOverallLengthMismatch.selector, expectedInnerSpecLength, actualInnerSpecLength
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(corruptedEncodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_DeclaredMetadataLengthTooSmallFuzz(Attestation memory auth1)
        public
    {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        Attestation[] memory authorizations = new Attestation[](1);
        authorizations[0] = auth1;
        AttestationSet memory authSet = AttestationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);

        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);
        uint256 encodedAuth1Length = encodedAuthSet.length - ATTESTATION_SET_AUTHORIZATIONS_OFFSET;
        uint32 actualInnerSpecLength = uint32(encodedAuth1Length - ATTESTATION_TRANSFER_SPEC_OFFSET);

        uint32 specOffset = ATTESTATION_SET_AUTHORIZATIONS_OFFSET + ATTESTATION_TRANSFER_SPEC_OFFSET;
        (bytes memory corruptedEncodedAuthSet, uint32 invalidMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedAuthSet,
            specOffset,
            originalMetadataLength,
            false // makeLengthBigger = false
        );

        uint256 expectedInnerSpecLength = TRANSFER_SPEC_METADATA_OFFSET + invalidMetadataLength;

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecOverallLengthMismatch.selector, expectedInnerSpecLength, actualInnerSpecLength
        );

        vm.expectRevert(expectedRevertData);
        AttestationLib._validate(corruptedEncodedAuthSet);
    }

    // ===== Iteration Tests =====

    function test_cursor_emptySet() public pure {
        Attestation[] memory authorizations = new Attestation[](0);
        AttestationSet memory set = AttestationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(set);
        Cursor memory cursor = AttestationLib.cursor(encodedAuthSet);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenEmptySet() public {
        Attestation[] memory authorizations = new Attestation[](0);
        AttestationSet memory set = AttestationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(set);
        Cursor memory cursor = AttestationLib.cursor(encodedAuthSet);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    function test_cursor_singleAuthInSetFuzz(Attestation memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;

        Attestation[] memory authorizations = new Attestation[](1);
        authorizations[0] = auth;
        AttestationSet memory authSet = AttestationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);
        bytes29 setRef = AttestationLib._asAuthOrSetView(encodedAuthSet);

        Cursor memory cursor = AttestationLib.cursor(encodedAuthSet);

        // Initial state
        assertEq(cursor.done, false);
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, ATTESTATION_SET_AUTHORIZATIONS_OFFSET);
        assertEq(cursor.numAuths, 1);
        assertEq(cursor.index, 0);

        bytes memory encodedAuth = AttestationLib.encodeAttestation(auth);
        uint256 expectedOffset = ATTESTATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth.length;

        // Advance cursor and verify first auth
        bytes29 currentAuth = cursor.next();
        _verifyAttestationFieldsFromView(currentAuth, auth);
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, expectedOffset);
        assertEq(cursor.numAuths, 1);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDone_SingleAuthFuzz(Attestation memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        Attestation[] memory authorizations = new Attestation[](1);
        authorizations[0] = auth;
        AttestationSet memory set = AttestationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(set);

        Cursor memory cursor = AttestationLib.cursor(encodedAuthSet);
        cursor.next();
        assertEq(cursor.done, true);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    function test_cursor_multipleAuthsInSetFuzz(Attestation memory auth1, Attestation memory auth2)
        public
        pure
    {
        AttestationSet memory authSet = _createMintAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);
        bytes29 setRef = AttestationLib._asAuthOrSetView(encodedAuthSet);
        Cursor memory cursor = AttestationLib.cursor(encodedAuthSet);

        // Initial state
        assertEq(cursor.done, false);
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, ATTESTATION_SET_AUTHORIZATIONS_OFFSET);
        assertEq(cursor.numAuths, 2);
        assertEq(cursor.index, 0);

        bytes memory encodedAuth1 = AttestationLib.encodeAttestation(auth1);
        uint256 expectedOffset = ATTESTATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth1.length;

        // Advance cursor and verify first auth
        bytes29 currentAuth = cursor.next();
        _verifyAttestationFieldsFromView(currentAuth, auth1);
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, expectedOffset);
        assertEq(cursor.numAuths, 2);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, false);

        bytes memory encodedAuth2 = AttestationLib.encodeAttestation(auth2);
        uint256 expectedUpdatedOffset = expectedOffset + encodedAuth2.length;

        // Advance cursor and verify second auth
        currentAuth = cursor.next();
        _verifyAttestationFieldsFromView(currentAuth, auth2);
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, expectedUpdatedOffset);
        assertEq(cursor.numAuths, 2);
        assertEq(cursor.index, 2);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDone_MultipleAuthsFuzz(
        Attestation memory auth1,
        Attestation memory auth2
    ) public {
        AttestationSet memory authSet = _createMintAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);
        Cursor memory cursor = AttestationLib.cursor(encodedAuthSet);
        cursor.next();
        cursor.next();
        assertEq(cursor.done, true);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    // ===== Field Accessor / Set Iteration Tests =====

    function test_mintAuthorizationSet_readsAllFieldsEmptySet() public pure {
        Attestation[] memory authorizations = new Attestation[](0);
        AttestationSet memory set = AttestationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(set);
        _verifyEncodedSetFieldsAgainstStruct(encodedAuthSet, set);
    }

    function test_mintAuthorizationSet_readAllFieldsEmptyMetadataFuzz(
        Attestation memory auth1,
        Attestation memory auth2
    ) public pure {
        AttestationSet memory authSet = _createMintAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedAuthSet, authSet);
    }

    function test_mintAuthorizationSet_readAllFieldsShortMetadataFuzz(
        Attestation memory auth1,
        Attestation memory auth2
    ) public pure {
        AttestationSet memory authSet = _createMintAuthSet(auth1, auth2, SHORT_METADATA);
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedAuthSet, authSet);
    }

    function test_mintAuthorizationSet_readAllFieldsLongMetadataFuzz(
        Attestation memory auth1,
        Attestation memory auth2
    ) public pure {
        AttestationSet memory authSet = _createMintAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = AttestationLib.encodeAttestationSet(authSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedAuthSet, authSet);
    }
}
