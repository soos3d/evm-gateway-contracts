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

import {AuthorizationTestUtils} from "./AuthorizationTestUtils.sol";
import {TRANSFER_SPEC_VERSION} from "src/lib/authorizations/TransferSpec.sol";
import {TransferSpecLib} from "src/lib/authorizations/TransferSpecLib.sol";
import {BYTES4_BYTES, TRANSFER_SPEC_METADATA_OFFSET} from "src/lib/authorizations/TransferSpecLib.sol";
import {
    MintAuthorization,
    MintAuthorizationSet,
    MINT_AUTHORIZATION_SET_MAGIC,
    MINT_AUTHORIZATION_MAGIC_OFFSET
} from "src/lib/authorizations/MintAuthorizations.sol";
import {MintAuthorizationLib} from "src/lib/authorizations/MintAuthorizationLib.sol";
import {AuthorizationCursor} from "src/lib/authorizations/AuthorizationCursor.sol";
import {TypedMemView} from "@memview-sol/TypedMemView.sol";

contract MintAuthorizationSetTest is AuthorizationTestUtils {
    using MintAuthorizationLib for bytes29;
    using MintAuthorizationLib for AuthorizationCursor;

    uint16 private constant MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET = 8;

    /// @notice Helper to create a MintAuthorizationSet with two authorizations and specified metadata.
    function _createMintAuthSet(MintAuthorization memory auth1, MintAuthorization memory auth2, bytes memory metadata)
        internal
        pure
        returns (MintAuthorizationSet memory)
    {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = metadata;
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = metadata;

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;

        return MintAuthorizationSet({authorizations: authorizations});
    }

    /// @notice Internal helper to verify all fields from encoded set bytes match the original struct.
    function _verifyEncodedSetFieldsAgainstStruct(bytes memory encodedAuthSet, MintAuthorizationSet memory authSet)
        internal
        pure
    {
        bytes29 setRef = MintAuthorizationLib._asAuthOrSetView(encodedAuthSet);
        uint32 numAuths = setRef.getNumAuthorizations();
        assertEq(numAuths, authSet.authorizations.length, "Eq Fail: numAuths");

        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(encodedAuthSet);
        uint32 i = 0;
        while (!cursor.done) {
            bytes29 authRef;
            (authRef, cursor) = cursor.next();
            _verifyMintAuthorizationFieldsFromView(authRef, authSet.authorizations[i]);
            i++;
        }
        assertEq(i, numAuths, "Loop iteration count mismatch");
    }

    // ===== Casting Tests =====

    function test_asAuthOrSetView_successMintAuthSet() public pure {
        (bytes memory data, uint40 expectedType) = _magic("circle.gateway.MintAuthorizationSet");
        bytes29 ref = MintAuthorizationLib._asAuthOrSetView(data);
        assertEq(TypedMemView.typeOf(ref), expectedType);
        assertEq(bytes4(uint32(expectedType)), MINT_AUTHORIZATION_SET_MAGIC);
    }

    // ===== Validation Tests =====

    function test_validateMintAuthorizationSet_successFuzz(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2
    ) public pure {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);
        MintAuthorizationLib._validate(encodedAuthSet);
    }

    // ===== Validation Failures: Set Structure =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnDataTooShortForHeader() public {
        // Length is > magic (4) but < header (8)
        bytes memory shortData = abi.encodePacked(MINT_AUTHORIZATION_SET_MAGIC, hex"112233"); // 7 bytes
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetHeaderTooShort.selector,
            MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET,
            shortData.length
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnEmptyAuthorizationsWithTrailingBytes() public {
        bytes memory encodedSetHeader = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
            uint32(0) // numAuthorizations = 0
        );
        bytes memory trailingBytesData = bytes.concat(encodedSetHeader, hex"FFFF");

        uint256 expectedLength = encodedSetHeader.length;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetOverallLengthMismatch.selector, expectedLength, trailingBytesData.length
        );
        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(trailingBytesData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BeforeFirstAuthHeader() public {
        // Set numAuthorizations = 1 but provide only the set header
        bytes memory encodedSetHeaderOnly = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
            uint32(1) // numAuthorizations = 1
        ); // 8 bytes total
        uint32 elementIndex = 0;
        uint256 requiredOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetElementHeaderTooShort.selector,
            elementIndex,
            encodedSetHeaderOnly.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(encodedSetHeaderOnly);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_WithinFirstAuthHeaderFuzz(MintAuthorization memory auth1)
        public
    {
        // Set numAuthorizations = 1, provide set header + partial auth header
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        bytes memory encodedAuth1 = MintAuthorizationLib.encodeMintAuthorization(auth1);

        bytes memory encodedSetHeader = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
            uint32(1) // numAuthorizations = 1
        );

        // Truncate the first auth header (e.g., provide only 10 bytes of it)
        uint256 partialAuthHeaderLength = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET - 1; // Ensure it's too short
        bytes memory partialAuthData = new bytes(partialAuthHeaderLength);
        for (uint256 i = 0; i < partialAuthHeaderLength; i++) {
            partialAuthData[i] = encodedAuth1[i];
        }

        bytes memory truncatedData = bytes.concat(encodedSetHeader, partialAuthData);

        uint32 elementIndex = 0;
        uint256 requiredOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetElementHeaderTooShort.selector,
            elementIndex,
            truncatedData.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BasedOnFirstAuthSpecLengthFuzz(
        MintAuthorization memory auth1
    ) public {
        // Set numAuthorizations = 1, provide set header + full auth header + partial spec
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth1 = MintAuthorizationLib.encodeMintAuthorization(auth1);

        bytes memory encodedSetHeader = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
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
        MintAuthorizationLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BetweenAuthorizationsFuzz(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2
    ) public {
        // Set numAuthorizations = 2, provide set header + auth1 + partial auth2 header
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);

        bytes memory encodedAuth1 = MintAuthorizationLib.encodeMintAuthorization(auth1);
        bytes memory encodedAuth2 = MintAuthorizationLib.encodeMintAuthorization(auth2);

        bytes memory encodedSetHeader = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
            uint32(2) // numAuthorizations = 2
        );

        // Truncate data after auth1 and partway into auth2's header
        uint256 partialAuth2HeaderLength = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET - 1;
        bytes memory partialAuth2Data = new bytes(partialAuth2HeaderLength);
        for (uint256 i = 0; i < partialAuth2HeaderLength; i++) {
            partialAuth2Data[i] = encodedAuth2[i];
        }

        bytes memory truncatedData = bytes.concat(encodedSetHeader, encodedAuth1, partialAuth2Data);

        uint32 elementIndex = 1;
        uint256 requiredOffset =
            MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth1.length + MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetElementHeaderTooShort.selector,
            elementIndex,
            truncatedData.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_WithinSecondAuthorizationFuzz(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2
    ) public {
        // Set numAuthorizations = 2, provide set header + auth1 + auth2 header + partial auth2 spec
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);

        bytes memory encodedAuth1 = MintAuthorizationLib.encodeMintAuthorization(auth1);
        bytes memory encodedAuth2 = MintAuthorizationLib.encodeMintAuthorization(auth2);

        bytes memory encodedSetHeader = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
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
        MintAuthorizationLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnTrailingBytes_AfterAllAuthsFuzz(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2
    ) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        // Add trailing bytes
        bytes memory trailingBytesData = bytes.concat(encodedAuthSet, hex"FFFF");

        uint256 expectedLength = encodedAuthSet.length;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetOverallLengthMismatch.selector, expectedLength, trailingBytesData.length
        );
        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(trailingBytesData);
    }

    // ===== Validation Failures: Inner Authorization Consistency =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAuth_CorruptedMagic_InFirstFuzz(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2
    ) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        // Corrupt the magic of the first authorization (at offset 8)
        encodedAuthSet[MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET] = hex"FF";

        uint32 elementIndex = 0;
        bytes4 corruptedMagic;
        uint256 offset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_MAGIC_OFFSET;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedAuthSet[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetInvalidElementMagic.selector, elementIndex, corruptedMagic
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAuth_CorruptedMagic_InSecondFuzz(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2
    ) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        // Calculate offset of second authorization's magic
        bytes memory encodedAuth1 = MintAuthorizationLib.encodeMintAuthorization(authSet.authorizations[0]);
        uint256 secondAuthOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth1.length;

        // Corrupt the magic of the second authorization
        encodedAuthSet[secondAuthOffset] = hex"FF";

        uint32 elementIndex = 1;
        bytes4 corruptedMagic;
        uint256 offset = secondAuthOffset + MINT_AUTHORIZATION_MAGIC_OFFSET;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedAuthSet[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetInvalidElementMagic.selector, elementIndex, corruptedMagic
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAuth_DeclaredSpecLengthTooSmallFuzz(MintAuthorization memory auth1)
        public
    {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        MintAuthorization[] memory authorizations = new MintAuthorization[](1);
        authorizations[0] = auth1;
        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        bytes memory encodedAuth1 = MintAuthorizationLib.encodeMintAuthorization(auth1);
        uint256 originalAuthLength = encodedAuth1.length;
        uint32 originalSpecLength = uint32(originalAuthLength - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET);
        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);

        // Corrupt the outer MintAuthorization's declared spec length (make it smaller)
        uint256 outerSpecLengthOffset =
            MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET;
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
        MintAuthorizationLib._validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAuth_DeclaredSpecLengthTooBigFuzz(MintAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        MintAuthorization[] memory authorizations = new MintAuthorization[](1);
        authorizations[0] = auth1;
        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        bytes memory encodedAuth1 = MintAuthorizationLib.encodeMintAuthorization(auth1);
        uint256 originalAuthLength = encodedAuth1.length;
        uint32 originalSpecLength = uint32(originalAuthLength - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        // Corrupt the outer MintAuthorization's declared spec length (make it larger)
        uint256 outerSpecLengthOffset =
            MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET;
        uint32 invalidSpecLength = originalSpecLength + 1; // Make it larger than actual
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            encodedAuthSet[outerSpecLengthOffset + i] = encodedInvalidLength[i];
        }

        // The failure occurs in the main validation loop when checking if the set data
        // is long enough to contain the authorization based on its inflated declared length.
        uint32 elementIndex = 0;
        uint256 requiredOffset =
            MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationSetElementTooShort.selector,
            elementIndex,
            encodedAuthSet.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_CorruptedMagicFuzz(MintAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        MintAuthorization[] memory authorizations = new MintAuthorization[](1);
        authorizations[0] = auth1;
        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        // Corrupt the inner TransferSpec magic within the first authorization
        uint256 innerSpecMagicOffset =
            MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
        encodedAuthSet[innerSpecMagicOffset] = hex"FF";

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
        MintAuthorizationLib._validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_InvalidVersionFuzz(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2
    ) public {
        // The inner TransferSpec of the second auth has an invalid version
        uint32 invalidVersion = TRANSFER_SPEC_VERSION + 1;
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = invalidVersion;
        auth2.spec.metadata = new bytes(0);

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;
        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        vm.expectRevert(
            abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecVersion.selector, invalidVersion)
        );
        MintAuthorizationLib._validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_DeclaredMetadataLengthTooBigFuzz(MintAuthorization memory auth1)
        public
    {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        MintAuthorization[] memory authorizations = new MintAuthorization[](1);
        authorizations[0] = auth1;
        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);
        uint256 encodedAuth1Length = encodedAuthSet.length - MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;
        uint32 actualInnerSpecLength = uint32(encodedAuth1Length - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        uint32 specOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
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
        MintAuthorizationLib._validate(corruptedEncodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_DeclaredMetadataLengthTooSmallFuzz(MintAuthorization memory auth1)
        public
    {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        MintAuthorization[] memory authorizations = new MintAuthorization[](1);
        authorizations[0] = auth1;
        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);
        uint256 encodedAuth1Length = encodedAuthSet.length - MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;
        uint32 actualInnerSpecLength = uint32(encodedAuth1Length - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        uint32 specOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
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
        MintAuthorizationLib._validate(corruptedEncodedAuthSet);
    }

    // ===== Iteration Tests =====

    function test_cursor_emptySet() public pure {
        MintAuthorization[] memory authorizations = new MintAuthorization[](0);
        MintAuthorizationSet memory set = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(set);
        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(encodedAuthSet);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenEmptySet() public {
        MintAuthorization[] memory authorizations = new MintAuthorization[](0);
        MintAuthorizationSet memory set = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(set);
        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(encodedAuthSet);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    function test_cursor_singleAuthInSetFuzz(MintAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;

        MintAuthorization[] memory authorizations = new MintAuthorization[](1);
        authorizations[0] = auth;
        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);
        bytes29 setRef = MintAuthorizationLib._asAuthOrSetView(encodedAuthSet);

        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(encodedAuthSet);

        // Initial state
        assertEq(cursor.done, false);
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET);
        assertEq(cursor.numAuths, 1);
        assertEq(cursor.index, 0);

        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        uint256 expectedOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth.length;

        // Advance cursor and verify first auth
        bytes29 currentAuth;
        (currentAuth, cursor) = cursor.next();
        _verifyMintAuthorizationFieldsFromView(currentAuth, auth);
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, expectedOffset);
        assertEq(cursor.numAuths, 1);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDone_SingleAuthFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        MintAuthorization[] memory authorizations = new MintAuthorization[](1);
        authorizations[0] = auth;
        MintAuthorizationSet memory set = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(set);

        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(encodedAuthSet);
        bytes29 currentAuth;
        (currentAuth, cursor) = cursor.next();
        assertEq(cursor.done, true);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    function test_cursor_multipleAuthsInSetFuzz(MintAuthorization memory auth1, MintAuthorization memory auth2)
        public
        pure
    {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);
        bytes29 setRef = MintAuthorizationLib._asAuthOrSetView(encodedAuthSet);
        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(encodedAuthSet);

        // Initial state
        assertEq(cursor.done, false);
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET);
        assertEq(cursor.numAuths, 2);
        assertEq(cursor.index, 0);

        bytes memory encodedAuth1 = MintAuthorizationLib.encodeMintAuthorization(auth1);
        uint256 expectedOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth1.length;

        // Advance cursor and verify first auth
        bytes29 currentAuth;
        (currentAuth, cursor) = cursor.next();
        _verifyMintAuthorizationFieldsFromView(currentAuth, auth1);
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, expectedOffset);
        assertEq(cursor.numAuths, 2);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, false);

        bytes memory encodedAuth2 = MintAuthorizationLib.encodeMintAuthorization(auth2);
        uint256 expectedUpdatedOffset = expectedOffset + encodedAuth2.length;

        // Advance cursor and verify second auth
        (currentAuth, cursor) = cursor.next();
        _verifyMintAuthorizationFieldsFromView(currentAuth, auth2);
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, expectedUpdatedOffset);
        assertEq(cursor.numAuths, 2);
        assertEq(cursor.index, 2);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDone_MultipleAuthsFuzz(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2
    ) public {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);
        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(encodedAuthSet);
        (, cursor) = cursor.next();
        (, cursor) = cursor.next();
        assertEq(cursor.done, true);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    // ===== Field Accessor / Set Iteration Tests =====

    function test_mintAuthorizationSet_readsAllFieldsEmptySet() public pure {
        MintAuthorization[] memory authorizations = new MintAuthorization[](0);
        MintAuthorizationSet memory set = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(set);
        _verifyEncodedSetFieldsAgainstStruct(encodedAuthSet, set);
    }

    function test_mintAuthorizationSet_readAllFieldsEmptyMetadataFuzz(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2
    ) public pure {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedAuthSet, authSet);
    }

    function test_mintAuthorizationSet_readAllFieldsShortMetadataFuzz(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2
    ) public pure {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, SHORT_METADATA);
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedAuthSet, authSet);
    }

    function test_mintAuthorizationSet_readAllFieldsLongMetadataFuzz(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2
    ) public pure {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedAuthSet, authSet);
    }
}
