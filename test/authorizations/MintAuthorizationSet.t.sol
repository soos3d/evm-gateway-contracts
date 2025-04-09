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
import {
    MintAuthorization,
    MintAuthorizationSet,
    MINT_AUTHORIZATION_SET_MAGIC
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
            bytes29 authRef = cursor.current();
            _verifyMintAuthorizationFieldsFromView(authRef, authSet.authorizations[i]); 
            cursor = cursor.next();
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
        MintAuthorizationLib.validate(encodedAuthSet);
    }

    // ===== Validation Failures: Set Structure =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnDataTooShortForHeader() public {
        // Length is > magic (4) but < header (8)
        bytes memory shortData = abi.encodePacked(MINT_AUTHORIZATION_SET_MAGIC, hex"112233"); // 7 bytes
        bytes memory expectedRevertData = abi.encodeWithSelector(
            MintAuthorizationLib.MalformedMintAuthorizationSet.selector, "Data too short for set header"
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnEmptyAuthorizationsWithTrailingBytes() public {
        bytes memory encodedSetHeader = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
            uint32(0) // numAuthorizations = 0
        );
        bytes memory trailingBytesData = bytes.concat(encodedSetHeader, hex"FFFF");

        bytes memory expectedRevertData = abi.encodeWithSelector(
            MintAuthorizationLib.MalformedMintAuthorizationSet.selector, "Set length mismatch after validating all elements"
        );
        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(trailingBytesData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BeforeFirstAuthHeader() public {
        // Set numAuthorizations = 1 but provide only the set header
        bytes memory encodedSetHeaderOnly = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
            uint32(1) // numAuthorizations = 1
        ); // 8 bytes total
        bytes memory expectedRevertData = abi.encodeWithSelector(
            MintAuthorizationLib.MalformedMintAuthorizationSet.selector, "Data too short for next MintAuthorization header"
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(encodedSetHeaderOnly);
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
        uint256 partialAuthHeaderLength = 10;
        bytes memory partialAuthData = new bytes(partialAuthHeaderLength);
        for (uint256 i = 0; i < partialAuthHeaderLength; i++) {
            partialAuthData[i] = encodedAuth1[i];
        }

        bytes memory truncatedData = bytes.concat(encodedSetHeader, partialAuthData);

        bytes memory expectedRevertData = abi.encodeWithSelector(
            MintAuthorizationLib.MalformedMintAuthorizationSet.selector, "Data too short for next MintAuthorization header"
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BasedOnFirstAuthSpecLengthFuzz(MintAuthorization memory auth1)
        public
    {
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

        bytes memory expectedRevertData = abi.encodeWithSelector(
            MintAuthorizationLib.MalformedMintAuthorizationSet.selector, "Data too short for next MintAuthorization"
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(truncatedData);
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
        uint256 partialAuth2HeaderLength = 10;
        bytes memory partialAuth2Data = new bytes(partialAuth2HeaderLength);
        for (uint256 i = 0; i < partialAuth2HeaderLength; i++) {
            partialAuth2Data[i] = encodedAuth2[i];
        }

        bytes memory truncatedData = bytes.concat(encodedSetHeader, encodedAuth1, partialAuth2Data);

        bytes memory expectedRevertData = abi.encodeWithSelector(
            MintAuthorizationLib.MalformedMintAuthorizationSet.selector, "Data too short for next MintAuthorization header"
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(truncatedData);
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

        bytes memory expectedRevertData = abi.encodeWithSelector(
            MintAuthorizationLib.MalformedMintAuthorizationSet.selector, "Data too short for next MintAuthorization"
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(truncatedData);
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

        bytes memory expectedRevertData = abi.encodeWithSelector(
            MintAuthorizationLib.MalformedMintAuthorizationSet.selector, "Set length mismatch after validating all elements"
        );
        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(trailingBytesData);
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

        bytes memory expectedRevertData = abi.encodeWithSelector(
            MintAuthorizationLib.MalformedMintAuthorizationSet.selector, "Invalid authorization magic in set"
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(encodedAuthSet);
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

        bytes memory expectedRevertData = abi.encodeWithSelector(
            MintAuthorizationLib.MalformedMintAuthorizationSet.selector, "Invalid authorization magic in set"
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAuth_DeclaredSpecLengthTooSmallFuzz(MintAuthorization memory auth1) public {
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
        for (uint8 i = 0; i < 4; i++) {
            encodedAuthSet[outerSpecLengthOffset + i] = encodedInvalidLength[i];
        }

        // The failure occurs inside the TransferSpec validating because the outer corruption
        // leads to providing a truncated spec slice.
        uint256 expectedInnerSpecLengthBasedOnMetadata = TRANSFER_SPEC_METADATA_OFFSET + originalMetadataLength;

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.MalformedTransferSpecInvalidLength.selector,
            expectedInnerSpecLengthBasedOnMetadata, // Length expected by inner spec based on its metadata
            invalidSpecLength // Actual length of the spec slice provided due to outer corruption
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(encodedAuthSet);
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
        for (uint8 i = 0; i < 4; i++) {
            encodedAuthSet[outerSpecLengthOffset + i] = encodedInvalidLength[i];
        }

        // The failure occurs in the main validation loop when checking if the set data
        // is long enough to contain the authorization based on its inflated declared length.
        bytes memory expectedRevertData = abi.encodeWithSelector(
            MintAuthorizationLib.MalformedMintAuthorizationSet.selector, "Data too short for next MintAuthorization"
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(encodedAuthSet);
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

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.MalformedTransferSpec.selector, "Invalid TransferSpec magic in MintAuthorization"
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(encodedAuthSet);
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
            TransferSpecLib.MalformedTransferSpecInvalidLength.selector, expectedInnerSpecLength, actualInnerSpecLength
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(corruptedEncodedAuthSet);
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
            TransferSpecLib.MalformedTransferSpecInvalidLength.selector, expectedInnerSpecLength, actualInnerSpecLength
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib.validate(corruptedEncodedAuthSet);
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
    function test_cursor_revertsOnCurrentWhenEmptySet() public {
        MintAuthorization[] memory authorizations = new MintAuthorization[](0);
        MintAuthorizationSet memory set = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(set);
        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(encodedAuthSet);
        vm.expectRevert(abi.encodeWithSelector(MintAuthorizationLib.CursorOutOfBounds.selector));
        cursor.current();
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenEmptySet() public {
        MintAuthorization[] memory authorizations = new MintAuthorization[](0);
        MintAuthorizationSet memory set = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(set);
        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(encodedAuthSet);
        vm.expectRevert(abi.encodeWithSelector(MintAuthorizationLib.CursorOutOfBounds.selector));
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

        // Verify first auth
        bytes29 currentAuth = cursor.current();
        _verifyMintAuthorizationFieldsFromView(currentAuth, auth);

        // Advance cursor
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        uint256 expectedOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth.length;
        cursor = cursor.next();
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, expectedOffset);
        assertEq(cursor.numAuths, 1);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnCurrentWhenDone_SingleAuthFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        MintAuthorization[] memory authorizations = new MintAuthorization[](1);
        authorizations[0] = auth;
        MintAuthorizationSet memory set = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(set);

        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(encodedAuthSet);
        cursor = cursor.next();
        assertEq(cursor.done, true);
        vm.expectRevert(abi.encodeWithSelector(MintAuthorizationLib.CursorOutOfBounds.selector));
        cursor.current();
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
        cursor = cursor.next();
        assertEq(cursor.done, true);
        vm.expectRevert(abi.encodeWithSelector(MintAuthorizationLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    function test_cursor_multipleAuthsInSetFuzz(MintAuthorization memory auth1, MintAuthorization memory auth2) public pure {
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

        // Verify first auth
        bytes29 currentAuth = cursor.current();
        _verifyMintAuthorizationFieldsFromView(currentAuth, auth1);

        // Advance cursor
        bytes memory encodedAuth1 = MintAuthorizationLib.encodeMintAuthorization(auth1);
        uint256 expectedOffset1 = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth1.length;
        cursor = cursor.next();
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, expectedOffset1);
        assertEq(cursor.numAuths, 2);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, false);

        // Verify second auth
        currentAuth = cursor.current();
        _verifyMintAuthorizationFieldsFromView(currentAuth, auth2);

        // Advance cursor
        bytes memory encodedAuth2 = MintAuthorizationLib.encodeMintAuthorization(auth2);
        uint256 expectedOffset2 = expectedOffset1 + encodedAuth2.length;
        cursor = cursor.next();
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, expectedOffset2);
        assertEq(cursor.numAuths, 2);
        assertEq(cursor.index, 2);
        assertEq(cursor.done, true);
    }    
    
    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnCurrentWhenDone_MultipleAuthsFuzz(MintAuthorization memory auth1, MintAuthorization memory auth2) public {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);
        
        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(encodedAuthSet);
        cursor = cursor.next();
        cursor = cursor.next();
        assertEq(cursor.done, true);

        vm.expectRevert(abi.encodeWithSelector(MintAuthorizationLib.CursorOutOfBounds.selector));
        cursor.current();
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDone_MultipleAuthsFuzz(MintAuthorization memory auth1, MintAuthorization memory auth2) public {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);
        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(encodedAuthSet);
        cursor = cursor.next();
        cursor = cursor.next();
        assertEq(cursor.done, true);

        vm.expectRevert(abi.encodeWithSelector(MintAuthorizationLib.CursorOutOfBounds.selector));
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
