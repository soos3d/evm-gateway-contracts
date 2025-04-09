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
    BurnAuthorization,
    BurnAuthorizationSet,
    BURN_AUTHORIZATION_SET_MAGIC
} from "src/lib/authorizations/BurnAuthorizations.sol";
import {BurnAuthorizationLib} from "src/lib/authorizations/BurnAuthorizationLib.sol";
import {AuthorizationCursor} from "src/lib/authorizations/AuthorizationCursor.sol";
import {TypedMemView} from "@memview-sol/TypedMemView.sol";

contract BurnAuthorizationSetTest is AuthorizationTestUtils {
    using BurnAuthorizationLib for bytes29;
    using BurnAuthorizationLib for AuthorizationCursor;

    uint16 private constant BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET = 8;

    /// @notice Helper to create a BurnAuthorizationSet with two authorizations and specified metadata.
    function _createBurnAuthSet(BurnAuthorization memory auth1, BurnAuthorization memory auth2, bytes memory metadata)
        internal
        pure
        returns (BurnAuthorizationSet memory)
    {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = metadata;
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = metadata;

        BurnAuthorization[] memory authorizations = new BurnAuthorization[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;

        return BurnAuthorizationSet({authorizations: authorizations});
    }

    /// @notice Internal helper to verify all fields from encoded set bytes match the original struct.
    function _verifyEncodedSetFieldsAgainstStruct(bytes memory encodedAuthSet, BurnAuthorizationSet memory authSet)
        internal
        pure
    {
        bytes29 setRef = BurnAuthorizationLib._asAuthOrSetView(encodedAuthSet);
        uint32 numAuths = setRef.getNumAuthorizations();
        assertEq(numAuths, authSet.authorizations.length, "Eq Fail: numAuths");

        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(encodedAuthSet);
        uint32 i = 0;
        while (!cursor.done) {
            bytes29 authRef = cursor.current();
            _verifyBurnAuthorizationFieldsFromView(authRef, authSet.authorizations[i]); 
            cursor = cursor.next();
            i++;
        }
        assertEq(i, numAuths, "Loop iteration count mismatch");
    }

    // ===== Casting Tests =====

    function test_asAuthOrSetView_successBurnAuthSet() public pure {
        (bytes memory data, uint40 expectedType) = _magic("circle.gateway.BurnAuthorizationSet");
        bytes29 ref = BurnAuthorizationLib._asAuthOrSetView(data);
        assertEq(TypedMemView.typeOf(ref), expectedType);
        assertEq(bytes4(uint32(expectedType)), BURN_AUTHORIZATION_SET_MAGIC);
    }

    // ===== Validation Tests =====

    function test_validateBurnAuthorizationSet_successFuzz(
        BurnAuthorization memory auth1,
        BurnAuthorization memory auth2
    ) public pure {
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);
        BurnAuthorizationLib.validate(encodedAuthSet);
    }

    // ===== Validation Failures: Set Structure =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnDataTooShortForHeader() public {
        // Length is > magic (4) but < header (8)
        bytes memory shortData = abi.encodePacked(BURN_AUTHORIZATION_SET_MAGIC, hex"112233"); // 7 bytes
        bytes memory expectedRevertData = abi.encodeWithSelector(
            BurnAuthorizationLib.MalformedBurnAuthorizationSet.selector, "Data too short for set header"
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnEmptyAuthorizationsWithTrailingBytes() public {
        bytes memory encodedSetHeader = abi.encodePacked(
            BURN_AUTHORIZATION_SET_MAGIC,
            uint32(0) // numAuthorizations = 0
        );
        bytes memory trailingBytesData = bytes.concat(encodedSetHeader, hex"FFFF");

        bytes memory expectedRevertData = abi.encodeWithSelector(
            BurnAuthorizationLib.MalformedBurnAuthorizationSet.selector, "Set length mismatch after validating all elements"
        );
        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(trailingBytesData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BeforeFirstAuthHeader() public {
        // Set numAuthorizations = 1 but provide only the set header
        bytes memory encodedSetHeaderOnly = abi.encodePacked(
            BURN_AUTHORIZATION_SET_MAGIC,
            uint32(1) // numAuthorizations = 1
        ); // 8 bytes total
        bytes memory expectedRevertData = abi.encodeWithSelector(
            BurnAuthorizationLib.MalformedBurnAuthorizationSet.selector, "Data too short for next BurnAuthorization header"
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(encodedSetHeaderOnly);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_WithinFirstAuthHeaderFuzz(BurnAuthorization memory auth1)
        public
    {
        // Set numAuthorizations = 1, provide set header + partial auth header
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        bytes memory encodedAuth1 = BurnAuthorizationLib.encodeBurnAuthorization(auth1);

        bytes memory encodedSetHeader = abi.encodePacked(
            BURN_AUTHORIZATION_SET_MAGIC,
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
            BurnAuthorizationLib.MalformedBurnAuthorizationSet.selector, "Data too short for next BurnAuthorization header"
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BasedOnFirstAuthSpecLengthFuzz(BurnAuthorization memory auth1)
        public
    {
        // Set numAuthorizations = 1, provide set header + full auth header + partial spec
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth1 = BurnAuthorizationLib.encodeBurnAuthorization(auth1);

        bytes memory encodedSetHeader = abi.encodePacked(
            BURN_AUTHORIZATION_SET_MAGIC,
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
            BurnAuthorizationLib.MalformedBurnAuthorizationSet.selector, "Data too short for next BurnAuthorization"
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BetweenAuthorizationsFuzz(
        BurnAuthorization memory auth1,
        BurnAuthorization memory auth2
    ) public {
        // Set numAuthorizations = 2, provide set header + auth1 + partial auth2 header
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);

        bytes memory encodedAuth1 = BurnAuthorizationLib.encodeBurnAuthorization(auth1);
        bytes memory encodedAuth2 = BurnAuthorizationLib.encodeBurnAuthorization(auth2);

        bytes memory encodedSetHeader = abi.encodePacked(
            BURN_AUTHORIZATION_SET_MAGIC,
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
            BurnAuthorizationLib.MalformedBurnAuthorizationSet.selector, "Data too short for next BurnAuthorization header"
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_WithinSecondAuthorizationFuzz(
        BurnAuthorization memory auth1,
        BurnAuthorization memory auth2
    ) public {
        // Set numAuthorizations = 2, provide set header + auth1 + auth2 header + partial auth2 spec
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);

        bytes memory encodedAuth1 = BurnAuthorizationLib.encodeBurnAuthorization(auth1);
        bytes memory encodedAuth2 = BurnAuthorizationLib.encodeBurnAuthorization(auth2);

        bytes memory encodedSetHeader = abi.encodePacked(
            BURN_AUTHORIZATION_SET_MAGIC,
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
            BurnAuthorizationLib.MalformedBurnAuthorizationSet.selector, "Data too short for next BurnAuthorization"
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnTrailingBytes_AfterAllAuthsFuzz(
        BurnAuthorization memory auth1,
        BurnAuthorization memory auth2
    ) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        // Add trailing bytes
        bytes memory trailingBytesData = bytes.concat(encodedAuthSet, hex"FFFF");

        bytes memory expectedRevertData = abi.encodeWithSelector(
            BurnAuthorizationLib.MalformedBurnAuthorizationSet.selector, "Set length mismatch after validating all elements"
        );
        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(trailingBytesData);
    }

    // ===== Validation Failures: Inner Authorization Consistency =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAuth_CorruptedMagic_InFirstFuzz(
        BurnAuthorization memory auth1,
        BurnAuthorization memory auth2
    ) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        // Corrupt the magic of the first authorization (at offset 8)
        encodedAuthSet[BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET] = hex"FF";

        bytes memory expectedRevertData = abi.encodeWithSelector(
            BurnAuthorizationLib.MalformedBurnAuthorizationSet.selector, "Invalid authorization magic in set"
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAuth_CorruptedMagic_InSecondFuzz(
        BurnAuthorization memory auth1,
        BurnAuthorization memory auth2
    ) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        // Calculate offset of second authorization's magic
        bytes memory encodedAuth1 = BurnAuthorizationLib.encodeBurnAuthorization(authSet.authorizations[0]);
        uint256 secondAuthOffset = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth1.length;

        // Corrupt the magic of the second authorization
        encodedAuthSet[secondAuthOffset] = hex"FF";

        bytes memory expectedRevertData = abi.encodeWithSelector(
            BurnAuthorizationLib.MalformedBurnAuthorizationSet.selector, "Invalid authorization magic in set"
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAuth_DeclaredSpecLengthTooSmallFuzz(BurnAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        BurnAuthorization[] memory authorizations = new BurnAuthorization[](1);
        authorizations[0] = auth1;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes memory encodedAuth1 = BurnAuthorizationLib.encodeBurnAuthorization(auth1);
        uint256 originalAuthLength = encodedAuth1.length;
        uint32 originalSpecLength = uint32(originalAuthLength - BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET);
        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);

        // Corrupt the outer BurnAuthorization's declared spec length (make it smaller)
        uint256 outerSpecLengthOffset =
            BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET;
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
        BurnAuthorizationLib.validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerAuth_DeclaredSpecLengthTooBigFuzz(BurnAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        BurnAuthorization[] memory authorizations = new BurnAuthorization[](1);
        authorizations[0] = auth1;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes memory encodedAuth1 = BurnAuthorizationLib.encodeBurnAuthorization(auth1);
        uint256 originalAuthLength = encodedAuth1.length;
        uint32 originalSpecLength = uint32(originalAuthLength - BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        // Corrupt the outer BurnAuthorization's declared spec length (make it larger)
        uint256 outerSpecLengthOffset =
            BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET;
        uint32 invalidSpecLength = originalSpecLength + 1; // Make it larger than actual
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        for (uint8 i = 0; i < 4; i++) {
            encodedAuthSet[outerSpecLengthOffset + i] = encodedInvalidLength[i];
        }

        // The failure occurs in the main validation loop when checking if the set data
        // is long enough to contain the authorization based on its inflated declared length.
        bytes memory expectedRevertData = abi.encodeWithSelector(
            BurnAuthorizationLib.MalformedBurnAuthorizationSet.selector, "Data too short for next BurnAuthorization"
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_CorruptedMagicFuzz(BurnAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        BurnAuthorization[] memory authorizations = new BurnAuthorization[](1);
        authorizations[0] = auth1;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        // Corrupt the inner TransferSpec magic within the first authorization
        uint256 innerSpecMagicOffset =
            BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
        encodedAuthSet[innerSpecMagicOffset] = hex"FF";

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.MalformedTransferSpec.selector, "Invalid TransferSpec magic in BurnAuthorization"
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_DeclaredMetadataLengthTooBigFuzz(BurnAuthorization memory auth1)
        public
    {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        BurnAuthorization[] memory authorizations = new BurnAuthorization[](1);
        authorizations[0] = auth1;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);
        uint256 encodedAuth1Length = encodedAuthSet.length - BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;
        uint32 actualInnerSpecLength = uint32(encodedAuth1Length - BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        uint32 specOffset = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
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
        BurnAuthorizationLib.validate(corruptedEncodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_DeclaredMetadataLengthTooSmallFuzz(BurnAuthorization memory auth1)
        public
    {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        BurnAuthorization[] memory authorizations = new BurnAuthorization[](1);
        authorizations[0] = auth1;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);
        uint256 encodedAuth1Length = encodedAuthSet.length - BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;
        uint32 actualInnerSpecLength = uint32(encodedAuth1Length - BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        uint32 specOffset = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
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
        BurnAuthorizationLib.validate(corruptedEncodedAuthSet);
    }

    // ===== Iteration Tests =====

    function test_cursor_emptySet() public pure {
        BurnAuthorization[] memory authorizations = new BurnAuthorization[](0);
        BurnAuthorizationSet memory set = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(set);
        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(encodedAuthSet);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnCurrentWhenEmptySet() public {
        BurnAuthorization[] memory authorizations = new BurnAuthorization[](0);
        BurnAuthorizationSet memory set = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(set);
        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(encodedAuthSet);
        vm.expectRevert(abi.encodeWithSelector(BurnAuthorizationLib.CursorOutOfBounds.selector));
        cursor.current();
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenEmptySet() public {
        BurnAuthorization[] memory authorizations = new BurnAuthorization[](0);
        BurnAuthorizationSet memory set = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(set);
        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(encodedAuthSet);
        vm.expectRevert(abi.encodeWithSelector(BurnAuthorizationLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    function test_cursor_singleAuthInSetFuzz(BurnAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        
        BurnAuthorization[] memory authorizations = new BurnAuthorization[](1);
        authorizations[0] = auth;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);
        bytes29 setRef = BurnAuthorizationLib._asAuthOrSetView(encodedAuthSet);
        
        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(encodedAuthSet);

        // Initial state
        assertEq(cursor.done, false);
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET);
        assertEq(cursor.numAuths, 1);
        assertEq(cursor.index, 0);

        // Verify first auth
        bytes29 currentAuth = cursor.current();
        _verifyBurnAuthorizationFieldsFromView(currentAuth, auth);

        // Advance cursor
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        uint256 expectedOffset = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth.length;
        cursor = cursor.next();
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, expectedOffset);
        assertEq(cursor.numAuths, 1);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnCurrentWhenDone_SingleAuthFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        BurnAuthorization[] memory authorizations = new BurnAuthorization[](1);
        authorizations[0] = auth;
        BurnAuthorizationSet memory set = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(set);

        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(encodedAuthSet);
        cursor = cursor.next();
        assertEq(cursor.done, true);
        vm.expectRevert(abi.encodeWithSelector(BurnAuthorizationLib.CursorOutOfBounds.selector));
        cursor.current();
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDone_SingleAuthFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        BurnAuthorization[] memory authorizations = new BurnAuthorization[](1);
        authorizations[0] = auth;
        BurnAuthorizationSet memory set = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(set);
        
        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(encodedAuthSet);
        cursor = cursor.next();
        assertEq(cursor.done, true);
        vm.expectRevert(abi.encodeWithSelector(BurnAuthorizationLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    function test_cursor_multipleAuthsInSetFuzz(BurnAuthorization memory auth1, BurnAuthorization memory auth2) public pure {
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);
        bytes29 setRef = BurnAuthorizationLib._asAuthOrSetView(encodedAuthSet);
        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(encodedAuthSet);

        // Initial state
        assertEq(cursor.done, false);
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET);
        assertEq(cursor.numAuths, 2);
        assertEq(cursor.index, 0);

        // Verify first auth
        bytes29 currentAuth = cursor.current();
        _verifyBurnAuthorizationFieldsFromView(currentAuth, auth1);

        // Advance cursor
        bytes memory encodedAuth1 = BurnAuthorizationLib.encodeBurnAuthorization(auth1);
        uint256 expectedOffset1 = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth1.length;
        cursor = cursor.next();
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, expectedOffset1);
        assertEq(cursor.numAuths, 2);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, false);

        // Verify second auth
        currentAuth = cursor.current();
        _verifyBurnAuthorizationFieldsFromView(currentAuth, auth2);

        // Advance cursor
        bytes memory encodedAuth2 = BurnAuthorizationLib.encodeBurnAuthorization(auth2);
        uint256 expectedOffset2 = expectedOffset1 + encodedAuth2.length;
        cursor = cursor.next();
        assertEq(cursor.setOrAuthView, setRef);
        assertEq(cursor.offset, expectedOffset2);
        assertEq(cursor.numAuths, 2);
        assertEq(cursor.index, 2);
        assertEq(cursor.done, true);
    }    
    
    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnCurrentWhenDone_MultipleAuthsFuzz(BurnAuthorization memory auth1, BurnAuthorization memory auth2) public {
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);
        
        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(encodedAuthSet);
        cursor = cursor.next();
        cursor = cursor.next();
        assertEq(cursor.done, true);

        vm.expectRevert(abi.encodeWithSelector(BurnAuthorizationLib.CursorOutOfBounds.selector));
        cursor.current();
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDone_MultipleAuthsFuzz(BurnAuthorization memory auth1, BurnAuthorization memory auth2) public {
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);
        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(encodedAuthSet);
        cursor = cursor.next();
        cursor = cursor.next();
        assertEq(cursor.done, true);

        vm.expectRevert(abi.encodeWithSelector(BurnAuthorizationLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    // ===== Field Accessor / Set Iteration Tests =====

    function test_burnAuthorizationSet_readsAllFieldsEmptySet() public pure {
        BurnAuthorization[] memory authorizations = new BurnAuthorization[](0);
        BurnAuthorizationSet memory set = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(set);
        _verifyEncodedSetFieldsAgainstStruct(encodedAuthSet, set);
    }

    function test_burnAuthorizationSet_readAllFieldsEmptyMetadataFuzz(
        BurnAuthorization memory auth1,
        BurnAuthorization memory auth2
    ) public pure {
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedAuthSet, authSet);
    }

    function test_burnAuthorizationSet_readAllFieldsShortMetadataFuzz(
        BurnAuthorization memory auth1,
        BurnAuthorization memory auth2
    ) public pure {
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, SHORT_METADATA);
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedAuthSet, authSet);
    }

    function test_burnAuthorizationSet_readAllFieldsLongMetadataFuzz(
        BurnAuthorization memory auth1,
        BurnAuthorization memory auth2
    ) public pure {
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedAuthSet, authSet);
    }

}
