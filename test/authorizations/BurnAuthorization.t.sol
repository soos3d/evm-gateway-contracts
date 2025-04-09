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
import {TRANSFER_SPEC_MAGIC, TRANSFER_SPEC_VERSION} from "src/lib/authorizations/TransferSpec.sol";
import {TransferSpecLib} from "src/lib/authorizations/TransferSpecLib.sol";
import {BYTES4_BYTES} from "src/lib/authorizations/TransferSpecLib.sol";
import {BurnAuthorization, BURN_AUTHORIZATION_MAGIC} from "src/lib/authorizations/BurnAuthorizations.sol";
import {BurnAuthorizationLib} from "src/lib/authorizations/BurnAuthorizationLib.sol";
import {AuthorizationCursor} from "src/lib/authorizations/AuthorizationCursor.sol";
import {TypedMemView} from "@memview-sol/TypedMemView.sol";

contract BurnAuthorizationTest is AuthorizationTestUtils {
    using BurnAuthorizationLib for bytes29;
    using BurnAuthorizationLib for AuthorizationCursor;

    // ===== Casting Tests =====

    function test_asAuthOrSetView_successBurnAuth() public pure {
        (bytes memory data, uint40 expectedType) = _magic("circle.gateway.BurnAuthorization"); // Use helper
        bytes29 ref = BurnAuthorizationLib._asAuthOrSetView(data);
        assertEq(TypedMemView.typeOf(ref), expectedType);
        assertEq(bytes4(uint32(expectedType)), BURN_AUTHORIZATION_MAGIC);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asAuthOrSetView_revertsOnShortData() public {
        bytes memory shortData = hex"1122";
        vm.expectRevert(
            abi.encodeWithSelector(TransferSpecLib.AuthorizationDataTooShort.selector, BYTES4_BYTES, shortData.length)
        );
        BurnAuthorizationLib._asAuthOrSetView(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asAuthOrSetView_revertsOnInvalidMagic4Bytes() public {
        (bytes memory invalidMagicData,) = _magic("not a valid magic");
        bytes4 incorrectMagic = bytes4(invalidMagicData);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidAuthorizationMagic.selector, incorrectMagic));
        BurnAuthorizationLib._asAuthOrSetView(invalidMagicData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asAuthOrSetView_revertsOnInvalidMagicLonger() public {
        (bytes memory invalidMagicData,) = _magic("not a valid magic");
        bytes memory longerInvalidMagic = bytes.concat(invalidMagicData, hex"01020304");
        bytes4 incorrectMagic = bytes4(longerInvalidMagic);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidAuthorizationMagic.selector, incorrectMagic));
        BurnAuthorizationLib._asAuthOrSetView(longerInvalidMagic);
    }

    // ===== Validation Tests =====

    function test_validate_successFuzz(BurnAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        BurnAuthorizationLib.validate(encodedAuth);
    }

    // ===== Validation Failures: Burn Authorization Structure =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnAuth_revertsOnDataTooShortForHeaderFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        bytes memory validEncodedBurnAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);

        uint16 truncatedLength = BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET - 1;
        bytes memory shortData = new bytes(truncatedLength);
        for (uint16 i = 0; i < truncatedLength; i++) {
            shortData[i] = validEncodedBurnAuth[i];
        }
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationHeaderTooShort.selector,
            BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET,
            shortData.length
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnAuth_revertsOnDeclaredSpecLengthTooBigFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        uint256 originalAuthLength = encodedAuth.length;
        uint32 originalSpecLength = uint32(originalAuthLength - BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        uint32 invalidSpecLength = originalSpecLength + 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        bytes memory corruptedData = cloneBytes(encodedAuth);
        for (uint8 i = 0; i < 4; i++) {
            corruptedData[BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET + i] = encodedInvalidLength[i];
        }

        uint256 expectedAuthLengthBasedOnCorruption = BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationOverallLengthMismatch.selector,
            expectedAuthLengthBasedOnCorruption,
            originalAuthLength
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnAuth_revertsOnDeclaredSpecLengthTooSmallFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        uint256 originalAuthLength = encodedAuth.length;
        uint32 originalSpecLength = uint32(originalAuthLength - BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        uint32 invalidSpecLength = originalSpecLength - 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        bytes memory corruptedData = cloneBytes(encodedAuth);
        for (uint8 i = 0; i < 4; i++) {
            corruptedData[BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET + i] = encodedInvalidLength[i];
        }

        uint256 expectedAuthLengthBasedOnCorruption = BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationOverallLengthMismatch.selector,
            expectedAuthLengthBasedOnCorruption,
            originalAuthLength
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnAuth_revertsOnTruncatedDataFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        uint256 expectedLength = encodedAuth.length;

        bytes memory truncatedData = new bytes(expectedLength - 1);
        for (uint256 i = 0; i < truncatedData.length; i++) {
            truncatedData[i] = encodedAuth[i];
        }
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationOverallLengthMismatch.selector, expectedLength, truncatedData.length
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnAuth_revertsOnTrailingBytesFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        uint256 originalAuthLength = encodedAuth.length;

        bytes memory corruptedData = bytes.concat(encodedAuth, hex"FFFF");
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationOverallLengthMismatch.selector, originalAuthLength, corruptedData.length
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(corruptedData);
    }

    // ===== Validation Failures: Inner TransferSpec Consistency =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDataTooShortForMagic() public {
        uint256 fixedMaxBlockHeight = 1;
        uint256 fixedMaxFee = 1;
        uint32 incorrectSpecLength = 2;
        bytes memory corruptedData =
            abi.encodePacked(BURN_AUTHORIZATION_MAGIC, fixedMaxBlockHeight, fixedMaxFee, incorrectSpecLength, hex"0000");

        bytes memory expectedRevertData = bytes(
            string.concat(
                "TypedMemView/index - Overran the view. ",
                "Slice is at 0x0000e8 with length 0x000002. ", // The length is the incorrectSpecLength (2)
                "Attempted to index at offset 0x000000 with length 0x000004." // Trying to read 4 byte magic
            )
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnCorruptedMagicFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);

        encodedAuth[BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET] = hex"FF";

        bytes4 corruptedMagic;
        uint256 offset = BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedAuth[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData =
            abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecMagic.selector, corruptedMagic);

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(encodedAuth);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDataTooShortForHeaderFuzz(BurnAuthorization memory auth) public {
        uint32 incorrectSpecLength = TRANSFER_SPEC_METADATA_OFFSET - 1;
        bytes memory dummySpecData =
            abi.encodePacked(TRANSFER_SPEC_MAGIC, new bytes(incorrectSpecLength - BYTES4_BYTES));
        bytes memory corruptedData = abi.encodePacked(
            BURN_AUTHORIZATION_MAGIC, auth.maxBlockHeight, auth.maxFee, incorrectSpecLength, dummySpecData
        );
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecHeaderTooShort.selector, TRANSFER_SPEC_METADATA_OFFSET, incorrectSpecLength
        );

        vm.expectRevert(expectedRevertData);
        BurnAuthorizationLib.validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDeclaredMetadataLengthTooBigFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        uint32 originalMetadataLength = uint32(auth.spec.metadata.length);
        uint32 originalInnerSpecLength = uint32(encodedAuth.length - BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        (bytes memory corruptedData, uint32 corruptedMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedAuth,
            BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within BurnAuth
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
        BurnAuthorizationLib.validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDeclaredMetadataLengthTooSmallFuzz(BurnAuthorization memory auth)
        public
    {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        uint32 originalMetadataLength = uint32(auth.spec.metadata.length);
        uint32 originalInnerSpecLength = uint32(encodedAuth.length - BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        (bytes memory corruptedData, uint32 corruptedMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedAuth,
            BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within BurnAuth
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
        BurnAuthorizationLib.validate(corruptedData);
    }

    // ===== Iteration Tests =====

    function test_cursor_successFuzz(BurnAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes29 authView = BurnAuthorizationLib._asAuthOrSetView(encodedAuth);

        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(encodedAuth);
        assertEq(cursor.setOrAuthView, authView);
        assertEq(cursor.offset, 0);
        assertEq(cursor.numAuths, 1);
        assertEq(cursor.index, 0);
        assertEq(cursor.done, false);

        bytes29 currentAuth = cursor.current();
        assertEq(currentAuth, authView);

        cursor = cursor.next();
        assertEq(cursor.setOrAuthView, authView);
        assertEq(cursor.offset, 0);
        assertEq(cursor.numAuths, 1);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnCurrentWhenDoneFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);

        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(encodedAuth);
        cursor = cursor.next();
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.current();
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDoneFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);

        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(encodedAuth);
        cursor = cursor.next();
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    // ===== Field Accessor Tests =====

    function test_burnAuthorization_readAllFieldsEmptyMetadataFuzz(BurnAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = new bytes(0);
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes29 ref = BurnAuthorizationLib._asAuthOrSetView(encodedAuth);
        _verifyBurnAuthorizationFieldsFromView(ref, auth);
    }

    function test_burnAuthorization_readAllFieldsShortMetadataFuzz(BurnAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = SHORT_METADATA;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes29 ref = BurnAuthorizationLib._asAuthOrSetView(encodedAuth);
        _verifyBurnAuthorizationFieldsFromView(ref, auth);
    }

    function test_burnAuthorization_readAllFieldsLongMetadataFuzz(BurnAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes29 ref = BurnAuthorizationLib._asAuthOrSetView(encodedAuth);
        _verifyBurnAuthorizationFieldsFromView(ref, auth);
    }
}
