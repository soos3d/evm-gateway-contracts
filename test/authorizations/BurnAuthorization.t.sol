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
import {BurnIntentLib} from "src/lib/BurnIntentLib.sol";
import {BurnIntent, BURN_INTENT_MAGIC} from "src/lib/BurnIntents.sol";
import {TRANSFER_SPEC_MAGIC, TRANSFER_SPEC_VERSION} from "src/lib/TransferSpec.sol";
import {TransferSpecLib} from "src/lib/TransferSpecLib.sol";
import {BYTES4_BYTES} from "src/lib/TransferSpecLib.sol";
import {AuthorizationTestUtils} from "./AuthorizationTestUtils.sol";

contract BurnIntentTest is AuthorizationTestUtils {
    using BurnIntentLib for bytes29;
    using BurnIntentLib for Cursor;

    // ===== Casting Tests =====

    function test_asAuthOrSetView_successBurnAuth() public pure {
        (bytes memory data, uint40 expectedType) = _magic("circle.gateway.BurnIntent"); // Use helper
        bytes29 ref = BurnIntentLib._asAuthOrSetView(data);
        assertEq(TypedMemView.typeOf(ref), expectedType);
        assertEq(bytes4(uint32(expectedType)), BURN_INTENT_MAGIC);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asAuthOrSetView_revertsOnShortData() public {
        bytes memory shortData = hex"1122";
        vm.expectRevert(
            abi.encodeWithSelector(TransferSpecLib.AuthorizationDataTooShort.selector, BYTES4_BYTES, shortData.length)
        );
        BurnIntentLib._asAuthOrSetView(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asAuthOrSetView_revertsOnInvalidMagic4Bytes() public {
        (bytes memory invalidMagicData,) = _magic("not a valid magic");
        bytes4 incorrectMagic = bytes4(invalidMagicData);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidAuthorizationMagic.selector, incorrectMagic));
        BurnIntentLib._asAuthOrSetView(invalidMagicData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asAuthOrSetView_revertsOnInvalidMagicLonger() public {
        (bytes memory invalidMagicData,) = _magic("not a valid magic");
        bytes memory longerInvalidMagic = bytes.concat(invalidMagicData, hex"01020304");
        bytes4 incorrectMagic = bytes4(longerInvalidMagic);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidAuthorizationMagic.selector, incorrectMagic));
        BurnIntentLib._asAuthOrSetView(longerInvalidMagic);
    }

    // ===== Validation Tests =====

    function test_validate_successFuzz(BurnIntent memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnIntentLib.encodeBurnIntent(auth);
        BurnIntentLib._validate(encodedAuth);
    }

    // ===== Validation Failures: Burn Authorization Structure =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnAuth_revertsOnDataTooShortForHeaderFuzz(BurnIntent memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        bytes memory validEncodedBurnAuth = BurnIntentLib.encodeBurnIntent(auth);

        uint16 truncatedLength = BURN_INTENT_TRANSFER_SPEC_OFFSET - 1;
        bytes memory shortData = new bytes(truncatedLength);
        for (uint16 i = 0; i < truncatedLength; i++) {
            shortData[i] = validEncodedBurnAuth[i];
        }
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationHeaderTooShort.selector,
            BURN_INTENT_TRANSFER_SPEC_OFFSET,
            shortData.length
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnAuth_revertsOnDeclaredSpecLengthTooBigFuzz(BurnIntent memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnIntentLib.encodeBurnIntent(auth);
        uint256 originalAuthLength = encodedAuth.length;
        uint32 originalSpecLength = uint32(originalAuthLength - BURN_INTENT_TRANSFER_SPEC_OFFSET);

        uint32 invalidSpecLength = originalSpecLength + 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        bytes memory corruptedData = cloneBytes(encodedAuth);
        for (uint8 i = 0; i < 4; i++) {
            corruptedData[BURN_INTENT_TRANSFER_SPEC_LENGTH_OFFSET + i] = encodedInvalidLength[i];
        }

        uint256 expectedAuthLengthBasedOnCorruption = BURN_INTENT_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationOverallLengthMismatch.selector,
            expectedAuthLengthBasedOnCorruption,
            originalAuthLength
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnAuth_revertsOnDeclaredSpecLengthTooSmallFuzz(BurnIntent memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnIntentLib.encodeBurnIntent(auth);
        uint256 originalAuthLength = encodedAuth.length;
        uint32 originalSpecLength = uint32(originalAuthLength - BURN_INTENT_TRANSFER_SPEC_OFFSET);

        uint32 invalidSpecLength = originalSpecLength - 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        bytes memory corruptedData = cloneBytes(encodedAuth);
        for (uint8 i = 0; i < 4; i++) {
            corruptedData[BURN_INTENT_TRANSFER_SPEC_LENGTH_OFFSET + i] = encodedInvalidLength[i];
        }

        uint256 expectedAuthLengthBasedOnCorruption = BURN_INTENT_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationOverallLengthMismatch.selector,
            expectedAuthLengthBasedOnCorruption,
            originalAuthLength
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnAuth_revertsOnTruncatedDataFuzz(BurnIntent memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnIntentLib.encodeBurnIntent(auth);
        uint256 expectedLength = encodedAuth.length;

        bytes memory truncatedData = new bytes(expectedLength - 1);
        for (uint256 i = 0; i < truncatedData.length; i++) {
            truncatedData[i] = encodedAuth[i];
        }
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationOverallLengthMismatch.selector, expectedLength, truncatedData.length
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnAuth_revertsOnTrailingBytesFuzz(BurnIntent memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnIntentLib.encodeBurnIntent(auth);
        uint256 originalAuthLength = encodedAuth.length;

        bytes memory corruptedData = bytes.concat(encodedAuth, hex"FFFF");
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationOverallLengthMismatch.selector, originalAuthLength, corruptedData.length
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(corruptedData);
    }

    // ===== Validation Failures: Inner TransferSpec Consistency =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDataTooShortForMagic() public {
        uint256 fixedMaxBlockHeight = 1;
        uint256 fixedMaxFee = 1;
        uint32 incorrectSpecLength = 2;
        bytes memory corruptedData =
            abi.encodePacked(BURN_INTENT_MAGIC, fixedMaxBlockHeight, fixedMaxFee, incorrectSpecLength, hex"0000");

        bytes memory expectedRevertData = bytes(
            string.concat(
                "TypedMemView/index - Overran the view. ",
                "Slice is at 0x0000e8 with length 0x000002. ", // The length is the incorrectSpecLength (2)
                "Attempted to index at offset 0x000000 with length 0x000004." // Trying to read 4 byte magic
            )
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnCorruptedMagicFuzz(BurnIntent memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnIntentLib.encodeBurnIntent(auth);

        encodedAuth[BURN_INTENT_TRANSFER_SPEC_OFFSET] = hex"00";

        bytes4 corruptedMagic;
        uint256 offset = BURN_INTENT_TRANSFER_SPEC_OFFSET;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedAuth[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData =
            abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecMagic.selector, corruptedMagic);

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(encodedAuth);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDataTooShortForHeaderFuzz(BurnIntent memory auth) public {
        uint32 incorrectSpecLength = TRANSFER_SPEC_METADATA_OFFSET - 1;
        bytes memory dummySpecData =
            abi.encodePacked(TRANSFER_SPEC_MAGIC, new bytes(incorrectSpecLength - BYTES4_BYTES));
        bytes memory corruptedData = abi.encodePacked(
            BURN_INTENT_MAGIC, auth.maxBlockHeight, auth.maxFee, incorrectSpecLength, dummySpecData
        );
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecHeaderTooShort.selector, TRANSFER_SPEC_METADATA_OFFSET, incorrectSpecLength
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnInvalidVersionFuzz(BurnIntent memory auth) public {
        uint32 invalidVersion = TRANSFER_SPEC_VERSION + 1;
        auth.spec.version = invalidVersion;
        auth.spec.metadata = LONG_METADATA;

        bytes memory encodedAuth = BurnIntentLib.encodeBurnIntent(auth);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecVersion.selector, invalidVersion));
        BurnIntentLib._validate(encodedAuth);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDeclaredMetadataLengthTooBigFuzz(BurnIntent memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnIntentLib.encodeBurnIntent(auth);
        uint32 originalMetadataLength = uint32(auth.spec.metadata.length);
        uint32 originalInnerSpecLength = uint32(encodedAuth.length - BURN_INTENT_TRANSFER_SPEC_OFFSET);

        (bytes memory corruptedData, uint32 corruptedMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedAuth,
            BURN_INTENT_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within BurnAuth
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
        BurnIntentLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDeclaredMetadataLengthTooSmallFuzz(BurnIntent memory auth)
        public
    {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnIntentLib.encodeBurnIntent(auth);
        uint32 originalMetadataLength = uint32(auth.spec.metadata.length);
        uint32 originalInnerSpecLength = uint32(encodedAuth.length - BURN_INTENT_TRANSFER_SPEC_OFFSET);

        (bytes memory corruptedData, uint32 corruptedMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedAuth,
            BURN_INTENT_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within BurnAuth
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
        BurnIntentLib._validate(corruptedData);
    }

    // ===== Iteration Tests =====

    function test_cursor_successFuzz(BurnIntent memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnIntentLib.encodeBurnIntent(auth);
        bytes29 authView = BurnIntentLib._asAuthOrSetView(encodedAuth);

        // Initial state
        Cursor memory cursor = BurnIntentLib.cursor(encodedAuth);
        assertEq(cursor.setOrAuthView, authView);
        assertEq(cursor.offset, 0);
        assertEq(cursor.numAuths, 1);
        assertEq(cursor.index, 0);
        assertEq(cursor.done, false);

        // Advance the cursor
        bytes29 currentAuth = cursor.next();
        assertEq(currentAuth, authView);
        assertEq(cursor.setOrAuthView, authView);
        assertEq(cursor.offset, encodedAuth.length);
        assertEq(cursor.numAuths, 1);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDoneFuzz(BurnIntent memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnIntentLib.encodeBurnIntent(auth);

        Cursor memory cursor = BurnIntentLib.cursor(encodedAuth);
        cursor.next();
        assertEq(cursor.done, true);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    // ===== Field Accessor Tests =====

    function test_burnAuthorization_readAllFieldsEmptyMetadataFuzz(BurnIntent memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = new bytes(0);
        bytes memory encodedAuth = BurnIntentLib.encodeBurnIntent(auth);
        bytes29 ref = BurnIntentLib._asAuthOrSetView(encodedAuth);
        _verifyBurnIntentFieldsFromView(ref, auth);
    }

    function test_burnAuthorization_readAllFieldsShortMetadataFuzz(BurnIntent memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = SHORT_METADATA;
        bytes memory encodedAuth = BurnIntentLib.encodeBurnIntent(auth);
        bytes29 ref = BurnIntentLib._asAuthOrSetView(encodedAuth);
        _verifyBurnIntentFieldsFromView(ref, auth);
    }

    function test_burnAuthorization_readAllFieldsLongMetadataFuzz(BurnIntent memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = BurnIntentLib.encodeBurnIntent(auth);
        bytes29 ref = BurnIntentLib._asAuthOrSetView(encodedAuth);
        _verifyBurnIntentFieldsFromView(ref, auth);
    }
}
