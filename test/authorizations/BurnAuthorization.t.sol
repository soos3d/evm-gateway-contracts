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
import {TransferPayloadTestUtils} from "./TransferPayloadTestUtils.sol";

contract BurnIntentTest is TransferPayloadTestUtils {
    using BurnIntentLib for bytes29;
    using BurnIntentLib for Cursor;

    // ===== Casting Tests =====

    function test_asIntentOrSetView_successBurnIntent() public pure {
        (bytes memory data, uint40 expectedType) = _magic("circle.gateway.BurnIntent"); // Use helper
        bytes29 ref = BurnIntentLib._asIntentOrSetView(data);
        assertEq(TypedMemView.typeOf(ref), expectedType);
        assertEq(bytes4(uint32(expectedType)), BURN_INTENT_MAGIC);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asIntentOrSetView_revertsOnShortData() public {
        bytes memory shortData = hex"1122";
        vm.expectRevert(
            abi.encodeWithSelector(TransferSpecLib.TransferPayloadDataTooShort.selector, BYTES4_BYTES, shortData.length)
        );
        BurnIntentLib._asIntentOrSetView(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asIntentOrSetView_revertsOnInvalidMagic4Bytes() public {
        (bytes memory invalidMagicData,) = _magic("not a valid magic");
        bytes4 incorrectMagic = bytes4(invalidMagicData);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidTransferPayloadMagic.selector, incorrectMagic));
        BurnIntentLib._asIntentOrSetView(invalidMagicData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asIntentOrSetView_revertsOnInvalidMagicLonger() public {
        (bytes memory invalidMagicData,) = _magic("not a valid magic");
        bytes memory longerInvalidMagic = bytes.concat(invalidMagicData, hex"01020304");
        bytes4 incorrectMagic = bytes4(longerInvalidMagic);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidTransferPayloadMagic.selector, incorrectMagic));
        BurnIntentLib._asIntentOrSetView(longerInvalidMagic);
    }

    // ===== Validation Tests =====

    function test_validate_successFuzz(BurnIntent memory intent) public pure {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = LONG_METADATA;
        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);
        BurnIntentLib._validate(encodedIntent);
    }

    // ===== Validation Failures: Burn Intent Structure =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnIntent_revertsOnDataTooShortForHeaderFuzz(BurnIntent memory intent) public {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        bytes memory validEncodedBurnIntent = BurnIntentLib.encodeBurnIntent(intent);

        uint16 truncatedLength = BURN_INTENT_TRANSFER_SPEC_OFFSET - 1;
        bytes memory shortData = new bytes(truncatedLength);
        for (uint16 i = 0; i < truncatedLength; i++) {
            shortData[i] = validEncodedBurnIntent[i];
        }
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadHeaderTooShort.selector, BURN_INTENT_TRANSFER_SPEC_OFFSET, shortData.length
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnIntent_revertsOnDeclaredSpecLengthTooBigFuzz(BurnIntent memory intent) public {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = LONG_METADATA;
        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);
        uint256 originalIntentLength = encodedIntent.length;
        uint32 originalSpecLength = uint32(originalIntentLength - BURN_INTENT_TRANSFER_SPEC_OFFSET);

        uint32 invalidSpecLength = originalSpecLength + 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        bytes memory corruptedData = cloneBytes(encodedIntent);
        for (uint8 i = 0; i < 4; i++) {
            corruptedData[BURN_INTENT_TRANSFER_SPEC_LENGTH_OFFSET + i] = encodedInvalidLength[i];
        }

        uint256 expectedIntentLengthBasedOnCorruption = BURN_INTENT_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadOverallLengthMismatch.selector,
            expectedIntentLengthBasedOnCorruption,
            originalIntentLength
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnIntent_revertsOnDeclaredSpecLengthTooSmallFuzz(BurnIntent memory intent) public {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = LONG_METADATA;
        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);
        uint256 originalIntentLength = encodedIntent.length;
        uint32 originalSpecLength = uint32(originalIntentLength - BURN_INTENT_TRANSFER_SPEC_OFFSET);

        uint32 invalidSpecLength = originalSpecLength - 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        bytes memory corruptedData = cloneBytes(encodedIntent);
        for (uint8 i = 0; i < 4; i++) {
            corruptedData[BURN_INTENT_TRANSFER_SPEC_LENGTH_OFFSET + i] = encodedInvalidLength[i];
        }

        uint256 expectedIntentLengthBasedOnCorruption = BURN_INTENT_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadOverallLengthMismatch.selector,
            expectedIntentLengthBasedOnCorruption,
            originalIntentLength
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnIntent_revertsOnTruncatedDataFuzz(BurnIntent memory intent) public {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = LONG_METADATA;
        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);
        uint256 expectedLength = encodedIntent.length;

        bytes memory truncatedData = new bytes(expectedLength - 1);
        for (uint256 i = 0; i < truncatedData.length; i++) {
            truncatedData[i] = encodedIntent[i];
        }
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadOverallLengthMismatch.selector, expectedLength, truncatedData.length
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_burnIntent_revertsOnTrailingBytesFuzz(BurnIntent memory intent) public {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = LONG_METADATA;
        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);
        uint256 originalIntentLength = encodedIntent.length;

        bytes memory corruptedData = bytes.concat(encodedIntent, hex"FFFF");
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadOverallLengthMismatch.selector, originalIntentLength, corruptedData.length
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
    function test_validate_innerSpec_revertsOnCorruptedMagicFuzz(BurnIntent memory intent) public {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = LONG_METADATA;
        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);

        encodedIntent[BURN_INTENT_TRANSFER_SPEC_OFFSET] = hex"00";

        bytes4 corruptedMagic;
        uint256 offset = BURN_INTENT_TRANSFER_SPEC_OFFSET;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedIntent[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData =
            abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecMagic.selector, corruptedMagic);

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(encodedIntent);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDataTooShortForHeaderFuzz(BurnIntent memory intent) public {
        uint32 incorrectSpecLength = TRANSFER_SPEC_METADATA_OFFSET - 1;
        bytes memory dummySpecData =
            abi.encodePacked(TRANSFER_SPEC_MAGIC, new bytes(incorrectSpecLength - BYTES4_BYTES));
        bytes memory corruptedData = abi.encodePacked(
            BURN_INTENT_MAGIC, intent.maxBlockHeight, intent.maxFee, incorrectSpecLength, dummySpecData
        );
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecHeaderTooShort.selector, TRANSFER_SPEC_METADATA_OFFSET, incorrectSpecLength
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnInvalidVersionFuzz(BurnIntent memory intent) public {
        uint32 invalidVersion = TRANSFER_SPEC_VERSION + 1;
        intent.spec.version = invalidVersion;
        intent.spec.metadata = LONG_METADATA;

        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecVersion.selector, invalidVersion));
        BurnIntentLib._validate(encodedIntent);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDeclaredMetadataLengthTooBigFuzz(BurnIntent memory intent) public {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = LONG_METADATA;
        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);
        uint32 originalMetadataLength = uint32(intent.spec.metadata.length);
        uint32 originalInnerSpecLength = uint32(encodedIntent.length - BURN_INTENT_TRANSFER_SPEC_OFFSET);

        (bytes memory corruptedData, uint32 corruptedMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedIntent,
            BURN_INTENT_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within BurnIntent
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
    function test_validate_innerSpec_revertsOnDeclaredMetadataLengthTooSmallFuzz(BurnIntent memory intent) public {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = LONG_METADATA;
        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);
        uint32 originalMetadataLength = uint32(intent.spec.metadata.length);
        uint32 originalInnerSpecLength = uint32(encodedIntent.length - BURN_INTENT_TRANSFER_SPEC_OFFSET);

        (bytes memory corruptedData, uint32 corruptedMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedIntent,
            BURN_INTENT_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within BurnIntent
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

    function test_cursor_successFuzz(BurnIntent memory intent) public pure {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = LONG_METADATA;
        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);
        bytes29 intentView = BurnIntentLib._asIntentOrSetView(encodedIntent);

        // Initial state
        Cursor memory cursor = BurnIntentLib.cursor(encodedIntent);
        assertEq(cursor.memView, intentView);
        assertEq(cursor.offset, 0);
        assertEq(cursor.numElements, 1);
        assertEq(cursor.index, 0);
        assertEq(cursor.done, false);

        // Advance the cursor
        bytes29 currentIntent = cursor.next();
        assertEq(currentIntent, intentView);
        assertEq(cursor.memView, intentView);
        assertEq(cursor.offset, encodedIntent.length);
        assertEq(cursor.numElements, 1);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDoneFuzz(BurnIntent memory intent) public {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = LONG_METADATA;
        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);

        Cursor memory cursor = BurnIntentLib.cursor(encodedIntent);
        cursor.next();
        assertEq(cursor.done, true);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    // ===== Field Accessor Tests =====

    function test_burnIntent_readAllFieldsEmptyMetadataFuzz(BurnIntent memory intent) public pure {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = new bytes(0);
        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);
        bytes29 ref = BurnIntentLib._asIntentOrSetView(encodedIntent);
        _verifyBurnIntentFieldsFromView(ref, intent);
    }

    function test_burnIntent_readAllFieldsShortMetadataFuzz(BurnIntent memory intent) public pure {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = SHORT_METADATA;
        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);
        bytes29 ref = BurnIntentLib._asIntentOrSetView(encodedIntent);
        _verifyBurnIntentFieldsFromView(ref, intent);
    }

    function test_burnIntent_readAllFieldsLongMetadataFuzz(BurnIntent memory intent) public pure {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = LONG_METADATA;
        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);
        bytes29 ref = BurnIntentLib._asIntentOrSetView(encodedIntent);
        _verifyBurnIntentFieldsFromView(ref, intent);
    }
}
