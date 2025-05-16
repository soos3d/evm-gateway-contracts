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
import {BurnIntentLib} from "src/lib/BurnIntentLib.sol";
import {BurnIntent, BurnIntentSet, BURN_INTENT_SET_MAGIC, BURN_INTENT_MAGIC_OFFSET} from "src/lib/BurnIntents.sol";
import {Cursor} from "src/lib/Cursor.sol";
import {TRANSFER_SPEC_VERSION} from "src/lib/TransferSpec.sol";
import {TransferSpecLib} from "src/lib/TransferSpecLib.sol";
import {BYTES4_BYTES, TRANSFER_SPEC_METADATA_OFFSET} from "src/lib/TransferSpecLib.sol";
import {TransferPayloadTestUtils} from "test/util/TransferPayloadTestUtils.sol";

contract BurnIntentSetTest is TransferPayloadTestUtils {
    using BurnIntentLib for bytes29;
    using BurnIntentLib for Cursor;

    uint16 private constant BURN_INTENT_SET_INTENTS_OFFSET = 8;

    /// @notice Helper to create a BurnIntentSet with two intents and specified metadata.
    function _createBurnIntentSet(BurnIntent memory intent1, BurnIntent memory intent2, bytes memory metadata)
        internal
        pure
        returns (BurnIntentSet memory)
    {
        intent1.spec.version = TRANSFER_SPEC_VERSION;
        intent1.spec.metadata = metadata;
        intent2.spec.version = TRANSFER_SPEC_VERSION;
        intent2.spec.metadata = metadata;

        BurnIntent[] memory intents = new BurnIntent[](2);
        intents[0] = intent1;
        intents[1] = intent2;

        return BurnIntentSet({intents: intents});
    }

    /// @notice Internal helper to verify all fields from encoded set bytes match the original struct.
    function _verifyEncodedSetFieldsAgainstStruct(bytes memory encodedIntentSet, BurnIntentSet memory intentSet)
        internal
        pure
    {
        bytes29 setRef = BurnIntentLib._asIntentOrSetView(encodedIntentSet);
        uint32 numIntents = setRef.getNumIntents();
        assertEq(numIntents, intentSet.intents.length, "Eq Fail: numIntents");

        Cursor memory cursor = BurnIntentLib.cursor(encodedIntentSet);
        uint32 i = 0;
        bytes29 intentRef;
        while (!cursor.done) {
            intentRef = cursor.next();
            _verifyBurnIntentFieldsFromView(intentRef, intentSet.intents[i]);
            i++;
        }
        assertEq(i, numIntents, "Loop iteration count mismatch");
    }

    // ===== Casting Tests =====

    function test_asIntentOrSetView_successBurnIntentSet() public pure {
        (bytes memory data, uint40 expectedType) = _magic("circle.gateway.BurnIntentSet");
        bytes29 ref = BurnIntentLib._asIntentOrSetView(data);
        assertEq(TypedMemView.typeOf(ref), expectedType);
        assertEq(bytes4(uint32(expectedType)), BURN_INTENT_SET_MAGIC);
    }

    // ===== Validation Tests =====

    function test_validateBurnIntentSet_successFuzz(BurnIntent memory intent1, BurnIntent memory intent2) public pure {
        BurnIntentSet memory intentSet = _createBurnIntentSet(intent1, intent2, LONG_METADATA);
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);
        BurnIntentLib._validate(encodedIntentSet);
    }

    // ===== Validation Failures: Set Structure =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_encode_tooLongSet() public {
        // Create an empty BurnIntentSet
        BurnIntent[] memory intents = new BurnIntent[](0);
        BurnIntentSet memory intentSet = BurnIntentSet({intents: intents});

        // Simulate an array with a size of `type(uint32).max + 1`
        uint256 maxSize = uint256(type(uint32).max);
        assembly {
            mstore(intents, add(maxSize, 1))
        }

        // Expect it to revert since the array is too long
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.TransferPayloadSetTooManyElements.selector, maxSize));
        BurnIntentLib.encodeBurnIntentSet(intentSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnDataTooShortForHeader() public {
        // Length is > magic (4) but < header (8)
        bytes memory shortData = abi.encodePacked(BURN_INTENT_SET_MAGIC, hex"112233"); // 7 bytes
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetHeaderTooShort.selector, BURN_INTENT_SET_INTENTS_OFFSET, shortData.length
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnEmptyIntentsWithTrailingBytes() public {
        bytes memory encodedSetHeader = abi.encodePacked(
            BURN_INTENT_SET_MAGIC,
            uint32(0) // numIntents = 0
        );
        bytes memory trailingBytesData = bytes.concat(encodedSetHeader, hex"FFFF");

        uint256 expectedLength = encodedSetHeader.length;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetOverallLengthMismatch.selector, expectedLength, trailingBytesData.length
        );
        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(trailingBytesData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BeforeFirstIntentHeader() public {
        // Set numIntents = 1 but provide only the set header
        bytes memory encodedSetHeaderOnly = abi.encodePacked(
            BURN_INTENT_SET_MAGIC,
            uint32(1) // numIntents = 1
        ); // 8 bytes total
        uint32 elementIndex = 0;
        uint256 requiredOffset = BURN_INTENT_SET_INTENTS_OFFSET + BURN_INTENT_TRANSFER_SPEC_OFFSET;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetElementHeaderTooShort.selector,
            elementIndex,
            encodedSetHeaderOnly.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(encodedSetHeaderOnly);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_WithinFirstIntentHeaderFuzz(BurnIntent memory intent1)
        public
    {
        // Set numIntents = 1, provide set header + partial intent header
        intent1.spec.version = TRANSFER_SPEC_VERSION;
        intent1.spec.metadata = new bytes(0);
        bytes memory encodedIntent1 = BurnIntentLib.encodeBurnIntent(intent1);

        bytes memory encodedSetHeader = abi.encodePacked(
            BURN_INTENT_SET_MAGIC,
            uint32(1) // numIntents = 1
        );

        // Truncate the first intent header (e.g., provide only 10 bytes of it)
        uint256 partialIntentHeaderLength = BURN_INTENT_TRANSFER_SPEC_OFFSET - 1; // Ensure it's too short
        bytes memory partialIntentData = new bytes(partialIntentHeaderLength);
        for (uint256 i = 0; i < partialIntentHeaderLength; i++) {
            partialIntentData[i] = encodedIntent1[i];
        }

        bytes memory truncatedData = bytes.concat(encodedSetHeader, partialIntentData);

        uint32 elementIndex = 0;
        uint256 requiredOffset = BURN_INTENT_SET_INTENTS_OFFSET + BURN_INTENT_TRANSFER_SPEC_OFFSET;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetElementHeaderTooShort.selector,
            elementIndex,
            truncatedData.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BasedOnFirstIntentSpecLengthFuzz(BurnIntent memory intent1)
        public
    {
        // Set numIntents = 1, provide set header + full intent header + partial spec
        intent1.spec.version = TRANSFER_SPEC_VERSION;
        intent1.spec.metadata = LONG_METADATA;
        bytes memory encodedIntent1 = BurnIntentLib.encodeBurnIntent(intent1);

        bytes memory encodedSetHeader = abi.encodePacked(
            BURN_INTENT_SET_MAGIC,
            uint32(1) // numIntents = 1
        );

        // Truncate the overall data just before the end of the first intent's spec
        uint256 truncatedLength = encodedSetHeader.length + encodedIntent1.length - 1;
        bytes memory truncatedData = new bytes(truncatedLength);
        bytes memory combined = bytes.concat(encodedSetHeader, encodedIntent1);
        for (uint256 i = 0; i < truncatedLength; i++) {
            truncatedData[i] = combined[i];
        }

        uint32 elementIndex = 0;
        uint256 requiredOffset = encodedSetHeader.length + encodedIntent1.length;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetElementTooShort.selector,
            elementIndex,
            truncatedData.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_BetweenIntentsFuzz(
        BurnIntent memory intent1,
        BurnIntent memory intent2
    ) public {
        // Set numIntents = 2, provide set header + intent1 + partial intent2 header
        intent1.spec.version = TRANSFER_SPEC_VERSION;
        intent1.spec.metadata = new bytes(0);
        intent2.spec.version = TRANSFER_SPEC_VERSION;
        intent2.spec.metadata = new bytes(0);

        bytes memory encodedIntent1 = BurnIntentLib.encodeBurnIntent(intent1);
        bytes memory encodedIntent2 = BurnIntentLib.encodeBurnIntent(intent2);

        bytes memory encodedSetHeader = abi.encodePacked(
            BURN_INTENT_SET_MAGIC,
            uint32(2) // numIntents = 2
        );

        // Truncate data after intent1 and partway into intent2's header
        uint256 partialIntent2HeaderLength = BURN_INTENT_TRANSFER_SPEC_OFFSET - 1;
        bytes memory partialIntent2Data = new bytes(partialIntent2HeaderLength);
        for (uint256 i = 0; i < partialIntent2HeaderLength; i++) {
            partialIntent2Data[i] = encodedIntent2[i];
        }

        bytes memory truncatedData = bytes.concat(encodedSetHeader, encodedIntent1, partialIntent2Data);

        uint32 elementIndex = 1;
        uint256 requiredOffset =
            BURN_INTENT_SET_INTENTS_OFFSET + encodedIntent1.length + BURN_INTENT_TRANSFER_SPEC_OFFSET;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetElementHeaderTooShort.selector,
            elementIndex,
            truncatedData.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsIfDataEndsPrematurely_WithinSecondIntentFuzz(
        BurnIntent memory intent1,
        BurnIntent memory intent2
    ) public {
        // Set numIntents = 2, provide set header + intent1 + intent2 header + partial intent2 spec
        intent1.spec.version = TRANSFER_SPEC_VERSION;
        intent1.spec.metadata = new bytes(0);
        intent2.spec.version = TRANSFER_SPEC_VERSION;
        intent2.spec.metadata = new bytes(0);

        bytes memory encodedIntent1 = BurnIntentLib.encodeBurnIntent(intent1);
        bytes memory encodedIntent2 = BurnIntentLib.encodeBurnIntent(intent2);

        bytes memory encodedSetHeader = abi.encodePacked(
            BURN_INTENT_SET_MAGIC,
            uint32(2) // numIntents = 2
        );

        // Truncate data partway through the second intent's spec
        uint256 truncatedLength = encodedSetHeader.length + encodedIntent1.length + encodedIntent2.length - 1;
        bytes memory truncatedData = new bytes(truncatedLength);
        bytes memory combined = bytes.concat(encodedSetHeader, encodedIntent1, encodedIntent2);
        for (uint256 i = 0; i < truncatedLength; i++) {
            truncatedData[i] = combined[i];
        }

        uint32 elementIndex = 1;
        uint256 requiredOffset = encodedSetHeader.length + encodedIntent1.length + encodedIntent2.length;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetElementTooShort.selector,
            elementIndex,
            truncatedData.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnTrailingBytes_AfterAllIntentsFuzz(
        BurnIntent memory intent1,
        BurnIntent memory intent2
    ) public {
        intent1.spec.version = TRANSFER_SPEC_VERSION;
        intent1.spec.metadata = new bytes(0);
        intent2.spec.version = TRANSFER_SPEC_VERSION;
        intent2.spec.metadata = new bytes(0);
        BurnIntentSet memory intentSet = _createBurnIntentSet(intent1, intent2, new bytes(0));
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);

        // Add trailing bytes
        bytes memory trailingBytesData = bytes.concat(encodedIntentSet, hex"FFFF");

        uint256 expectedLength = encodedIntentSet.length;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetOverallLengthMismatch.selector, expectedLength, trailingBytesData.length
        );
        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(trailingBytesData);
    }

    // ===== Validation Failures: Inner Intent Consistency =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerIntent_CorruptedMagic_InFirstFuzz(
        BurnIntent memory intent1,
        BurnIntent memory intent2
    ) public {
        intent1.spec.version = TRANSFER_SPEC_VERSION;
        intent1.spec.metadata = new bytes(0);
        intent2.spec.version = TRANSFER_SPEC_VERSION;
        intent2.spec.metadata = new bytes(0);
        BurnIntentSet memory intentSet = _createBurnIntentSet(intent1, intent2, new bytes(0));
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);

        // Corrupt the magic of the first intent (at offset 8)
        encodedIntentSet[BURN_INTENT_SET_INTENTS_OFFSET] = hex"00";

        uint32 elementIndex = 0;
        bytes4 corruptedMagic;
        uint256 offset = BURN_INTENT_SET_INTENTS_OFFSET + BURN_INTENT_MAGIC_OFFSET;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedIntentSet[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetInvalidElementMagic.selector, elementIndex, corruptedMagic
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(encodedIntentSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerIntent_CorruptedMagic_InSecondFuzz(
        BurnIntent memory intent1,
        BurnIntent memory intent2
    ) public {
        intent1.spec.version = TRANSFER_SPEC_VERSION;
        intent1.spec.metadata = new bytes(0);
        intent2.spec.version = TRANSFER_SPEC_VERSION;
        intent2.spec.metadata = new bytes(0);
        BurnIntentSet memory intentSet = _createBurnIntentSet(intent1, intent2, new bytes(0));
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);

        // Calculate offset of second intent's magic
        bytes memory encodedIntent1 = BurnIntentLib.encodeBurnIntent(intentSet.intents[0]);
        uint256 secondIntentOffset = BURN_INTENT_SET_INTENTS_OFFSET + encodedIntent1.length;

        // Corrupt the magic of the second intent
        encodedIntentSet[secondIntentOffset] = hex"00";

        uint32 elementIndex = 1;
        bytes4 corruptedMagic;
        uint256 offset = secondIntentOffset + BURN_INTENT_MAGIC_OFFSET;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedIntentSet[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetInvalidElementMagic.selector, elementIndex, corruptedMagic
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(encodedIntentSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerIntent_DeclaredSpecLengthTooSmallFuzz(BurnIntent memory intent1) public {
        intent1.spec.version = TRANSFER_SPEC_VERSION;
        intent1.spec.metadata = LONG_METADATA;

        BurnIntent[] memory intents = new BurnIntent[](1);
        intents[0] = intent1;
        BurnIntentSet memory intentSet = BurnIntentSet({intents: intents});
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);

        bytes memory encodedIntent1 = BurnIntentLib.encodeBurnIntent(intent1);
        uint256 originalIntentLength = encodedIntent1.length;
        uint32 originalSpecLength = uint32(originalIntentLength - BURN_INTENT_TRANSFER_SPEC_OFFSET);
        uint32 originalMetadataLength = uint32(intent1.spec.metadata.length);

        // Corrupt the outer BurnIntent's declared spec length (make it smaller)
        uint256 outerSpecLengthOffset = BURN_INTENT_SET_INTENTS_OFFSET + BURN_INTENT_TRANSFER_SPEC_LENGTH_OFFSET;
        uint32 invalidSpecLength = originalSpecLength - 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        for (uint8 i = 0; i < 4; i++) {
            encodedIntentSet[outerSpecLengthOffset + i] = encodedInvalidLength[i];
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
        BurnIntentLib._validate(encodedIntentSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerIntent_DeclaredSpecLengthTooBigFuzz(BurnIntent memory intent1) public {
        intent1.spec.version = TRANSFER_SPEC_VERSION;
        intent1.spec.metadata = LONG_METADATA;

        BurnIntent[] memory intents = new BurnIntent[](1);
        intents[0] = intent1;
        BurnIntentSet memory intentSet = BurnIntentSet({intents: intents});
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);

        bytes memory encodedIntent1 = BurnIntentLib.encodeBurnIntent(intent1);
        uint256 originalIntentLength = encodedIntent1.length;
        uint32 originalSpecLength = uint32(originalIntentLength - BURN_INTENT_TRANSFER_SPEC_OFFSET);

        // Corrupt the outer BurnIntent's declared spec length (make it larger)
        uint256 outerSpecLengthOffset = BURN_INTENT_SET_INTENTS_OFFSET + BURN_INTENT_TRANSFER_SPEC_LENGTH_OFFSET;
        uint32 invalidSpecLength = originalSpecLength + 1; // Make it larger than actual
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        for (uint8 i = 0; i < 4; i++) {
            encodedIntentSet[outerSpecLengthOffset + i] = encodedInvalidLength[i];
        }

        // The failure occurs in the main validation loop when checking if the set data
        // is long enough to contain the intent based on its inflated declared length.
        uint32 elementIndex = 0;
        uint256 requiredOffset = BURN_INTENT_SET_INTENTS_OFFSET + BURN_INTENT_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferPayloadSetElementTooShort.selector,
            elementIndex,
            encodedIntentSet.length,
            requiredOffset
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(encodedIntentSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_CorruptedMagicFuzz(BurnIntent memory intent1) public {
        intent1.spec.version = TRANSFER_SPEC_VERSION;
        intent1.spec.metadata = LONG_METADATA;

        BurnIntent[] memory intents = new BurnIntent[](1);
        intents[0] = intent1;
        BurnIntentSet memory intentSet = BurnIntentSet({intents: intents});
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);

        // Corrupt the inner TransferSpec magic within the first intent
        uint256 innerSpecMagicOffset = BURN_INTENT_SET_INTENTS_OFFSET + BURN_INTENT_TRANSFER_SPEC_OFFSET;
        encodedIntentSet[innerSpecMagicOffset] = hex"00";

        bytes4 corruptedMagic;
        uint256 offset = innerSpecMagicOffset;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedIntentSet[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData =
            abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecMagic.selector, corruptedMagic);

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(encodedIntentSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_InvalidVersionFuzz(
        BurnIntent memory intent1,
        BurnIntent memory intent2
    ) public {
        // The inner TransferSpec of the second intent has an invalid version
        uint32 invalidVersion = TRANSFER_SPEC_VERSION + 1;
        intent1.spec.version = TRANSFER_SPEC_VERSION;
        intent1.spec.metadata = new bytes(0);
        intent2.spec.version = invalidVersion;
        intent2.spec.metadata = new bytes(0);

        BurnIntent[] memory intents = new BurnIntent[](2);
        intents[0] = intent1;
        intents[1] = intent2;
        BurnIntentSet memory intentSet = BurnIntentSet({intents: intents});
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecVersion.selector, invalidVersion));
        BurnIntentLib._validate(encodedIntentSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_DeclaredMetadataLengthTooBigFuzz(BurnIntent memory intent1) public {
        intent1.spec.version = TRANSFER_SPEC_VERSION;
        intent1.spec.metadata = LONG_METADATA;

        BurnIntent[] memory intents = new BurnIntent[](1);
        intents[0] = intent1;
        BurnIntentSet memory intentSet = BurnIntentSet({intents: intents});
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);

        uint32 originalMetadataLength = uint32(intent1.spec.metadata.length);
        uint256 encodedIntent1Length = encodedIntentSet.length - BURN_INTENT_SET_INTENTS_OFFSET;
        uint32 actualInnerSpecLength = uint32(encodedIntent1Length - BURN_INTENT_TRANSFER_SPEC_OFFSET);

        uint32 specOffset = BURN_INTENT_SET_INTENTS_OFFSET + BURN_INTENT_TRANSFER_SPEC_OFFSET;
        (bytes memory corruptedEncodedIntentSet, uint32 invalidMetadataLength) =
        _getCorruptedInnerSpecMetadataLengthData(
            encodedIntentSet,
            specOffset,
            originalMetadataLength,
            true // makeLengthBigger = true
        );

        uint256 expectedInnerSpecLength = TRANSFER_SPEC_METADATA_OFFSET + invalidMetadataLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecOverallLengthMismatch.selector, expectedInnerSpecLength, actualInnerSpecLength
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(corruptedEncodedIntentSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_set_revertsOnInnerSpec_DeclaredMetadataLengthTooSmallFuzz(BurnIntent memory intent1)
        public
    {
        intent1.spec.version = TRANSFER_SPEC_VERSION;
        intent1.spec.metadata = LONG_METADATA;

        BurnIntent[] memory intents = new BurnIntent[](1);
        intents[0] = intent1;
        BurnIntentSet memory intentSet = BurnIntentSet({intents: intents});
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);

        uint32 originalMetadataLength = uint32(intent1.spec.metadata.length);
        uint256 encodedIntent1Length = encodedIntentSet.length - BURN_INTENT_SET_INTENTS_OFFSET;
        uint32 actualInnerSpecLength = uint32(encodedIntent1Length - BURN_INTENT_TRANSFER_SPEC_OFFSET);

        uint32 specOffset = BURN_INTENT_SET_INTENTS_OFFSET + BURN_INTENT_TRANSFER_SPEC_OFFSET;
        (bytes memory corruptedEncodedIntentSet, uint32 invalidMetadataLength) =
        _getCorruptedInnerSpecMetadataLengthData(
            encodedIntentSet,
            specOffset,
            originalMetadataLength,
            false // makeLengthBigger = false
        );

        uint256 expectedInnerSpecLength = TRANSFER_SPEC_METADATA_OFFSET + invalidMetadataLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecOverallLengthMismatch.selector, expectedInnerSpecLength, actualInnerSpecLength
        );

        vm.expectRevert(expectedRevertData);
        BurnIntentLib._validate(corruptedEncodedIntentSet);
    }

    // ===== Iteration Tests =====

    function test_cursor_emptySet() public pure {
        BurnIntent[] memory intents = new BurnIntent[](0);
        BurnIntentSet memory set = BurnIntentSet({intents: intents});
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(set);
        Cursor memory cursor = BurnIntentLib.cursor(encodedIntentSet);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenEmptySet() public {
        BurnIntent[] memory intents = new BurnIntent[](0);
        BurnIntentSet memory set = BurnIntentSet({intents: intents});
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(set);
        Cursor memory cursor = BurnIntentLib.cursor(encodedIntentSet);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    function test_cursor_singleIntentInSetFuzz(BurnIntent memory intent) public pure {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = LONG_METADATA;

        BurnIntent[] memory intents = new BurnIntent[](1);
        intents[0] = intent;
        BurnIntentSet memory intentSet = BurnIntentSet({intents: intents});
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);
        bytes29 setRef = BurnIntentLib._asIntentOrSetView(encodedIntentSet);

        Cursor memory cursor = BurnIntentLib.cursor(encodedIntentSet);

        // Initial state
        assertEq(cursor.done, false);
        assertEq(cursor.memView, setRef);
        assertEq(cursor.offset, BURN_INTENT_SET_INTENTS_OFFSET);
        assertEq(cursor.numElements, 1);
        assertEq(cursor.index, 0);

        bytes memory encodedIntent = BurnIntentLib.encodeBurnIntent(intent);
        uint256 expectedOffset = BURN_INTENT_SET_INTENTS_OFFSET + encodedIntent.length;

        // Advance cursor and verify first intent
        bytes29 currentIntent = cursor.next();
        _verifyBurnIntentFieldsFromView(currentIntent, intent);
        assertEq(cursor.memView, setRef);
        assertEq(cursor.offset, expectedOffset);
        assertEq(cursor.numElements, 1);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDone_SingleIntentFuzz(BurnIntent memory intent) public {
        intent.spec.version = TRANSFER_SPEC_VERSION;
        intent.spec.metadata = LONG_METADATA;
        BurnIntent[] memory intents = new BurnIntent[](1);
        intents[0] = intent;
        BurnIntentSet memory set = BurnIntentSet({intents: intents});
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(set);

        Cursor memory cursor = BurnIntentLib.cursor(encodedIntentSet);
        cursor.next();
        assertEq(cursor.done, true);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    function test_cursor_multipleIntentsInSetFuzz(BurnIntent memory intent1, BurnIntent memory intent2) public pure {
        BurnIntentSet memory intentSet = _createBurnIntentSet(intent1, intent2, LONG_METADATA);
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);
        bytes29 setRef = BurnIntentLib._asIntentOrSetView(encodedIntentSet);
        Cursor memory cursor = BurnIntentLib.cursor(encodedIntentSet);

        // Initial state
        assertEq(cursor.done, false);
        assertEq(cursor.memView, setRef);
        assertEq(cursor.offset, BURN_INTENT_SET_INTENTS_OFFSET);
        assertEq(cursor.numElements, 2);
        assertEq(cursor.index, 0);

        bytes memory encodedIntent1 = BurnIntentLib.encodeBurnIntent(intent1);
        uint256 expectedOffset = BURN_INTENT_SET_INTENTS_OFFSET + encodedIntent1.length;

        // Advance cursor and verify first intent
        bytes29 currentIntent = cursor.next();
        _verifyBurnIntentFieldsFromView(currentIntent, intent1);
        assertEq(cursor.memView, setRef);
        assertEq(cursor.offset, expectedOffset);
        assertEq(cursor.numElements, 2);
        assertEq(cursor.index, 1);
        assertEq(cursor.done, false);

        bytes memory encodedIntent2 = BurnIntentLib.encodeBurnIntent(intent2);
        uint256 expectedUpdatedOffset = expectedOffset + encodedIntent2.length;

        // Advance cursor and verify second intent
        currentIntent = cursor.next();
        _verifyBurnIntentFieldsFromView(currentIntent, intent2);
        assertEq(cursor.memView, setRef);
        assertEq(cursor.offset, expectedUpdatedOffset);
        assertEq(cursor.numElements, 2);
        assertEq(cursor.index, 2);
        assertEq(cursor.done, true);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_cursor_revertsOnNextWhenDone_MultipleIntentsFuzz(BurnIntent memory intent1, BurnIntent memory intent2)
        public
    {
        BurnIntentSet memory intentSet = _createBurnIntentSet(intent1, intent2, LONG_METADATA);
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);
        Cursor memory cursor = BurnIntentLib.cursor(encodedIntentSet);
        cursor.next();
        cursor.next();
        assertEq(cursor.done, true);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    // ===== Field Accessor / Set Iteration Tests =====

    function test_burnIntentSet_readsAllFieldsEmptySet() public pure {
        BurnIntent[] memory intents = new BurnIntent[](0);
        BurnIntentSet memory set = BurnIntentSet({intents: intents});
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(set);
        _verifyEncodedSetFieldsAgainstStruct(encodedIntentSet, set);
    }

    function test_burnIntentSet_readAllFieldsEmptyMetadataFuzz(BurnIntent memory intent1, BurnIntent memory intent2)
        public
        pure
    {
        BurnIntentSet memory intentSet = _createBurnIntentSet(intent1, intent2, new bytes(0));
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedIntentSet, intentSet);
    }

    function test_burnIntentSet_readAllFieldsShortMetadataFuzz(BurnIntent memory intent1, BurnIntent memory intent2)
        public
        pure
    {
        BurnIntentSet memory intentSet = _createBurnIntentSet(intent1, intent2, SHORT_METADATA);
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedIntentSet, intentSet);
    }

    function test_burnIntentSet_readAllFieldsLongMetadataFuzz(BurnIntent memory intent1, BurnIntent memory intent2)
        public
        pure
    {
        BurnIntentSet memory intentSet = _createBurnIntentSet(intent1, intent2, LONG_METADATA);
        bytes memory encodedIntentSet = BurnIntentLib.encodeBurnIntentSet(intentSet);
        _verifyEncodedSetFieldsAgainstStruct(encodedIntentSet, intentSet);
    }
}
