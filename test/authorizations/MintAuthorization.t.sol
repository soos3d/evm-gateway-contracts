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
pragma solidity ^0.8.29;

import {TypedMemView} from "@memview-sol/TypedMemView.sol";
import {AuthorizationCursor} from "src/lib/authorizations/AuthorizationCursor.sol";
import {MintAuthorizationLib} from "src/lib/authorizations/MintAuthorizationLib.sol";
import {MintAuthorization, MINT_AUTHORIZATION_MAGIC} from "src/lib/authorizations/MintAuthorizations.sol";
import {TRANSFER_SPEC_VERSION, TRANSFER_SPEC_MAGIC} from "src/lib/authorizations/TransferSpec.sol";
import {TransferSpecLib} from "src/lib/authorizations/TransferSpecLib.sol";
import {BYTES4_BYTES} from "src/lib/authorizations/TransferSpecLib.sol";
import {AuthorizationTestUtils} from "./AuthorizationTestUtils.sol";

contract MintAuthorizationTest is AuthorizationTestUtils {
    using MintAuthorizationLib for bytes29;
    using MintAuthorizationLib for AuthorizationCursor;

    // ===== Casting Tests =====

    function test_asAuthOrSetView_successMintAuth() public pure {
        (bytes memory data, uint40 magicType) = _magic("circle.gateway.MintAuthorization");
        bytes29 ref = MintAuthorizationLib._asAuthOrSetView(data);
        assertEq(TypedMemView.typeOf(ref), magicType);
        assertEq(bytes4(uint32(magicType)), MINT_AUTHORIZATION_MAGIC);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asAuthOrSetView_revertsOnShortData() public {
        bytes memory shortData = hex"1122";
        vm.expectRevert(
            abi.encodeWithSelector(TransferSpecLib.AuthorizationDataTooShort.selector, BYTES4_BYTES, shortData.length)
        );
        MintAuthorizationLib._asAuthOrSetView(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asAuthOrSetView_revertsOnInvalidMagic4Bytes() public {
        (bytes memory invalidMagicData,) = _magic("not a valid magic");
        bytes4 incorrectMagic = bytes4(invalidMagicData);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidAuthorizationMagic.selector, incorrectMagic));
        MintAuthorizationLib._asAuthOrSetView(invalidMagicData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asAuthOrSetView_revertsOnInvalidMagicLonger() public {
        (bytes memory invalidMagicData,) = _magic("not a valid magic");
        bytes memory longerInvalidMagic = bytes.concat(invalidMagicData, hex"01020304");
        bytes4 incorrectMagic = bytes4(longerInvalidMagic);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidAuthorizationMagic.selector, incorrectMagic));
        MintAuthorizationLib._asAuthOrSetView(longerInvalidMagic);
    }

    // ===== Validation Tests =====

    function test_validate_successFuzz(MintAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        MintAuthorizationLib._validate(encodedAuth);
    }

    // ===== Validation Failures: Mint Authorization Structure =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_mintAuth_revertsOnDataTooShortForHeaderFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        bytes memory validEncodedMintAuth = MintAuthorizationLib.encodeMintAuthorization(auth);

        uint16 truncatedLength = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET - 1;
        bytes memory shortData = new bytes(truncatedLength);
        for (uint16 i = 0; i < truncatedLength; i++) {
            shortData[i] = validEncodedMintAuth[i];
        }
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationHeaderTooShort.selector,
            MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET,
            shortData.length
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_mintAuth_revertsOnDeclaredSpecLengthTooBigFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        uint256 originalAuthLength = encodedAuth.length;
        uint32 originalSpecLength = uint32(originalAuthLength - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        uint32 invalidSpecLength = originalSpecLength + 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        bytes memory corruptedData = cloneBytes(encodedAuth);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            corruptedData[MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET + i] = encodedInvalidLength[i];
        }

        uint256 expectedAuthLengthBasedOnCorruption = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationOverallLengthMismatch.selector,
            expectedAuthLengthBasedOnCorruption,
            originalAuthLength
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_mintAuth_revertsOnDeclaredSpecLengthTooSmallFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        uint256 originalAuthLength = encodedAuth.length;
        uint32 originalSpecLength = uint32(originalAuthLength - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        uint32 invalidSpecLength = originalSpecLength - 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        bytes memory corruptedData = cloneBytes(encodedAuth);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            corruptedData[MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET + i] = encodedInvalidLength[i];
        }

        uint256 expectedAuthLengthBasedOnCorruption = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationOverallLengthMismatch.selector,
            expectedAuthLengthBasedOnCorruption,
            originalAuthLength
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_mintAuth_revertsOnTruncatedDataFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        uint256 expectedLength = encodedAuth.length;

        bytes memory truncatedData = new bytes(expectedLength - 1);
        for (uint256 i = 0; i < truncatedData.length; i++) {
            truncatedData[i] = encodedAuth[i];
        }
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationOverallLengthMismatch.selector, expectedLength, truncatedData.length
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_mintAuth_revertsOnTrailingBytesFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        uint256 originalAuthLength = encodedAuth.length;

        bytes memory corruptedData = bytes.concat(encodedAuth, hex"FFFF");
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.AuthorizationOverallLengthMismatch.selector, originalAuthLength, corruptedData.length
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(corruptedData);
    }

    // ===== Validation Failures: Inner TransferSpec Consistency =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDataTooShortForMagic() public {
        uint256 fixedMaxBlockHeight = 1;
        uint32 incorrectSpecLength = 2;

        bytes memory corruptedData =
            abi.encodePacked(MINT_AUTHORIZATION_MAGIC, fixedMaxBlockHeight, incorrectSpecLength, hex"0000");

        bytes memory expectedRevertData = bytes(
            string.concat(
                "TypedMemView/index - Overran the view. ",
                "Slice is at 0x0000c8 with length 0x000002. ", // The length is the incorrectSpecLength (2)
                "Attempted to index at offset 0x000000 with length 0x000004." // Trying to read 4 byte magic
            )
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnCorruptedMagicFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);

        encodedAuth[MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET] = hex"FF";

        bytes4 corruptedMagic;
        uint256 offset = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedAuth[offset + i];
        }
        corruptedMagic = bytes4(tempBytes);

        bytes memory expectedRevertData =
            abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecMagic.selector, corruptedMagic);

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(encodedAuth);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDataTooShortForHeaderFuzz(MintAuthorization memory auth) public {
        uint32 incorrectSpecLength = TRANSFER_SPEC_METADATA_OFFSET - 1;
        bytes memory dummySpecData =
            abi.encodePacked(TRANSFER_SPEC_MAGIC, new bytes(incorrectSpecLength - BYTES4_BYTES));
        bytes memory corruptedData =
            abi.encodePacked(MINT_AUTHORIZATION_MAGIC, auth.maxBlockHeight, incorrectSpecLength, dummySpecData);
        bytes memory expectedRevertData = abi.encodeWithSelector(
            TransferSpecLib.TransferSpecHeaderTooShort.selector, TRANSFER_SPEC_METADATA_OFFSET, incorrectSpecLength
        );

        vm.expectRevert(expectedRevertData);
        MintAuthorizationLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnInvalidVersionFuzz(MintAuthorization memory auth) public {
        uint32 invalidVersion = TRANSFER_SPEC_VERSION + 1;
        auth.spec.version = invalidVersion;
        auth.spec.metadata = LONG_METADATA;

        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecVersion.selector, invalidVersion));
        MintAuthorizationLib._validate(encodedAuth);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDeclaredMetadataLengthTooBigFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        uint32 originalMetadataLength = uint32(auth.spec.metadata.length);
        uint32 originalInnerSpecLength = uint32(encodedAuth.length - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        (bytes memory corruptedData, uint32 corruptedMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedAuth,
            MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within MintAuth
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
        MintAuthorizationLib._validate(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_validate_innerSpec_revertsOnDeclaredMetadataLengthTooSmallFuzz(MintAuthorization memory auth)
        public
    {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        uint32 originalMetadataLength = uint32(auth.spec.metadata.length);
        uint32 originalInnerSpecLength = uint32(encodedAuth.length - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        (bytes memory corruptedData, uint32 corruptedMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedAuth,
            MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within MintAuth
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
        MintAuthorizationLib._validate(corruptedData);
    }

    // ===== Iteration Tests =====

    function test_cursor_successFuzz(MintAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        bytes29 authView = MintAuthorizationLib._asAuthOrSetView(encodedAuth);

        // Initial state
        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(encodedAuth);
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
    function test_cursor_revertsOnNextWhenDoneFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);

        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(encodedAuth);
        cursor.next();
        assertEq(cursor.done, true);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.CursorOutOfBounds.selector));
        cursor.next();
    }

    // ===== Field Accessor Tests =====

    function test_mintAuthorization_readAllFieldsEmptyMetadataFuzz(MintAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = new bytes(0);
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        bytes29 ref = MintAuthorizationLib._asAuthOrSetView(encodedAuth);
        _verifyMintAuthorizationFieldsFromView(ref, auth);
    }

    function test_mintAuthorization_readAllFieldsShortMetadataFuzz(MintAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = SHORT_METADATA;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        bytes29 ref = MintAuthorizationLib._asAuthOrSetView(encodedAuth);
        _verifyMintAuthorizationFieldsFromView(ref, auth);
    }

    function test_mintAuthorization_readAllFieldsLongMetadataFuzz(MintAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        bytes29 ref = MintAuthorizationLib._asAuthOrSetView(encodedAuth);
        _verifyMintAuthorizationFieldsFromView(ref, auth);
    }
}
