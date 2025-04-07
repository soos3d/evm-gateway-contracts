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
import {BurnAuthorization, BURN_AUTHORIZATION_MAGIC} from "src/lib/authorizations/BurnAuthorizations.sol";
import {AuthorizationLib} from "src/lib/authorizations/AuthorizationLib.sol";
import {TypedMemView} from "@memview-sol/TypedMemView.sol";

contract BurnAuthorizationTest is AuthorizationTestUtils {
    using AuthorizationLib for bytes;
    using AuthorizationLib for bytes29;

    // ===== Casting Tests =====

    function test_asBurnAuthorization_correctMagic() public pure {
        (bytes memory data, uint40 magicType) = _magic("circle.gateway.BurnAuthorization");
        bytes29 ref = data.asBurnAuthorization();
        assertEq(TypedMemView.typeOf(ref), magicType);
        assertEq(bytes4(uint32(magicType)), BURN_AUTHORIZATION_MAGIC);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asBurnAuthorization_incorrectMagic() public {
        (bytes memory data,) = _magic("something else");
        vm.expectRevert(abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorization.selector, data));
        data.asBurnAuthorization();
    }

    // ===== Direct Validation Tests =====

    function test_validateBurnAuthorization_successFuzz(BurnAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);
        bytes29 authView = encodedAuth.asBurnAuthorization();
        AuthorizationLib.validateBurnAuthorization(authView);
    }

    // ===== Field Accessor Tests =====

    function test_burnAuthorization_readAllFieldsEmptyMetadataFuzz(BurnAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = new bytes(0);
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);
        bytes29 ref = encodedAuth.asBurnAuthorization();
        _verifyBurnAuthorizationFieldsFromView(ref, auth);
    }

    function test_burnAuthorization_readAllFieldsShortMetadataFuzz(BurnAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = SHORT_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);
        bytes29 ref = encodedAuth.asBurnAuthorization();
        _verifyBurnAuthorizationFieldsFromView(ref, auth);
    }

    function test_burnAuthorization_readAllFieldsLongMetadataFuzz(BurnAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);
        bytes29 ref = encodedAuth.asBurnAuthorization();
        _verifyBurnAuthorizationFieldsFromView(ref, auth);
    }

    // ===== Encode/Decode Round Trip Tests =====

    function test_encodeDecode_roundTrip_emptySpecMetadataFuzz(BurnAuthorization memory originalAuth) public view {
        originalAuth.spec.version = TRANSFER_SPEC_VERSION;
        originalAuth.spec.metadata = new bytes(0);
        bytes memory encoded = AuthorizationLib.encodeBurnAuthorization(originalAuth);
        BurnAuthorization memory decodedAuth = AuthorizationLib.decodeBurnAuthorization(encoded);
        _assertBurnAuthorizationsEqual(decodedAuth, originalAuth);
    }

    function test_encodeDecode_roundTrip_shortSpecMetadataFuzz(BurnAuthorization memory originalAuth) public view {
        originalAuth.spec.version = TRANSFER_SPEC_VERSION;
        originalAuth.spec.metadata = SHORT_METADATA;
        bytes memory encoded = AuthorizationLib.encodeBurnAuthorization(originalAuth);
        BurnAuthorization memory decodedAuth = AuthorizationLib.decodeBurnAuthorization(encoded);
        _assertBurnAuthorizationsEqual(decodedAuth, originalAuth);
    }

    function test_encodeDecode_roundTrip_longSpecMetadataFuzz(BurnAuthorization memory originalAuth) public view {
        originalAuth.spec.version = TRANSFER_SPEC_VERSION;
        originalAuth.spec.metadata = LONG_METADATA;
        bytes memory encoded = AuthorizationLib.encodeBurnAuthorization(originalAuth);
        BurnAuthorization memory decodedAuth = AuthorizationLib.decodeBurnAuthorization(encoded);
        _assertBurnAuthorizationsEqual(decodedAuth, originalAuth);
    }

    // ===== Decode Failures: Outer BurnAuthorization struct Consistency Tests =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_burnAuth_revertsOnDataTooShortForMagic() public {
        bytes memory shorterThanMagic = new bytes(2);
        vm.expectRevert(
            bytes(
                string.concat(
                    "TypedMemView/index - Overran the view. ",
                    "Slice is at 0x0000a0 with length 0x000002. ",
                    "Attempted to index at offset 0x000000 with length 0x000004."
                )
            )
        );
        AuthorizationLib.decodeBurnAuthorization(shorterThanMagic);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_burnAuth_revertsOnCorruptedMagicFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);

        // Corrupt the first byte of the BurnAuthorization magic
        encodedAuth[0] = hex"FF";
        vm.expectRevert(abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorization.selector, encodedAuth));
        AuthorizationLib.decodeBurnAuthorization(encodedAuth);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_burnAuth_revertsOnDataTooShortForHeaderFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        bytes memory validEncodedBurnAuth = AuthorizationLib.encodeBurnAuthorization(auth);

        uint16 truncatedLength = BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET - 1;
        bytes memory shortData = new bytes(truncatedLength);
        for (uint16 i = 0; i < truncatedLength; i++) {
            shortData[i] = validEncodedBurnAuth[i];
        }
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedBurnAuthorizationInvalidLength.selector,
            BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET,
            shortData.length
        );

        bytes29 authView = shortData.asBurnAuthorization();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateBurnAuthorization(authView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeBurnAuthorization(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_burnAuth_revertsOnDeclaredSpecLengthTooBigFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);
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
            AuthorizationLib.MalformedBurnAuthorizationInvalidLength.selector,
            expectedAuthLengthBasedOnCorruption,
            originalAuthLength
        );

        bytes29 authView = corruptedData.asBurnAuthorization();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateBurnAuthorization(authView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeBurnAuthorization(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_burnAuth_revertsOnDeclaredSpecLengthTooSmallFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);
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
            AuthorizationLib.MalformedBurnAuthorizationInvalidLength.selector,
            expectedAuthLengthBasedOnCorruption,
            originalAuthLength
        );

        bytes29 authView = corruptedData.asBurnAuthorization();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateBurnAuthorization(authView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeBurnAuthorization(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_burnAuth_revertsOnTruncatedDataFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);
        uint256 expectedLength = encodedAuth.length;

        bytes memory truncatedData = new bytes(expectedLength - 1);
        for (uint256 i = 0; i < truncatedData.length; i++) {
            truncatedData[i] = encodedAuth[i];
        }
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedBurnAuthorizationInvalidLength.selector, expectedLength, truncatedData.length
        );

        bytes29 authView = truncatedData.asBurnAuthorization();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateBurnAuthorization(authView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeBurnAuthorization(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_burnAuth_revertsOnTrailingBytesFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);
        uint256 originalAuthLength = encodedAuth.length;

        bytes memory corruptedData = bytes.concat(encodedAuth, hex"FFFF");
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedBurnAuthorizationInvalidLength.selector, originalAuthLength, corruptedData.length
        );

        bytes29 authView = corruptedData.asBurnAuthorization();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateBurnAuthorization(authView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeBurnAuthorization(corruptedData);
    }

    // ===== Decode Failures: Inner TransferSpec Consistency Tests =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnDataTooShortForMagic() public {
        uint256 fixedMaxBlockHeight = 1;
        uint256 fixedMaxFee = 1;
        uint32 incorrectSpecLength = 2;
        bytes memory corruptedData = abi.encodePacked(
            BURN_AUTHORIZATION_MAGIC,
            fixedMaxBlockHeight,
            fixedMaxFee,
            incorrectSpecLength,
            hex"0000" // Dummy spec data
        );

        bytes memory expectedRevertData = bytes(
            string.concat(
                "TypedMemView/index - Overran the view. ",
                "Slice is at 0x0000e8 with length 0x000002. ", // The length is the incorrectSpecLength (2)
                "Attempted to index at offset 0x000000 with length 0x000004." // Trying to read 4 byte magic
            )
        );

        bytes29 authView = corruptedData.asBurnAuthorization();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateBurnAuthorization(authView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeBurnAuthorization(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnCorruptedMagicFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);

        encodedAuth[BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET] = hex"FF";
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedTransferSpec.selector, "Invalid TransferSpec magic in BurnAuthorization"
        );

        bytes29 authView = encodedAuth.asBurnAuthorization();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateBurnAuthorization(authView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeBurnAuthorization(encodedAuth);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnDataTooShortForHeaderFuzz(BurnAuthorization memory auth) public {
        uint32 incorrectSpecLength = TRANSFER_SPEC_METADATA_OFFSET - 1;
        bytes memory dummySpecData = abi.encodePacked(TRANSFER_SPEC_MAGIC, new bytes(incorrectSpecLength - 4));
        bytes memory corruptedData = abi.encodePacked(
            BURN_AUTHORIZATION_MAGIC, auth.maxBlockHeight, auth.maxFee, incorrectSpecLength, dummySpecData
        );
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
            TRANSFER_SPEC_METADATA_OFFSET,
            incorrectSpecLength
        );

        bytes29 authView = corruptedData.asBurnAuthorization();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateBurnAuthorization(authView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeBurnAuthorization(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnDeclaredMetadataLengthTooBigFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);
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
            AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
            expectedInnerSpecLength, // The incorrect length expected based on corrupted field
            originalInnerSpecLength // The actual length of the original spec view
        );

        bytes29 authView = corruptedData.asBurnAuthorization();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateBurnAuthorization(authView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeBurnAuthorization(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnDeclaredMetadataLengthTooSmallFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);
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
            AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
            expectedInnerSpecLength, // The incorrect length expected based on corrupted field
            originalInnerSpecLength // The actual length of the original spec view
        );

        bytes29 authView = corruptedData.asBurnAuthorization();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateBurnAuthorization(authView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeBurnAuthorization(corruptedData);
    }
}
