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

import {AuthorizationLibWrapper, AuthorizationTestUtils} from "./AuthorizationTestUtils.sol";
import {TRANSFER_SPEC_VERSION, TRANSFER_SPEC_MAGIC} from "src/lib/authorizations/TransferSpec.sol";
import {MintAuthorization, MINT_AUTHORIZATION_MAGIC} from "src/lib/authorizations/MintAuthorizations.sol";
import {AuthorizationLib} from "src/lib/authorizations/AuthorizationLib.sol";
import {TypedMemView} from "@memview-sol/TypedMemView.sol";

contract MintAuthorizationTest is AuthorizationTestUtils {
    using AuthorizationLib for bytes;
    using AuthorizationLib for bytes29;

    AuthorizationLibWrapper private wrapper;

    function setUp() public {
        wrapper = new AuthorizationLibWrapper();
    }

    // ===== Casting Tests =====

    function test_asMintAuthorization_correctMagic() public pure {
        (bytes memory data, uint40 magicType) = _magic("circle.gateway.MintAuthorization");
        bytes29 ref = data.asMintAuthorization();
        assertEq(TypedMemView.typeOf(ref), magicType);
        assertEq(bytes4(uint32(magicType)), MINT_AUTHORIZATION_MAGIC);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asMintAuthorization_incorrectMagic() public {
        (bytes memory data,) = _magic("something else");
        vm.expectRevert(abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorization.selector, data));
        data.asMintAuthorization();
    }

    // ===== Direct Validation Tests =====

    function test_validateMintAuthorization_successFuzz(MintAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);
        bytes29 authView = encodedAuth.asMintAuthorization();
        AuthorizationLib.validateMintAuthorization(authView);
    }

    // ===== Field Accessor Tests =====

    function test_mintAuthorization_readAllFieldsEmptyMetadataFuzz(MintAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = new bytes(0);
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);
        bytes29 ref = encodedAuth.asMintAuthorization();
        _verifyMintAuthorizationFieldsFromView(ref, auth);
    }

    function test_mintAuthorization_readAllFieldsShortMetadataFuzz(MintAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = SHORT_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);
        bytes29 ref = encodedAuth.asMintAuthorization();
        _verifyMintAuthorizationFieldsFromView(ref, auth);
    }

    function test_mintAuthorization_readAllFieldsLongMetadataFuzz(MintAuthorization memory auth) public pure {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);
        bytes29 ref = encodedAuth.asMintAuthorization();
        _verifyMintAuthorizationFieldsFromView(ref, auth);
    }

    // ===== Encode/Decode Round Trip Tests =====

    function test_encodeDecode_roundTrip_emptySpecMetadataFuzz(MintAuthorization memory originalAuth) public view {
        originalAuth.spec.version = TRANSFER_SPEC_VERSION;
        originalAuth.spec.metadata = new bytes(0);
        bytes memory encoded = AuthorizationLib.encodeMintAuthorization(originalAuth);
        MintAuthorization memory decodedAuth = AuthorizationLib.decodeMintAuthorization(encoded);
        _assertMintAuthorizationsEqual(decodedAuth, originalAuth);
    }

    function test_encodeDecode_roundTrip_shortSpecMetadataFuzz(MintAuthorization memory originalAuth) public view {
        originalAuth.spec.version = TRANSFER_SPEC_VERSION;
        originalAuth.spec.metadata = SHORT_METADATA;
        bytes memory encoded = AuthorizationLib.encodeMintAuthorization(originalAuth);
        MintAuthorization memory decodedAuth = AuthorizationLib.decodeMintAuthorization(encoded);
        _assertMintAuthorizationsEqual(decodedAuth, originalAuth);
    }

    function test_encodeDecode_roundTrip_longSpecMetadataFuzz(MintAuthorization memory originalAuth) public view {
        originalAuth.spec.version = TRANSFER_SPEC_VERSION;
        originalAuth.spec.metadata = LONG_METADATA;
        bytes memory encoded = AuthorizationLib.encodeMintAuthorization(originalAuth);
        MintAuthorization memory decodedAuth = AuthorizationLib.decodeMintAuthorization(encoded);
        _assertMintAuthorizationsEqual(decodedAuth, originalAuth);
    }

    // ===== Decode Failures: Outer MintAuthorization struct Consistency Tests =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_mintAuth_revertsOnDataTooShortForMagic() public {
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
        AuthorizationLib.decodeMintAuthorization(shorterThanMagic);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_mintAuth_revertsOnCorruptedMagicFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);

        // Corrupt the first byte of the MintAuthorization magic
        encodedAuth[0] = hex"FF";
        vm.expectRevert(abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorization.selector, encodedAuth));
        AuthorizationLib.decodeMintAuthorization(encodedAuth);
    }

    function test_decode_mintAuth_revertsOnDataTooShortForHeaderFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        bytes memory validEncodedMintAuth = AuthorizationLib.encodeMintAuthorization(auth);

        uint16 truncatedLength = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET - 1;
        bytes memory shortData = new bytes(truncatedLength);
        for (uint16 i = 0; i < truncatedLength; i++) {
            shortData[i] = validEncodedMintAuth[i];
        }
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedMintAuthorizationInvalidLength.selector,
            MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET,
            shortData.length
        );

        vm.expectRevert(expectedRevertData);
        wrapper.castAndValidateMintAuthorization(shortData);

        vm.expectRevert(expectedRevertData);
        wrapper.decodeMintAuthorizationWrapper(shortData);
    }

    function test_decode_mintAuth_revertsOnDeclaredSpecLengthTooBigFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);
        uint256 originalAuthLength = encodedAuth.length;
        uint32 originalSpecLength = uint32(originalAuthLength - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        uint32 invalidSpecLength = originalSpecLength + 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        bytes memory corruptedData = cloneBytes(encodedAuth);
        for (uint8 i = 0; i < 4; i++) {
            corruptedData[MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET + i] = encodedInvalidLength[i];
        }

        uint256 expectedAuthLengthBasedOnCorruption = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedMintAuthorizationInvalidLength.selector,
            expectedAuthLengthBasedOnCorruption,
            originalAuthLength
        );

        vm.expectRevert(expectedRevertData);
        wrapper.castAndValidateMintAuthorization(corruptedData);

        vm.expectRevert(expectedRevertData);
        wrapper.decodeMintAuthorizationWrapper(corruptedData);
    }

    function test_decode_mintAuth_revertsOnDeclaredSpecLengthTooSmallFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);
        uint256 originalAuthLength = encodedAuth.length;
        uint32 originalSpecLength = uint32(originalAuthLength - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        uint32 invalidSpecLength = originalSpecLength - 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
        bytes memory corruptedData = cloneBytes(encodedAuth);
        for (uint8 i = 0; i < 4; i++) {
            corruptedData[MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET + i] = encodedInvalidLength[i];
        }

        uint256 expectedAuthLengthBasedOnCorruption = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + invalidSpecLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedMintAuthorizationInvalidLength.selector,
            expectedAuthLengthBasedOnCorruption,
            originalAuthLength
        );

        vm.expectRevert(expectedRevertData);
        wrapper.castAndValidateMintAuthorization(corruptedData);

        vm.expectRevert(expectedRevertData);
        wrapper.decodeMintAuthorizationWrapper(corruptedData);
    }

    function test_decode_mintAuth_revertsOnTruncatedDataFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);
        uint256 expectedLength = encodedAuth.length;

        bytes memory truncatedData = new bytes(expectedLength - 1);
        for (uint256 i = 0; i < truncatedData.length; i++) {
            truncatedData[i] = encodedAuth[i];
        }
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedMintAuthorizationInvalidLength.selector, expectedLength, truncatedData.length
        );

        vm.expectRevert(expectedRevertData);
        wrapper.castAndValidateMintAuthorization(truncatedData);

        vm.expectRevert(expectedRevertData);
        wrapper.decodeMintAuthorizationWrapper(truncatedData);
    }

    function test_decode_mintAuth_revertsOnTrailingBytesFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);
        uint256 originalAuthLength = encodedAuth.length;

        bytes memory corruptedData = bytes.concat(encodedAuth, hex"FFFF");
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedMintAuthorizationInvalidLength.selector, originalAuthLength, corruptedData.length
        );

        vm.expectRevert(expectedRevertData);
        wrapper.castAndValidateMintAuthorization(corruptedData);

        vm.expectRevert(expectedRevertData);
        wrapper.decodeMintAuthorizationWrapper(corruptedData);
    }

    // ===== Decode Failures: Inner TransferSpec Consistency Tests =====

    function test_decode_innerSpec_revertsOnDataTooShortForMagic() public {
        // Use fixed values for header fields, override spec length
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
        wrapper.castAndValidateMintAuthorization(corruptedData);

        vm.expectRevert(expectedRevertData);
        wrapper.decodeMintAuthorizationWrapper(corruptedData);
    }

    function test_decode_innerSpec_revertsOnCorruptedMagicFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);

        encodedAuth[MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET] = hex"FF";
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedTransferSpec.selector, "Invalid TransferSpec magic in MintAuthorization"
        );

        vm.expectRevert(expectedRevertData);
        wrapper.castAndValidateMintAuthorization(encodedAuth);

        vm.expectRevert(expectedRevertData);
        wrapper.decodeMintAuthorizationWrapper(encodedAuth);
    }

    function test_decode_innerSpec_revertsOnDataTooShortForHeaderFuzz(MintAuthorization memory auth) public {
        uint32 incorrectSpecLength = TRANSFER_SPEC_METADATA_OFFSET - 1;
        bytes memory dummySpecData = abi.encodePacked(TRANSFER_SPEC_MAGIC, new bytes(incorrectSpecLength - 4));
        bytes memory corruptedData =
            abi.encodePacked(MINT_AUTHORIZATION_MAGIC, auth.maxBlockHeight, incorrectSpecLength, dummySpecData);
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
            TRANSFER_SPEC_METADATA_OFFSET,
            incorrectSpecLength
        );

        vm.expectRevert(expectedRevertData);
        wrapper.castAndValidateMintAuthorization(corruptedData);

        vm.expectRevert(expectedRevertData);
        wrapper.decodeMintAuthorizationWrapper(corruptedData);
    }

    function test_decode_innerSpec_revertsOnDeclaredMetadataLengthTooBigFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);
        uint32 originalMetadataLength = uint32(auth.spec.metadata.length);
        uint32 originalInnerSpecLength = uint32(encodedAuth.length - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        (bytes memory corruptedData, uint32 corruptedMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedAuth,
            MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within MintAuth
            originalMetadataLength, // Original metadata length
            true // Inflate the metadata length field
        );

        // Set up expectRevert here
        uint256 expectedInnerSpecLength = TRANSFER_SPEC_METADATA_OFFSET + corruptedMetadataLength;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
            expectedInnerSpecLength, // The incorrect length expected based on corrupted field
            originalInnerSpecLength // The actual length of the original spec view
        );

        vm.expectRevert(expectedRevertData);
        wrapper.castAndValidateMintAuthorization(corruptedData);

        vm.expectRevert(expectedRevertData);
        wrapper.decodeMintAuthorizationWrapper(corruptedData);
    }

    function test_decode_innerSpec_revertsOnDeclaredMetadataLengthTooSmallFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);
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
            AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
            expectedInnerSpecLength, // The incorrect length expected based on corrupted field
            originalInnerSpecLength // The actual length of the original spec view
        );

        vm.expectRevert(expectedRevertData);
        wrapper.castAndValidateMintAuthorization(corruptedData);

        vm.expectRevert(expectedRevertData);
        wrapper.decodeMintAuthorizationWrapper(corruptedData);
    }
}
