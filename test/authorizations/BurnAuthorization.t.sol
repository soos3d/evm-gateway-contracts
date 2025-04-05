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
import {TransferSpec, TRANSFER_SPEC_VERSION, TRANSFER_SPEC_MAGIC} from "src/lib/authorizations/TransferSpec.sol";
import {
    BurnAuthorization,
    BURN_AUTHORIZATION_MAGIC
} from "src/lib/authorizations/BurnAuthorizations.sol";
import {AuthorizationLib} from "src/lib/authorizations/AuthorizationLib.sol";
import {TypedMemView} from "@memview-sol/TypedMemView.sol";

contract BurnAuthorizationTest is AuthorizationTestUtils {
    using AuthorizationLib for bytes;
    using AuthorizationLib for bytes29;
    using TypedMemView for bytes29;

    uint16 private constant BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET = 72;

    function _assertBurnAuthorizationEqual(BurnAuthorization memory a, BurnAuthorization memory b) internal pure {
        assertEq(a.maxBlockHeight, b.maxBlockHeight, "Eq Fail: maxBlockHeight");
        assertEq(a.maxFee, b.maxFee, "Eq Fail: maxFee");
        _assertTransferSpecEqual(a.spec, b.spec);
    }

    function _verifyBurnAuthorizationFieldsFromView(bytes29 ref, BurnAuthorization memory auth) internal pure {
        assertEq(ref.getBurnAuthorizationMaxBlockHeight(), auth.maxBlockHeight, "Eq Fail: maxBlockHeight");
        assertEq(ref.getBurnAuthorizationMaxFee(), auth.maxFee, "Eq Fail: maxFee");
        bytes29 specRef = ref.getBurnAuthorizationTransferSpec();
        _verifyTransferSpecFieldsFromView(specRef, auth.spec);
    }

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
        _assertBurnAuthorizationEqual(decodedAuth, originalAuth);
    }

    function test_encodeDecode_roundTrip_shortSpecMetadataFuzz(BurnAuthorization memory originalAuth) public view {
        originalAuth.spec.version = TRANSFER_SPEC_VERSION;
        originalAuth.spec.metadata = SHORT_METADATA;
        bytes memory encoded = AuthorizationLib.encodeBurnAuthorization(originalAuth);
        BurnAuthorization memory decodedAuth = AuthorizationLib.decodeBurnAuthorization(encoded);
        _assertBurnAuthorizationEqual(decodedAuth, originalAuth);
    }

    function test_encodeDecode_roundTrip_longSpecMetadataFuzz(BurnAuthorization memory originalAuth) public view {
        originalAuth.spec.version = TRANSFER_SPEC_VERSION;
        originalAuth.spec.metadata = LONG_METADATA;
        bytes memory encoded = AuthorizationLib.encodeBurnAuthorization(originalAuth);
        BurnAuthorization memory decodedAuth = AuthorizationLib.decodeBurnAuthorization(encoded);
        _assertBurnAuthorizationEqual(decodedAuth, originalAuth);
    }

    // ===== Decode Failures: Outer BurnAuthorization struct Consistency Tests =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_revertsOnCorruptedBurnAuthorizationMagic(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);

        // Corrupt the first byte of the BurnAuthorization magic
        encodedAuth[0] = hex"FF";
        vm.expectRevert(
             abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorization.selector, encodedAuth)
        );
        AuthorizationLib.decodeBurnAuthorization(encodedAuth);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_revertsOnDataTooShortForRequiredFields(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        bytes memory validEncodedBurnAuth = AuthorizationLib.encodeBurnAuthorization(auth);

        // Truncate data to be shorter than the fixed header offset
        uint16 truncatedLength = BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET - 1;
        bytes memory shortData = new bytes(truncatedLength);
        for (uint i = 0; i < truncatedLength; i++) {
            shortData[i] = validEncodedBurnAuth[i];
        }
        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedBurnAuthorizationInvalidLength.selector,
                BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET, // The minimum expected length of a BurnAuthorization struct
                shortData.length // The actual shorter length
            )
        );
        AuthorizationLib.decodeBurnAuthorization(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_revertsOnDataShorterThanMagic() public {
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
    function test_decode_revertsOnTruncatedDataFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA; 

        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);
        uint256 expectedLength = encodedAuth.length;

        bytes memory truncatedData = new bytes(expectedLength - 1);
        for (uint i = 0; i < truncatedData.length; i++) {
            truncatedData[i] = encodedAuth[i];
        }

        vm.expectRevert(
             abi.encodeWithSelector(
                AuthorizationLib.MalformedBurnAuthorizationInvalidLength.selector,
                expectedLength, // The length the decoder expects based on the header
                truncatedData.length // The actual shorter length provided
            )
        );
        AuthorizationLib.decodeBurnAuthorization(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_revertsOnTrailingBytes(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);
        uint256 originalAuthLength = encodedAuth.length;

        // Corrupt the encoded auth by adding trailing bytes
        bytes memory corruptedData = bytes.concat(encodedAuth, hex"FFFF");

        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedBurnAuthorizationInvalidLength.selector,
                originalAuthLength, // The length the decoder expects based on the header
                corruptedData.length // The actual shorter length provided
            )
        );
        AuthorizationLib.decodeBurnAuthorization(corruptedData);
    }


    // ===== Decode Failures: Inner TransferSpec Consistency Tests =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnDataTooShortForMagic() public {
        // Use fixed values for header fields, override spec length
        uint256 fixedMaxBlockHeight = 1;
        uint256 fixedMaxFee = 1;
        uint32 incorrectSpecLength = 2;

        // Construct corrupted data: header + 2 dummy bytes for spec
        bytes memory corruptedData = abi.encodePacked(
            BURN_AUTHORIZATION_MAGIC,
            fixedMaxBlockHeight,
            fixedMaxFee,
            incorrectSpecLength,
            hex"0000"
        );

        vm.expectRevert(
             bytes(
                string.concat(
                    "TypedMemView/index - Overran the view. ",
                    "Slice is at 0x0000e8 with length 0x000002. ", // Updated address
                    "Attempted to index at offset 0x000000 with length 0x000004."
                )
            )
        );
        AuthorizationLib.decodeBurnAuthorization(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnCorruptedMagicFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);

        // Corrupt the TransferSpec magic using the offset
        encodedAuth[BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET] = hex"FF";

        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedTransferSpec.selector,
                "Invalid TransferSpec magic in BurnAuthorization"
            )
        );
        AuthorizationLib.decodeBurnAuthorization(encodedAuth);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnDataTooShortForHeaderFuzz(BurnAuthorization memory auth) public {
        uint32 incorrectSpecLength = TRANSFER_SPEC_METADATA_OFFSET - 1;

        // Construct dummy spec data that starts with the correct magic, but is too short overall
        bytes memory dummySpecData = abi.encodePacked(
            TRANSFER_SPEC_MAGIC,
            new bytes(incorrectSpecLength - 4)
        );

        bytes memory corruptedData = abi.encodePacked(
            BURN_AUTHORIZATION_MAGIC,
            auth.maxBlockHeight,
            auth.maxFee,
            incorrectSpecLength,
            dummySpecData
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
                TRANSFER_SPEC_METADATA_OFFSET, // The minimum expected length of a TransferSpec struct
                incorrectSpecLength // The actual shorter length provided
            )
        );
        AuthorizationLib.decodeBurnAuthorization(corruptedData);
    }
    
    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnDeclaredMetadataLengthTooBigFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA; // Use non-empty metadata for the test base
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);

        // Corrupt the TransferSpec metadata length field, making it larger
        bytes memory corruptedData = _expectRevertForInnerSpecMetadataLengthMismatch(
            encodedAuth, 
            BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within BurnAuth
            uint32(auth.spec.metadata.length), // Original metadata length
            true // Inflate the metadata length field
        );
        AuthorizationLib.decodeBurnAuthorization(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnDeclaredMetadataLengthTooSmallFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        // Ensure metadata length > 0 for the test logic
        if (auth.spec.metadata.length == 0) {
            auth.spec.metadata = LONG_METADATA; 
        }
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);
        uint32 originalMetadataLength = uint32(auth.spec.metadata.length);

        // Corrupt the TransferSpec metadata length field, making it smaller
        bytes memory corruptedData = _expectRevertForInnerSpecMetadataLengthMismatch(
            encodedAuth, 
            BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within BurnAuth
            originalMetadataLength, // Original metadata length
            false // Make the metadata length field smaller
        );
        AuthorizationLib.decodeBurnAuthorization(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnTrailingBytesFuzz(BurnAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeBurnAuthorization(auth);
        uint256 originalAuthLength = encodedAuth.length;

        // Corrupt the encoded auth by adding trailing bytes
        bytes memory corruptedData = bytes.concat(encodedAuth, hex"FFFF");

        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedBurnAuthorizationInvalidLength.selector,
                originalAuthLength, // The length the decoder expects based on the header
                corruptedData.length // The actual shorter length provided
            )
        );
        AuthorizationLib.decodeBurnAuthorization(corruptedData);
    }
} 