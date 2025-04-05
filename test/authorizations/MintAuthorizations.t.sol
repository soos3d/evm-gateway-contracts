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
    MintAuthorization,
    MINT_AUTHORIZATION_MAGIC
} from "src/lib/authorizations/MintAuthorizations.sol";
import {AuthorizationLib} from "src/lib/authorizations/AuthorizationLib.sol";
import {TypedMemView} from "@memview-sol/TypedMemView.sol";

contract MintAuthorizationTest is AuthorizationTestUtils {
    using AuthorizationLib for bytes;
    using AuthorizationLib for bytes29;
    using TypedMemView for bytes29;

    uint16 private constant MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET = 40;

    function _assertMintAuthorizationEqual(MintAuthorization memory a, MintAuthorization memory b) internal pure {
        assertEq(a.maxBlockHeight, b.maxBlockHeight, "Eq Fail: maxBlockHeight");
        _assertTransferSpecEqual(a.spec, b.spec);
    }

    function _verifyMintAuthorizationFieldsFromView(bytes29 ref, MintAuthorization memory auth) internal pure {
        assertEq(ref.getMintAuthorizationMaxBlockHeight(), auth.maxBlockHeight, "Eq Fail: maxBlockHeight");
        bytes29 specRef = ref.getMintAuthorizationTransferSpec();
        _verifyTransferSpecFieldsFromView(specRef, auth.spec);
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
        _assertMintAuthorizationEqual(decodedAuth, originalAuth);
    }

    function test_encodeDecode_roundTrip_shortSpecMetadataFuzz(MintAuthorization memory originalAuth) public view {
        originalAuth.spec.version = TRANSFER_SPEC_VERSION;
        originalAuth.spec.metadata = SHORT_METADATA;
        bytes memory encoded = AuthorizationLib.encodeMintAuthorization(originalAuth);
        MintAuthorization memory decodedAuth = AuthorizationLib.decodeMintAuthorization(encoded);
        _assertMintAuthorizationEqual(decodedAuth, originalAuth);
    }

    function test_encodeDecode_roundTrip_longSpecMetadataFuzz(MintAuthorization memory originalAuth) public view {
        originalAuth.spec.version = TRANSFER_SPEC_VERSION;
        originalAuth.spec.metadata = LONG_METADATA;
        bytes memory encoded = AuthorizationLib.encodeMintAuthorization(originalAuth);
        MintAuthorization memory decodedAuth = AuthorizationLib.decodeMintAuthorization(encoded);
        _assertMintAuthorizationEqual(decodedAuth, originalAuth);
    }

    // ===== Decode Failures: Outer MintAuthorization struct Consistency Tests =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_revertsOnCorruptedMintAuthorizationMagic(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);

        // Corrupt the first byte of the MintAuthorization magic
        encodedAuth[0] = hex"FF";
        vm.expectRevert(
             abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorization.selector, encodedAuth)
        );
        AuthorizationLib.decodeMintAuthorization(encodedAuth);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_revertsOnDataTooShortForRequiredFields(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        bytes memory validEncodedMintAuth = AuthorizationLib.encodeMintAuthorization(auth);

        // Truncate data to be shorter than the fixed header offset
        uint16 truncatedLength = MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET - 1;
        bytes memory shortData = new bytes(truncatedLength);
        for (uint i = 0; i < truncatedLength; i++) {
            shortData[i] = validEncodedMintAuth[i];
        }
        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedMintAuthorizationInvalidLength.selector,
                MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET, // The minimum expected length of a MintAuthorization struct
                shortData.length // The actual shorter length
            )
        );
        AuthorizationLib.decodeMintAuthorization(shortData);
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
        AuthorizationLib.decodeMintAuthorization(shorterThanMagic);
    }
    
    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_revertsOnTruncatedDataFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA; 

        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);
        uint256 expectedLength = encodedAuth.length;

        bytes memory truncatedData = new bytes(expectedLength - 1);
        for (uint i = 0; i < truncatedData.length; i++) {
            truncatedData[i] = encodedAuth[i];
        }

        vm.expectRevert(
             abi.encodeWithSelector(
                AuthorizationLib.MalformedMintAuthorizationInvalidLength.selector,
                expectedLength, // The length the decoder expects based on the header
                truncatedData.length // The actual shorter length provided
            )
        );
        AuthorizationLib.decodeMintAuthorization(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_revertsOnTrailingBytes(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);
        uint256 originalAuthLength = encodedAuth.length;

        // Corrupt the encoded auth by adding trailing bytes
        bytes memory corruptedData = bytes.concat(encodedAuth, hex"FFFF");

        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedMintAuthorizationInvalidLength.selector,
                originalAuthLength, // The length the decoder expects based on the header
                corruptedData.length // The actual longer length provided
            )
        );
        AuthorizationLib.decodeMintAuthorization(corruptedData);
    }


    // ===== Decode Failures: Inner TransferSpec Consistency Tests =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnDataTooShortForMagic() public {
        // Use fixed values for header fields, override spec length
        uint256 fixedMaxBlockHeight = 1;
        uint32 incorrectSpecLength = 2;

        // Construct corrupted data: header + 2 dummy bytes for spec
        bytes memory corruptedData = abi.encodePacked(
            MINT_AUTHORIZATION_MAGIC,
            fixedMaxBlockHeight,
            incorrectSpecLength,
            hex"0000"
        );

        vm.expectRevert(
             bytes(
                string.concat(
                    "TypedMemView/index - Overran the view. ",
                    "Slice is at 0x0000c8 with length 0x000002. ",
                    "Attempted to index at offset 0x000000 with length 0x000004."
                )
            )
        );
        AuthorizationLib.decodeMintAuthorization(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnCorruptedMagicFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);

        // Corrupt the TransferSpec magic using the offset
        encodedAuth[MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET] = hex"FF";

        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedTransferSpec.selector,
                "Invalid TransferSpec magic in MintAuthorization"
            )
        );
        AuthorizationLib.decodeMintAuthorization(encodedAuth);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnDataTooShortForHeaderFuzz(MintAuthorization memory auth) public {
        uint32 incorrectSpecLength = TRANSFER_SPEC_METADATA_OFFSET - 1;

        // Construct dummy spec data that starts with the correct magic, but is too short overall
        bytes memory dummySpecData = abi.encodePacked(
            TRANSFER_SPEC_MAGIC,
            new bytes(incorrectSpecLength - 4)
        );

        bytes memory corruptedData = abi.encodePacked(
            MINT_AUTHORIZATION_MAGIC,
            auth.maxBlockHeight,
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
        AuthorizationLib.decodeMintAuthorization(corruptedData);
    }
    
    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnDeclaredMetadataLengthTooBigFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA; // Use non-empty metadata for the test base
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);

        // Corrupt the TransferSpec metadata length field, making it larger
        bytes memory corruptedData = _expectRevertForInnerSpecMetadataLengthMismatch(
            encodedAuth, 
            MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within MintAuth
            uint32(auth.spec.metadata.length), // Original metadata length
            true // Inflate the metadata length field
        );
        AuthorizationLib.decodeMintAuthorization(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnDeclaredMetadataLengthTooSmallFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        // Ensure metadata length > 0 for the test logic
        if (auth.spec.metadata.length == 0) {
            auth.spec.metadata = LONG_METADATA; 
        }
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);
        uint32 originalMetadataLength = uint32(auth.spec.metadata.length);

        // Corrupt the TransferSpec metadata length field, making it smaller
        bytes memory corruptedData = _expectRevertForInnerSpecMetadataLengthMismatch(
            encodedAuth, 
            MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET, // Offset of TransferSpec within MintAuth
            originalMetadataLength, // Original metadata length
            false // Make the metadata length field smaller
        );
        AuthorizationLib.decodeMintAuthorization(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_innerSpec_revertsOnTrailingBytesFuzz(MintAuthorization memory auth) public {
        auth.spec.version = TRANSFER_SPEC_VERSION;
        auth.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth = AuthorizationLib.encodeMintAuthorization(auth);
        uint256 originalAuthLength = encodedAuth.length;

        // Corrupt the encoded auth by adding trailing bytes
        bytes memory corruptedData = bytes.concat(encodedAuth, hex"FFFF");

        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedMintAuthorizationInvalidLength.selector,
                originalAuthLength, // The length the decoder expects based on the outer header
                corruptedData.length // The actual longer length provided
            )
        );
        AuthorizationLib.decodeMintAuthorization(corruptedData);
    }
} 