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
import {AuthorizationLib} from "src/lib/authorizations/AuthorizationLib.sol";
import {TypedMemView} from "@memview-sol/TypedMemView.sol";

contract TransferSpecTest is AuthorizationTestUtils {
    using TypedMemView for bytes29;
    using AuthorizationLib for bytes;
    using AuthorizationLib for bytes29;

    // ===== Casting Tests =====

    function test_asTransferSpec_correctMagic() external pure {
        (bytes memory data, uint40 magicType) = _magic("circle.gateway.TransferSpec");
        bytes29 ref = data.asTransferSpec();
        assertEq(TypedMemView.typeOf(ref), magicType);
        assertEq(bytes4(uint32(magicType)), TRANSFER_SPEC_MAGIC);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asTransferSpec_incorrectMagic() external {
        (bytes memory data,) = _magic("something else");
        vm.expectRevert(abi.encodeWithSelector(AuthorizationLib.MalformedTransferSpec.selector, data));
        data.asTransferSpec();
    }

    // ===== Field Accessor Tests =====

    function test_transferSpec_readAllFieldsEmptyMetadataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = new bytes(0);
        bytes memory encodedSpec = AuthorizationLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.asTransferSpec();
        _verifyTransferSpecFieldsFromView(ref, spec);
    }

    function test_transferSpec_readAllFieldsShortMetadataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = SHORT_METADATA;
        bytes memory encodedSpec = AuthorizationLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.asTransferSpec();
        _verifyTransferSpecFieldsFromView(ref, spec);
    }

    function test_transferSpec_readAllFieldsLongMetadataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = LONG_METADATA;
        bytes memory encodedSpec = AuthorizationLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.asTransferSpec();
        _verifyTransferSpecFieldsFromView(ref, spec);
    }

    // ===== Encode/Decode Round Trip Tests =====

    function test_encodeDecode_roundTrip_emptyMetadataFuzz(TransferSpec memory originalSpec) public view {
        originalSpec.version = TRANSFER_SPEC_VERSION;
        originalSpec.metadata = new bytes(0);
        bytes memory encoded = AuthorizationLib.encodeTransferSpec(originalSpec);
        TransferSpec memory decodedSpec = AuthorizationLib.decodeTransferSpec(encoded);
        _assertTransferSpecsEqual(decodedSpec, originalSpec);
    }

    function test_encodeDecode_roundTrip_shortMetadataFuzz(TransferSpec memory originalSpec) public view {
        originalSpec.version = TRANSFER_SPEC_VERSION;
        originalSpec.metadata = SHORT_METADATA;
        bytes memory encoded = AuthorizationLib.encodeTransferSpec(originalSpec);
        TransferSpec memory decodedSpec = AuthorizationLib.decodeTransferSpec(encoded);
        _assertTransferSpecsEqual(decodedSpec, originalSpec);
    }

    function test_encodeDecode_roundTrip_longMetadataFuzz(TransferSpec memory originalSpec) public view {
        originalSpec.version = TRANSFER_SPEC_VERSION;
        originalSpec.metadata = LONG_METADATA;
        bytes memory encoded = AuthorizationLib.encodeTransferSpec(originalSpec);
        TransferSpec memory decodedSpec = AuthorizationLib.decodeTransferSpec(encoded);
        _assertTransferSpecsEqual(decodedSpec, originalSpec);
    }

    function test_encodeDecode_roundTripZeroSignerAndCallerFuzz(TransferSpec memory originalSpec) public view {
        originalSpec.version = TRANSFER_SPEC_VERSION;
        originalSpec.sourceSigner = bytes32(0);
        originalSpec.destinationCaller = bytes32(0);
        originalSpec.metadata = new bytes(0);
        bytes memory encoded = AuthorizationLib.encodeTransferSpec(originalSpec);
        TransferSpec memory decodedSpec = AuthorizationLib.decodeTransferSpec(encoded);
        _assertTransferSpecsEqual(decodedSpec, originalSpec);
    }

    // ===== Decode Failure Tests =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_revertsOnDataTooShortForMagic() public {
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
        AuthorizationLib.decodeTransferSpec(shorterThanMagic);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_revertsOnCorruptedMagicFuzz(TransferSpec memory spec) public {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = LONG_METADATA;
        bytes memory encodedSpec = AuthorizationLib.encodeTransferSpec(spec);
        encodedSpec[0] = hex"FF";
        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedTransferSpec.selector,
                encodedSpec
            )
        );
        AuthorizationLib.decodeTransferSpec(encodedSpec);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_revertsOnDataTooShortForHeaderFuzz(TransferSpec memory originalSpec) public {
        originalSpec.version = TRANSFER_SPEC_VERSION;
        bytes memory validEncodedSpec = AuthorizationLib.encodeTransferSpec(originalSpec);

        uint16 truncatedLength = TRANSFER_SPEC_METADATA_OFFSET - 1;
        bytes memory shortData = new bytes(truncatedLength);
        for (uint16 i = 0; i < truncatedLength; i++) {
            shortData[i] = validEncodedSpec[i];
        }

        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
                TRANSFER_SPEC_METADATA_OFFSET,
                shortData.length
            )
        );
        AuthorizationLib.decodeTransferSpec(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_revertsOnDeclaredMetadataLengthTooBigFuzz(TransferSpec memory spec) public {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = LONG_METADATA;
        bytes memory encodedSpec = AuthorizationLib.encodeTransferSpec(spec);
        uint32 originalMetadataLength = uint32(spec.metadata.length);
        uint32 originalInnerSpecLength = uint32(encodedSpec.length); // Original total length

        // Call the new helper to get corrupted data and the invalid length
        (bytes memory corruptedData, uint32 corruptedMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedSpec, 0, originalMetadataLength, true /* inflate metadata length field */
        );
        
        uint256 expectedLengthAfterCorruption = TRANSFER_SPEC_METADATA_OFFSET + corruptedMetadataLength;
        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
                expectedLengthAfterCorruption, // The incorrect length expected based on corrupted field
                originalInnerSpecLength        // The actual length of the original spec view
            )
        );
        AuthorizationLib.decodeTransferSpec(corruptedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_revertsOnDeclaredMetadataLengthTooSmallFuzz(TransferSpec memory spec) public {
        spec.version = TRANSFER_SPEC_VERSION;
        // Ensure metadata length > 0 for division
        if (spec.metadata.length == 0) {
            spec.metadata = LONG_METADATA; 
        }
        bytes memory encodedSpec = AuthorizationLib.encodeTransferSpec(spec);
        uint32 originalMetadataLength = uint32(spec.metadata.length);
        uint32 originalInnerSpecLength = uint32(encodedSpec.length); // Original total length

        (bytes memory corruptedData, uint32 corruptedMetadataLength) = _getCorruptedInnerSpecMetadataLengthData(
            encodedSpec, 0, originalMetadataLength, false /* make metadata length shorter */
        );

        uint256 expectedLengthAfterCorruption = TRANSFER_SPEC_METADATA_OFFSET + corruptedMetadataLength;
        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
                expectedLengthAfterCorruption, // The incorrect length expected based on corrupted field
                originalInnerSpecLength        // The actual length of the original spec view
            )
        );
        AuthorizationLib.decodeTransferSpec(corruptedData);
    }
 
    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_revertsOnTrailingBytesFuzz(TransferSpec memory spec) public {
        spec.version = TRANSFER_SPEC_VERSION; // Ensure correct version for encoding
        spec.metadata = LONG_METADATA;
        bytes memory encodedSpec = AuthorizationLib.encodeTransferSpec(spec);
        uint256 originalSpecLength = encodedSpec.length;

        // Corrupt the encoded spec with some trailing bytes
        bytes memory corruptedData = bytes.concat(encodedSpec, hex"ffff");
        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
                originalSpecLength,
                corruptedData.length
            )
        );
        AuthorizationLib.decodeTransferSpec(corruptedData);
    }

    // ===== Hash Utility Tests =====

    function test_getTransferSpecHash_withMetadataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = SHORT_METADATA;
        bytes memory encodedSpec = AuthorizationLib.encodeTransferSpec(spec);

        bytes32 libHash = AuthorizationLib.getTransferSpecHash(encodedSpec);
        bytes32 expectedHash = keccak256(encodedSpec);

        assertEq(libHash, expectedHash, "Hash mismatch for non-empty metadata");
    }
}
