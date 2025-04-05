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
    BURN_AUTHORIZATION_MAGIC,
    BurnAuthorizationSet,
    BURN_AUTHORIZATION_SET_MAGIC
} from "src/lib/authorizations/BurnAuthorizations.sol";
import {AuthorizationLib} from "src/lib/authorizations/AuthorizationLib.sol";
import {TypedMemView} from "@memview-sol/TypedMemView.sol";

contract BurnAuthorizationSetTest is AuthorizationTestUtils {
    using AuthorizationLib for bytes;
    using AuthorizationLib for bytes29;
    using TypedMemView for bytes29;

    uint16 private constant BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET = 72;
    uint16 private constant BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET = 8;
    uint16 private constant BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET = 68;

    /// @notice Helper to create a BurnAuthorizationSet with two authorizations and specified metadata.
    function _createBurnAuthSet(
        BurnAuthorization memory auth1,
        BurnAuthorization memory auth2,
        bytes memory metadataBytes
    ) internal pure returns (BurnAuthorizationSet memory) {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = metadataBytes;
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = metadataBytes;

        BurnAuthorization[] memory authorizations = new BurnAuthorization[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;

        return BurnAuthorizationSet({authorizations: authorizations});
    }

    /// @notice Internal helper to verify all fields from a BurnAuthorizationSet view match the original struct.
    function _verifyBurnAuthorizationSetFieldsFromView(bytes29 setRef, BurnAuthorizationSet memory authSet) internal pure {
        uint32 numAuths = setRef.getBurnAuthorizationSetNumAuthorizations();
        assertEq(numAuths, authSet.authorizations.length, "Eq Fail: numAuths");

        // Test accessing each authorization
        for (uint32 i = 0; i < numAuths; i++) {
            bytes29 authRef = setRef.getBurnAuthorizationSetAuthorizationAt(i);
            _verifyBurnAuthorizationFieldsFromView(authRef, authSet.authorizations[i]);
        }
    }

    function _assertBurnAuthorizationSetsEqual(BurnAuthorizationSet memory a, BurnAuthorizationSet memory b) internal pure {
        assertEq(a.authorizations.length, b.authorizations.length, "Eq Fail: authorizations length");
        for (uint32 i = 0; i < a.authorizations.length; i++) {
            _assertBurnAuthorizationsEqual(a.authorizations[i], b.authorizations[i]);
        }
    }

    // ===== Casting Tests (Set) =====

    function test_asBurnAuthorizationSet_correctMagic() public pure {
        (bytes memory data, uint40 magicType) = _magic("circle.gateway.BurnAuthorizationSet");
        bytes29 ref = data.asBurnAuthorizationSet();
        assertEq(TypedMemView.typeOf(ref), magicType);
        assertEq(bytes4(uint32(magicType)), BURN_AUTHORIZATION_SET_MAGIC);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asBurnAuthorizationSet_incorrectMagic() public {
        (bytes memory data,) = _magic("something else");
        vm.expectRevert(abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, data));
        data.asBurnAuthorizationSet();
    }

    // ===== Field Accessor / Set Iteration Tests =====

    function test_burnAuthorizationSet_readsAllFieldsEmptySet() public pure {
        BurnAuthorization[] memory authorizations = new BurnAuthorization[](0);
        BurnAuthorizationSet memory set = BurnAuthorizationSet({ authorizations: authorizations });
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(set);
        bytes29 setRef = encodedAuthSet.asBurnAuthorizationSet();
        _verifyBurnAuthorizationSetFieldsFromView(setRef, set);
    }

    function test_burnAuthorizationSet_readAllFieldsEmptyMetadataFuzz(BurnAuthorization memory auth1, BurnAuthorization memory auth2)
        public
        pure
    {
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);
        bytes29 setRef = encodedAuthSet.asBurnAuthorizationSet();
        _verifyBurnAuthorizationSetFieldsFromView(setRef, authSet);
    }

    function test_burnAuthorizationSet_readAllFieldsShortMetadataFuzz(BurnAuthorization memory auth1, BurnAuthorization memory auth2)
        public
        pure
    {
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, SHORT_METADATA);
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);
        bytes29 setRef = encodedAuthSet.asBurnAuthorizationSet();
        _verifyBurnAuthorizationSetFieldsFromView(setRef, authSet);
    }

    function test_burnAuthorizationSet_readAllFieldsLongMetadataFuzz(BurnAuthorization memory auth1, BurnAuthorization memory auth2)
        public
        pure
    {
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);
        bytes29 setRef = encodedAuthSet.asBurnAuthorizationSet();
        _verifyBurnAuthorizationSetFieldsFromView(setRef, authSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_burnAuthorizationSet_revertsOnOutOfBoundsAccessFuzz(
        BurnAuthorization memory auth1,
        BurnAuthorization memory auth2
    ) public {
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);
        bytes29 ref = encodedAuthSet.asBurnAuthorizationSet();
        uint32 numAuths = ref.getBurnAuthorizationSetNumAuthorizations();
        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, "Index out of bounds")
        );
        ref.getBurnAuthorizationSetAuthorizationAt(numAuths);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_getBurnAuthSetAuthAt_revertsIfDeclaredSpecLengthExceedsBoundsFuzz(BurnAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = SHORT_METADATA;

        BurnAuthorization[] memory authorizations = new BurnAuthorization[](1);
        authorizations[0] = auth1;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes memory encodedAuth1 = AuthorizationLib.encodeBurnAuthorization(auth1);
        uint256 originalAuth1Length = encodedAuth1.length;
        uint32 originalSpecLength = uint32(originalAuth1Length - BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        // Corruption: Increase the declared spec length within the encoded data without actually adding more data bytes
        uint256 specLengthOffset = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET;
        uint32 corruptedSpecLength = 2 * originalSpecLength;
        bytes4 encodedCorruptedLength = bytes4(corruptedSpecLength);

        bytes memory corruptedEncodedAuthSet = encodedAuthSet;
        for (uint i = 0; i < 4; i++) {
            corruptedEncodedAuthSet[specLengthOffset + i] = encodedCorruptedLength[i];
        }

        bytes29 ref = corruptedEncodedAuthSet.asBurnAuthorizationSet();

        // Expect the revert from the bounds check added in getBurnAuthorizationSetAuthorizationAt
        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedBurnAuthorizationSet.selector,
                "Calculated authorization slice exceeds set bounds"
            )
        );
        ref.getBurnAuthorizationSetAuthorizationAt(0);
    }

    // ===== Encode/Decode Round Trip Tests =====

    function test_encodeDecode_roundTrip_emptySet() public view {
        BurnAuthorization[] memory authorizations = new BurnAuthorization[](0);
        BurnAuthorizationSet memory set = BurnAuthorizationSet({ authorizations: authorizations });
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(set);
        BurnAuthorizationSet memory decodedAuthSet = AuthorizationLib.decodeBurnAuthorizationSet(encodedAuthSet);
        _assertBurnAuthorizationSetsEqual(decodedAuthSet, set);
    }

    function test_encodeDecode_roundTrip_emptyMetadataFuzz(BurnAuthorization memory auth1, BurnAuthorization memory auth2) public view {
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);
        BurnAuthorizationSet memory decodedAuthSet = AuthorizationLib.decodeBurnAuthorizationSet(encodedAuthSet);
        _assertBurnAuthorizationSetsEqual(decodedAuthSet, authSet);
    }

    function test_encodeDecode_roundTrip_shortMetadataFuzz(BurnAuthorization memory auth1, BurnAuthorization memory auth2) public view {
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, SHORT_METADATA);
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);
        BurnAuthorizationSet memory decodedAuthSet = AuthorizationLib.decodeBurnAuthorizationSet(encodedAuthSet);
        _assertBurnAuthorizationSetsEqual(decodedAuthSet, authSet);
    }

    function test_encodeDecode_roundTrip_longMetadataFuzz(BurnAuthorization memory auth1, BurnAuthorization memory auth2) public view {
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);
        BurnAuthorizationSet memory decodedAuthSet = AuthorizationLib.decodeBurnAuthorizationSet(encodedAuthSet);
        _assertBurnAuthorizationSetsEqual(decodedAuthSet, authSet);
    }

    // ===== Decode Failures: Set Structure and Iteration =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnDataTooShortForMagic() public {
        bytes memory shorterThanMagic = new bytes(2);
        // Expect the revert from the initial length check in decodeBurnAuthorizationSet
        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, shorterThanMagic)
        );
        AuthorizationLib.decodeBurnAuthorizationSet(shorterThanMagic);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnCorruptedMagic() public {
        BurnAuthorization[] memory authorizations = new BurnAuthorization[](0);
        BurnAuthorizationSet memory set = BurnAuthorizationSet({ authorizations: authorizations });
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(set);

        // Corrupt the first byte of the magic
        encodedAuthSet[0] = hex"FF";
        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, encodedAuthSet)
        );
        AuthorizationLib.decodeBurnAuthorizationSet(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnDataTooShortForHeader() public {
        // Length is > magic (4) but < header (8)
        bytes memory shortData = abi.encodePacked(BURN_AUTHORIZATION_SET_MAGIC, hex"112233"); // 7 bytes
        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, shortData)
        );
        AuthorizationLib.decodeBurnAuthorizationSet(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnEmptyAuthorizationsWithTrailingBytes() public {
         bytes memory encodedSetHeader = abi.encodePacked(
            BURN_AUTHORIZATION_SET_MAGIC,
            uint32(0) // numAuthorizations = 0
        );
        bytes memory trailingBytesData = bytes.concat(encodedSetHeader, hex"FFFF");

        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, "Set length mismatch after decoding all elements")
        );
        AuthorizationLib.decodeBurnAuthorizationSet(trailingBytesData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsIfDataEndsPrematurely_BeforeFirstAuthHeader() public {
        // Set numAuthorizations = 1 but provide only the set header
        bytes memory encodedSetHeaderOnly = abi.encodePacked(
            BURN_AUTHORIZATION_SET_MAGIC,
            uint32(1) // numAuthorizations = 1
        ); // 8 bytes total

        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, "Data too short for next BurnAuthorization header")
        );
        AuthorizationLib.decodeBurnAuthorizationSet(encodedSetHeaderOnly);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsIfDataEndsPrematurely_WithinFirstAuthHeaderFuzz(BurnAuthorization memory auth1) public {
         // Set numAuthorizations = 1, provide set header + partial auth header
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        bytes memory encodedAuth1 = AuthorizationLib.encodeBurnAuthorization(auth1);

        bytes memory encodedSetHeader = abi.encodePacked(
            BURN_AUTHORIZATION_SET_MAGIC,
            uint32(1) // numAuthorizations = 1
        );

        // Truncate the first auth header (e.g., provide only 10 bytes of it)
        uint256 partialAuthHeaderLength = 10;
        require(partialAuthHeaderLength < BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET, "Test setup invalid");
        bytes memory partialAuthData = new bytes(partialAuthHeaderLength);
        for (uint i=0; i < partialAuthHeaderLength; i++) {
            partialAuthData[i] = encodedAuth1[i];
        }

        bytes memory truncatedData = bytes.concat(encodedSetHeader, partialAuthData);

        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, "Data too short for next BurnAuthorization header")
        );
        AuthorizationLib.decodeBurnAuthorizationSet(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsIfDataEndsPrematurely_BasedOnFirstAuthSpecLengthFuzz(BurnAuthorization memory auth1) public {
        // Set numAuthorizations = 1, provide set header + full auth header + partial spec
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth1 = AuthorizationLib.encodeBurnAuthorization(auth1);

        bytes memory encodedSetHeader = abi.encodePacked(
            BURN_AUTHORIZATION_SET_MAGIC,
            uint32(1) // numAuthorizations = 1
        );

        // Truncate the overall data just before the end of the first auth's spec
        uint256 truncatedLength = encodedSetHeader.length + encodedAuth1.length - 1;
        bytes memory truncatedData = new bytes(truncatedLength);
        bytes memory combined = bytes.concat(encodedSetHeader, encodedAuth1);
        for(uint i=0; i < truncatedLength; i++) {
            truncatedData[i] = combined[i];
        }

        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, "Data too short for next BurnAuthorization")
        );
        AuthorizationLib.decodeBurnAuthorizationSet(truncatedData);
    }

     /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsIfDataEndsPrematurely_BetweenAuthorizationsFuzz(
        BurnAuthorization memory auth1,
        BurnAuthorization memory auth2
    ) public {
        // Set numAuthorizations = 2, provide set header + auth1 + partial auth2 header
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);

        bytes memory encodedAuth1 = AuthorizationLib.encodeBurnAuthorization(auth1);
        bytes memory encodedAuth2 = AuthorizationLib.encodeBurnAuthorization(auth2);

        bytes memory encodedSetHeader = abi.encodePacked(
            BURN_AUTHORIZATION_SET_MAGIC,
            uint32(2) // numAuthorizations = 2
        );

        // Truncate data after auth1 and partway into auth2's header
        uint256 partialAuth2HeaderLength = 10;
        bytes memory partialAuth2Data = new bytes(partialAuth2HeaderLength);
        for (uint i=0; i < partialAuth2HeaderLength; i++) {
            partialAuth2Data[i] = encodedAuth2[i];
        }

        bytes memory truncatedData = bytes.concat(encodedSetHeader, encodedAuth1, partialAuth2Data);

        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, "Data too short for next BurnAuthorization header")
        );
        AuthorizationLib.decodeBurnAuthorizationSet(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsIfDataEndsPrematurely_WithinSecondAuthorizationFuzz(
        BurnAuthorization memory auth1,
        BurnAuthorization memory auth2
    ) public {
        // Set numAuthorizations = 2, provide set header + auth1 + auth2 header + partial auth2 spec
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);

        bytes memory encodedAuth1 = AuthorizationLib.encodeBurnAuthorization(auth1);
        bytes memory encodedAuth2 = AuthorizationLib.encodeBurnAuthorization(auth2);

        bytes memory encodedSetHeader = abi.encodePacked(
            BURN_AUTHORIZATION_SET_MAGIC,
            uint32(2) // numAuthorizations = 2
        );

        // Truncate data partway through the second authorization's spec
        uint256 truncatedLength = encodedSetHeader.length + encodedAuth1.length + encodedAuth2.length - 1;
        bytes memory truncatedData = new bytes(truncatedLength);
        bytes memory combined = bytes.concat(encodedSetHeader, encodedAuth1, encodedAuth2);
        for(uint i=0; i < truncatedLength; i++) {
            truncatedData[i] = combined[i];
        }

        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, "Data too short for next BurnAuthorization")
        );
        AuthorizationLib.decodeBurnAuthorizationSet(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnTrailingBytes_WhenEmpty() public {
         bytes memory encodedSetHeader = abi.encodePacked(
            BURN_AUTHORIZATION_SET_MAGIC,
            uint32(0) // numAuthorizations = 0
        );
        bytes memory trailingBytesData = bytes.concat(encodedSetHeader, hex"FFFF"); // Add trailing bytes

        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, "Set length mismatch after decoding all elements")
        );
        AuthorizationLib.decodeBurnAuthorizationSet(trailingBytesData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnTrailingBytes_AfterAllAuthsFuzz(BurnAuthorization memory auth1, BurnAuthorization memory auth2) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);

        // Add trailing bytes
        bytes memory trailingBytesData = bytes.concat(encodedAuthSet, hex"FFFF");

        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, "Set length mismatch after decoding all elements")
        );
        AuthorizationLib.decodeBurnAuthorizationSet(trailingBytesData);
    }

    // ===== Decode Failures: Inner Authorization Consistency =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnInnerAuth_CorruptedMagic_InFirstFuzz(BurnAuthorization memory auth1, BurnAuthorization memory auth2) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);

        // Corrupt the magic of the first authorization (at offset 8)
        encodedAuthSet[BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET] = hex"FF";

        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, "Invalid authorization magic in set")
        );
        AuthorizationLib.decodeBurnAuthorizationSet(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnInnerAuth_CorruptedMagic_InSecondFuzz(BurnAuthorization memory auth1, BurnAuthorization memory auth2) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        BurnAuthorizationSet memory authSet = _createBurnAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);

        // Calculate offset of second authorization's magic
        bytes memory encodedAuth1 = AuthorizationLib.encodeBurnAuthorization(authSet.authorizations[0]);
        uint256 secondAuthOffset = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth1.length;

        // Corrupt the magic of the second authorization
        encodedAuthSet[secondAuthOffset] = hex"FF";

        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, "Invalid authorization magic in set")
        );
        AuthorizationLib.decodeBurnAuthorizationSet(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnInnerSpec_CorruptedMagicFuzz(BurnAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        BurnAuthorization[] memory authorizations = new BurnAuthorization[](1);
        authorizations[0] = auth1;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);

        // Corrupt the inner TransferSpec magic within the first authorization
        uint256 innerSpecMagicOffset = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
        encodedAuthSet[innerSpecMagicOffset] = hex"FF";

        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedTransferSpec.selector,
                "Invalid TransferSpec magic in BurnAuthorization"
            )
        );
        AuthorizationLib.decodeBurnAuthorizationSet(encodedAuthSet);
    }

     /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnInnerSpec_DeclaredMetadataLengthTooBigFuzz(BurnAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        BurnAuthorization[] memory authorizations = new BurnAuthorization[](1);
        authorizations[0] = auth1;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);

        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);
        uint256 encodedAuth1Length = encodedAuthSet.length - BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;

        // Corrupt the inner TransferSpec metadata length field (make it larger)
        uint256 innerMetadataLengthOffset = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET + TRANSFER_SPEC_METADATA_LENGTH_OFFSET;
        uint32 invalidMetadataLength = originalMetadataLength + 1;
        bytes4 encodedInvalidLength = bytes4(invalidMetadataLength);
        for (uint i = 0; i < 4; i++) {
            encodedAuthSet[innerMetadataLengthOffset + i] = encodedInvalidLength[i];
        }

        uint256 expectedInnerSpecLength = TRANSFER_SPEC_METADATA_OFFSET + invalidMetadataLength;
        uint256 actualInnerSpecLength = encodedAuth1Length - BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET;

        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
                expectedInnerSpecLength,
                actualInnerSpecLength
            )
        );
        AuthorizationLib.decodeBurnAuthorizationSet(encodedAuthSet);
    }

     /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnInnerSpec_DeclaredMetadataLengthTooSmallFuzz(BurnAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        BurnAuthorization[] memory authorizations = new BurnAuthorization[](1);
        authorizations[0] = auth1;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);

        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);
        uint256 encodedAuth1Length = encodedAuthSet.length - BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;

        // Corrupt the inner TransferSpec metadata length field (make it smaller)
        uint256 innerMetadataLengthOffset = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET + TRANSFER_SPEC_METADATA_LENGTH_OFFSET;
        uint32 invalidMetadataLength = originalMetadataLength / 2; // Make it smaller
        bytes4 encodedInvalidLength = bytes4(invalidMetadataLength);
        for (uint i = 0; i < 4; i++) {
            encodedAuthSet[innerMetadataLengthOffset + i] = encodedInvalidLength[i];
        }

        uint256 expectedInnerSpecLength = TRANSFER_SPEC_METADATA_OFFSET + invalidMetadataLength;
        uint256 actualInnerSpecLength = encodedAuth1Length - BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET;

        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
                expectedInnerSpecLength,
                actualInnerSpecLength
            )
        );
        AuthorizationLib.decodeBurnAuthorizationSet(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnInnerAuth_DeclaredSpecLengthTooSmallFuzz(BurnAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        BurnAuthorization[] memory authorizations = new BurnAuthorization[](1);
        authorizations[0] = auth1;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes memory encodedAuth1 = AuthorizationLib.encodeBurnAuthorization(auth1);
        uint256 originalAuthLength = encodedAuth1.length;
        uint32 originalSpecLength = uint32(originalAuthLength - BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET);
        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);

        // Corrupt the outer BurnAuthorization's declared spec length (make it smaller)
        uint256 outerSpecLengthOffset = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET;
        uint32 invalidSpecLength = originalSpecLength - 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
         for (uint i = 0; i < 4; i++) {
            encodedAuthSet[outerSpecLengthOffset + i] = encodedInvalidLength[i];
        }

        // The failure occurs inside the TransferSpec decoding because the outer corruption
        // leads to providing a truncated spec slice.
        uint256 expectedInnerSpecLengthBasedOnMetadata = TRANSFER_SPEC_METADATA_OFFSET + originalMetadataLength;

        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
                expectedInnerSpecLengthBasedOnMetadata, // Length expected by inner spec based on its metadata
                invalidSpecLength // Actual length of the spec slice provided due to outer corruption
            )
        );
        AuthorizationLib.decodeBurnAuthorizationSet(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnInnerAuth_DeclaredSpecLengthTooLargeFuzz(BurnAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA; // Ensure metadata exists

        BurnAuthorization[] memory authorizations = new BurnAuthorization[](1);
        authorizations[0] = auth1;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes memory encodedAuth1 = AuthorizationLib.encodeBurnAuthorization(auth1);
        uint256 originalAuthLength = encodedAuth1.length;
        uint32 originalSpecLength = uint32(originalAuthLength - BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        // Corrupt the outer BurnAuthorization's declared spec length (make it larger)
        uint256 outerSpecLengthOffset = BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET;
        uint32 invalidSpecLength = originalSpecLength + 1; // Make it larger than actual
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
         for (uint i = 0; i < 4; i++) {
            encodedAuthSet[outerSpecLengthOffset + i] = encodedInvalidLength[i];
        }

        // The failure occurs in the main decode loop when checking if the set data
        // is long enough to contain the authorization based on its inflated declared length.
        vm.expectRevert(
             abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, "Data too short for next BurnAuthorization")
        );
        AuthorizationLib.decodeBurnAuthorizationSet(encodedAuthSet);
    }

} 