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
import {TRANSFER_SPEC_VERSION} from "src/lib/authorizations/TransferSpec.sol";
import {
    MintAuthorization,
    MintAuthorizationSet,
    MINT_AUTHORIZATION_SET_MAGIC
} from "src/lib/authorizations/MintAuthorizations.sol";
import {AuthorizationLib} from "src/lib/authorizations/AuthorizationLib.sol";
import {TypedMemView} from "@memview-sol/TypedMemView.sol";

contract MintAuthorizationSetTest is AuthorizationTestUtils {
    using AuthorizationLib for bytes;
    using AuthorizationLib for bytes29;
    using TypedMemView for bytes29;

    uint16 private constant MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET = 40;
    uint16 private constant MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET = 8;
    uint16 private constant MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET = 36;

    function _createMintAuthSet(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2,
        bytes memory metadataBytes
    ) internal pure returns (MintAuthorizationSet memory) {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = metadataBytes;
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = metadataBytes;

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;

        return MintAuthorizationSet({authorizations: authorizations});
    }

    function _verifyMintAuthorizationSetFieldsFromView(bytes29 setRef, MintAuthorizationSet memory authSet) internal pure {
        uint32 numAuths = setRef.getMintAuthorizationSetNumAuthorizations();
        assertEq(numAuths, authSet.authorizations.length, "Eq Fail: numAuths");

        for (uint32 i = 0; i < numAuths; i++) {
            bytes29 authRef = setRef.getMintAuthorizationSetAuthorizationAt(i);
            _verifyMintAuthorizationFieldsFromView(authRef, authSet.authorizations[i]);
        }
    }

    function _assertMintAuthorizationSetsEqual(MintAuthorizationSet memory a, MintAuthorizationSet memory b) internal pure {
        assertEq(a.authorizations.length, b.authorizations.length, "Eq Fail: authorizations length");
        for (uint32 i = 0; i < a.authorizations.length; i++) {
            _assertMintAuthorizationsEqual(a.authorizations[i], b.authorizations[i]);
        }
    }

    // ===== Casting Tests (Set) =====

    function test_asMintAuthorizationSet_correctMagic() public pure {
        (bytes memory data, uint40 magicType) = _magic("circle.gateway.MintAuthorizationSet");
        bytes29 ref = data.asMintAuthorizationSet();
        assertEq(TypedMemView.typeOf(ref), magicType);
        assertEq(bytes4(uint32(magicType)), MINT_AUTHORIZATION_SET_MAGIC);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asMintAuthorizationSet_incorrectMagic() public {
        (bytes memory data,) = _magic("something else");
        vm.expectRevert(abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, data));
        data.asMintAuthorizationSet();
    }

    // ===== Direct Validation Tests =====

    function test_validateMintAuthorizationSet_successFuzz(MintAuthorization memory auth1, MintAuthorization memory auth2) public pure {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);
        bytes29 setView = encodedAuthSet.asMintAuthorizationSet();
        AuthorizationLib.validateMintAuthorizationSet(setView);
    }

    // ===== Field Accessor / Set Iteration Tests =====

    function test_mintAuthorizationSet_readsAllFieldsEmptySet() public pure {
        MintAuthorization[] memory authorizations = new MintAuthorization[](0);
        MintAuthorizationSet memory set = MintAuthorizationSet({ authorizations: authorizations });
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(set);
        bytes29 setRef = encodedAuthSet.asMintAuthorizationSet();
        _verifyMintAuthorizationSetFieldsFromView(setRef, set);
    }

    function test_mintAuthorizationSet_readAllFieldsEmptyMetadataFuzz(MintAuthorization memory auth1, MintAuthorization memory auth2)
        public
        pure
    {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);
        bytes29 setRef = encodedAuthSet.asMintAuthorizationSet();
        _verifyMintAuthorizationSetFieldsFromView(setRef, authSet);
    }

    function test_mintAuthorizationSet_readAllFieldsShortMetadataFuzz(MintAuthorization memory auth1, MintAuthorization memory auth2)
        public
        pure
    {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, SHORT_METADATA);
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);
        bytes29 setRef = encodedAuthSet.asMintAuthorizationSet();
        _verifyMintAuthorizationSetFieldsFromView(setRef, authSet);
    }

    function test_mintAuthorizationSet_readAllFieldsLongMetadataFuzz(MintAuthorization memory auth1, MintAuthorization memory auth2)
        public
        pure
    {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);
        bytes29 setRef = encodedAuthSet.asMintAuthorizationSet();
        _verifyMintAuthorizationSetFieldsFromView(setRef, authSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_mintAuthorizationSet_revertsOnOutOfBoundsAccessFuzz(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2
    ) public {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);
        bytes29 ref = encodedAuthSet.asMintAuthorizationSet();
        uint32 numAuths = ref.getMintAuthorizationSetNumAuthorizations();
        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, "Index out of bounds")
        );
        ref.getMintAuthorizationSetAuthorizationAt(numAuths);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_getMintAuthSetAuthAt_revertsIfDeclaredSpecLengthExceedsBoundsFuzz(MintAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = SHORT_METADATA;

        MintAuthorization[] memory authorizations = new MintAuthorization[](1);
        authorizations[0] = auth1;
        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);

        bytes memory encodedAuth1 = AuthorizationLib.encodeMintAuthorization(auth1);
        uint256 originalAuth1Length = encodedAuth1.length;
        uint32 originalSpecLength = uint32(originalAuth1Length - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        // Increase the declared spec length within the encoded data without actually adding more data bytes
        uint256 specLengthOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET;
        uint32 corruptedSpecLength = 2 * originalSpecLength;
        bytes4 encodedCorruptedLength = bytes4(corruptedSpecLength);

        bytes memory corruptedEncodedAuthSet = encodedAuthSet;
        for (uint8 i = 0; i < 4; i++) {
            corruptedEncodedAuthSet[specLengthOffset + i] = encodedCorruptedLength[i];
        }

        bytes29 ref = corruptedEncodedAuthSet.asMintAuthorizationSet();

        // Expect the revert from the bounds check added in getMintAuthorizationSetAuthorizationAt
        vm.expectRevert(
            abi.encodeWithSelector(
                AuthorizationLib.MalformedMintAuthorizationSet.selector,
                "Calculated authorization slice exceeds set bounds"
            )
        );
        ref.getMintAuthorizationSetAuthorizationAt(0);
    }

    // ===== Encode/Decode Round Trip Tests =====

    function test_encodeDecode_roundTrip_emptySet() public view {
        MintAuthorization[] memory authorizations = new MintAuthorization[](0);
        MintAuthorizationSet memory set = MintAuthorizationSet({ authorizations: authorizations });
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(set);
        MintAuthorizationSet memory decodedAuthSet = AuthorizationLib.decodeMintAuthorizationSet(encodedAuthSet);
        _assertMintAuthorizationSetsEqual(decodedAuthSet, set);
    }

    function test_encodeDecode_roundTrip_emptyMetadataFuzz(MintAuthorization memory auth1, MintAuthorization memory auth2) public view {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);
        MintAuthorizationSet memory decodedAuthSet = AuthorizationLib.decodeMintAuthorizationSet(encodedAuthSet);
        _assertMintAuthorizationSetsEqual(decodedAuthSet, authSet);
    }

    function test_encodeDecode_roundTrip_shortMetadataFuzz(MintAuthorization memory auth1, MintAuthorization memory auth2) public view {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, SHORT_METADATA);
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);
        MintAuthorizationSet memory decodedAuthSet = AuthorizationLib.decodeMintAuthorizationSet(encodedAuthSet);
        _assertMintAuthorizationSetsEqual(decodedAuthSet, authSet);
    }

    function test_encodeDecode_roundTrip_longMetadataFuzz(MintAuthorization memory auth1, MintAuthorization memory auth2) public view {
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, LONG_METADATA);
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);
        MintAuthorizationSet memory decodedAuthSet = AuthorizationLib.decodeMintAuthorizationSet(encodedAuthSet);
        _assertMintAuthorizationSetsEqual(decodedAuthSet, authSet);
    }

    // ===== Decode Failures: Set Structure and Iteration =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnDataTooShortForMagic() public {
        bytes memory shorterThanMagic = new bytes(2);
        // Expect the revert from the initial length check in decodeMintAuthorizationSet
        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, shorterThanMagic)
        );
        AuthorizationLib.decodeMintAuthorizationSet(shorterThanMagic);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnCorruptedMagic() public {
        MintAuthorization[] memory authorizations = new MintAuthorization[](0);
        MintAuthorizationSet memory set = MintAuthorizationSet({ authorizations: authorizations });
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(set);

        // Corrupt the first byte of the magic
        encodedAuthSet[0] = hex"FF";
        vm.expectRevert(
            abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, encodedAuthSet)
        );
        AuthorizationLib.decodeMintAuthorizationSet(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnDataTooShortForHeader() public {
        // Length is > magic (4) but < header (8)
        bytes memory shortData = abi.encodePacked(MINT_AUTHORIZATION_SET_MAGIC, hex"112233"); // 7 bytes
        bytes memory expectedRevertData = abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, "Data too short for set header");

        bytes29 setView = shortData.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(shortData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnEmptyAuthorizationsWithTrailingBytes() public {
         bytes memory encodedSetHeader = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
            uint32(0) // numAuthorizations = 0
        );
        bytes memory trailingBytesData = bytes.concat(encodedSetHeader, hex"FFFF");
        bytes memory expectedRevertData = abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, "Set length mismatch after validating all elements");

        bytes29 setView = trailingBytesData.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(trailingBytesData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsIfDataEndsPrematurely_BeforeFirstAuthHeader() public {
        // Set numAuthorizations = 1 but provide only the set header
        bytes memory encodedSetHeaderOnly = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
            uint32(1) // numAuthorizations = 1
        ); // 8 bytes total
        bytes memory expectedRevertData = abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, "Data too short for next MintAuthorization header");

        bytes29 setView = encodedSetHeaderOnly.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(encodedSetHeaderOnly);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsIfDataEndsPrematurely_WithinFirstAuthHeaderFuzz(MintAuthorization memory auth1) public {
         // Set numAuthorizations = 1, provide set header + partial auth header
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        bytes memory encodedAuth1 = AuthorizationLib.encodeMintAuthorization(auth1);

        bytes memory encodedSetHeader = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
            uint32(1) // numAuthorizations = 1
        );

        // Truncate the first auth header (e.g., provide only 10 bytes of it)
        uint256 partialAuthHeaderLength = 10;
        bytes memory partialAuthData = new bytes(partialAuthHeaderLength);
        for (uint256 i=0; i < partialAuthHeaderLength; i++) {
            partialAuthData[i] = encodedAuth1[i];
        }

        bytes memory truncatedData = bytes.concat(encodedSetHeader, partialAuthData);

        bytes memory expectedRevertData = abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, "Data too short for next MintAuthorization header");

        bytes29 setView = truncatedData.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsIfDataEndsPrematurely_BasedOnFirstAuthSpecLengthFuzz(MintAuthorization memory auth1) public {
        // Set numAuthorizations = 1, provide set header + full auth header + partial spec
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;
        bytes memory encodedAuth1 = AuthorizationLib.encodeMintAuthorization(auth1);

        bytes memory encodedSetHeader = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
            uint32(1) // numAuthorizations = 1
        );

        // Truncate the overall data just before the end of the first auth's spec
        uint256 truncatedLength = encodedSetHeader.length + encodedAuth1.length - 1;
        bytes memory truncatedData = new bytes(truncatedLength);
        bytes memory combined = bytes.concat(encodedSetHeader, encodedAuth1);
        for(uint256 i=0; i < truncatedLength; i++) {
            truncatedData[i] = combined[i];
        }

        bytes memory expectedRevertData = abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, "Data too short for next MintAuthorization");

        bytes29 setView = truncatedData.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(truncatedData);
    }

     /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsIfDataEndsPrematurely_BetweenAuthorizationsFuzz(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2
    ) public {
        // Set numAuthorizations = 2, provide set header + auth1 + partial auth2 header
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);

        bytes memory encodedAuth1 = AuthorizationLib.encodeMintAuthorization(auth1);
        bytes memory encodedAuth2 = AuthorizationLib.encodeMintAuthorization(auth2);

        bytes memory encodedSetHeader = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
            uint32(2) // numAuthorizations = 2
        );

        // Truncate data after auth1 and partway into auth2's header
        uint256 partialAuth2HeaderLength = 10;
        bytes memory partialAuth2Data = new bytes(partialAuth2HeaderLength);
        for (uint256 i=0; i < partialAuth2HeaderLength; i++) {
            partialAuth2Data[i] = encodedAuth2[i];
        }

        bytes memory truncatedData = bytes.concat(encodedSetHeader, encodedAuth1, partialAuth2Data);

        bytes memory expectedRevertData = abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, "Data too short for next MintAuthorization header");

        bytes29 setView = truncatedData.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsIfDataEndsPrematurely_WithinSecondAuthorizationFuzz(
        MintAuthorization memory auth1,
        MintAuthorization memory auth2
    ) public {
        // Set numAuthorizations = 2, provide set header + auth1 + auth2 header + partial auth2 spec
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);

        bytes memory encodedAuth1 = AuthorizationLib.encodeMintAuthorization(auth1);
        bytes memory encodedAuth2 = AuthorizationLib.encodeMintAuthorization(auth2);

        bytes memory encodedSetHeader = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
            uint32(2) // numAuthorizations = 2
        );

        // Truncate data partway through the second authorization's spec
        uint256 truncatedLength = encodedSetHeader.length + encodedAuth1.length + encodedAuth2.length - 1;
        bytes memory truncatedData = new bytes(truncatedLength);
        bytes memory combined = bytes.concat(encodedSetHeader, encodedAuth1, encodedAuth2);
        for(uint256 i=0; i < truncatedLength; i++) {
            truncatedData[i] = combined[i];
        }

        bytes memory expectedRevertData = abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, "Data too short for next MintAuthorization");

        bytes29 setView = truncatedData.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(truncatedData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnTrailingBytes_WhenEmpty() public {
         bytes memory encodedSetHeader = abi.encodePacked(
            MINT_AUTHORIZATION_SET_MAGIC,
            uint32(0) // numAuthorizations = 0
        );
        bytes memory trailingBytesData = bytes.concat(encodedSetHeader, hex"FFFF"); // Add trailing bytes
        bytes memory expectedRevertData = abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, "Set length mismatch after validating all elements");

        bytes29 setView = trailingBytesData.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(trailingBytesData);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnTrailingBytes_AfterAllAuthsFuzz(MintAuthorization memory auth1, MintAuthorization memory auth2) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);

        // Add trailing bytes
        bytes memory trailingBytesData = bytes.concat(encodedAuthSet, hex"FFFF");
        bytes memory expectedRevertData = abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, "Set length mismatch after validating all elements");

        bytes29 setView = trailingBytesData.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(trailingBytesData);
    }

    // ===== Decode Failures: Inner Authorization Consistency =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnInnerAuth_CorruptedMagic_InFirstFuzz(MintAuthorization memory auth1, MintAuthorization memory auth2) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);

        // Corrupt the magic of the first authorization (at offset 8)
        encodedAuthSet[MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET] = hex"FF";

        bytes memory expectedRevertData = abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, "Invalid authorization magic in set");

        bytes29 setView = encodedAuthSet.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnInnerAuth_CorruptedMagic_InSecondFuzz(MintAuthorization memory auth1, MintAuthorization memory auth2) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = new bytes(0);
        auth2.spec.version = TRANSFER_SPEC_VERSION;
        auth2.spec.metadata = new bytes(0);
        MintAuthorizationSet memory authSet = _createMintAuthSet(auth1, auth2, new bytes(0));
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);

        // Calculate offset of second authorization's magic
        bytes memory encodedAuth1 = AuthorizationLib.encodeMintAuthorization(authSet.authorizations[0]);
        uint256 secondAuthOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + encodedAuth1.length;

        // Corrupt the magic of the second authorization
        encodedAuthSet[secondAuthOffset] = hex"FF";

        bytes memory expectedRevertData = abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, "Invalid authorization magic in set");

        bytes29 setView = encodedAuthSet.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnInnerSpec_CorruptedMagicFuzz(MintAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        MintAuthorization[] memory authorizations = new MintAuthorization[](1);
        authorizations[0] = auth1;
        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);

        // Corrupt the inner TransferSpec magic within the first authorization
        uint256 innerSpecMagicOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
        encodedAuthSet[innerSpecMagicOffset] = hex"FF";

        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedTransferSpec.selector,
            "Invalid TransferSpec magic in MintAuthorization"
        );

        bytes29 setView = encodedAuthSet.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(encodedAuthSet);
    }

     /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnInnerSpec_DeclaredMetadataLengthTooBigFuzz(MintAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        MintAuthorization[] memory authorizations = new MintAuthorization[](1);
        authorizations[0] = auth1;
        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);

        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);
        uint256 encodedAuth1Length = encodedAuthSet.length - MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;

        // Corrupt the inner TransferSpec metadata length field (make it larger)
        uint256 innerMetadataLengthOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + TRANSFER_SPEC_METADATA_LENGTH_OFFSET;
        uint32 invalidMetadataLength = originalMetadataLength + 1;
        bytes4 encodedInvalidLength = bytes4(invalidMetadataLength);
        for (uint256 i = 0; i < 4; i++) {
            encodedAuthSet[innerMetadataLengthOffset + i] = encodedInvalidLength[i];
        }

        uint256 expectedInnerSpecLength = TRANSFER_SPEC_METADATA_OFFSET + invalidMetadataLength;
        uint256 actualInnerSpecLength = encodedAuth1Length - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
            expectedInnerSpecLength,
            actualInnerSpecLength
        );

        bytes29 setView = encodedAuthSet.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(encodedAuthSet);
    }

     /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnInnerSpec_DeclaredMetadataLengthTooSmallFuzz(MintAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        MintAuthorization[] memory authorizations = new MintAuthorization[](1);
        authorizations[0] = auth1;
        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);

        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);
        uint256 encodedAuth1Length = encodedAuthSet.length - MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET;

        // Corrupt the inner TransferSpec metadata length field (make it smaller)
        uint256 innerMetadataLengthOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET + TRANSFER_SPEC_METADATA_LENGTH_OFFSET;
        uint32 invalidMetadataLength = originalMetadataLength / 2; // Make it smaller
        bytes4 encodedInvalidLength = bytes4(invalidMetadataLength);
        for (uint256 i = 0; i < 4; i++) {
            encodedAuthSet[innerMetadataLengthOffset + i] = encodedInvalidLength[i];
        }

        uint256 expectedInnerSpecLength = TRANSFER_SPEC_METADATA_OFFSET + invalidMetadataLength;
        uint256 actualInnerSpecLength = encodedAuth1Length - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET;
        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
            expectedInnerSpecLength,
            actualInnerSpecLength
        );

        bytes29 setView = encodedAuthSet.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnInnerAuth_DeclaredSpecLengthTooSmallFuzz(MintAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA;

        MintAuthorization[] memory authorizations = new MintAuthorization[](1);
        authorizations[0] = auth1;
        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);

        bytes memory encodedAuth1 = AuthorizationLib.encodeMintAuthorization(auth1);
        uint256 originalAuthLength = encodedAuth1.length;
        uint32 originalSpecLength = uint32(originalAuthLength - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET);
        uint32 originalMetadataLength = uint32(auth1.spec.metadata.length);

        // Corrupt the outer MintAuthorization's declared spec length (make it smaller)
        uint256 outerSpecLengthOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET;
        uint32 invalidSpecLength = originalSpecLength - 1;
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
         for (uint8 i = 0; i < 4; i++) {
            encodedAuthSet[outerSpecLengthOffset + i] = encodedInvalidLength[i];
        }

        // The failure occurs inside the TransferSpec decoding because the outer corruption
        // leads to providing a truncated spec slice.
        uint256 expectedInnerSpecLengthBasedOnMetadata = TRANSFER_SPEC_METADATA_OFFSET + originalMetadataLength;

        bytes memory expectedRevertData = abi.encodeWithSelector(
            AuthorizationLib.MalformedTransferSpecInvalidLength.selector,
            expectedInnerSpecLengthBasedOnMetadata, // Length expected by inner spec based on its metadata
            invalidSpecLength // Actual length of the spec slice provided due to outer corruption
        );

        bytes29 setView = encodedAuthSet.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(encodedAuthSet);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_decode_set_revertsOnInnerAuth_DeclaredSpecLengthTooLargeFuzz(MintAuthorization memory auth1) public {
        auth1.spec.version = TRANSFER_SPEC_VERSION;
        auth1.spec.metadata = LONG_METADATA; // Ensure metadata exists

        MintAuthorization[] memory authorizations = new MintAuthorization[](1);
        authorizations[0] = auth1;
        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthSet = AuthorizationLib.encodeMintAuthorizationSet(authSet);

        bytes memory encodedAuth1 = AuthorizationLib.encodeMintAuthorization(auth1);
        uint256 originalAuthLength = encodedAuth1.length;
        uint32 originalSpecLength = uint32(originalAuthLength - MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET);

        // Corrupt the outer MintAuthorization's declared spec length (make it larger)
        uint256 outerSpecLengthOffset = MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET + MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET;
        uint32 invalidSpecLength = originalSpecLength + 1; // Make it larger than actual
        bytes4 encodedInvalidLength = bytes4(invalidSpecLength);
         for (uint256 i = 0; i < 4; i++) {
            encodedAuthSet[outerSpecLengthOffset + i] = encodedInvalidLength[i];
        }

        // The failure occurs in the main decode loop when checking if the set data
        // is long enough to contain the authorization based on its inflated declared length.
        bytes memory expectedRevertData = abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, "Data too short for next MintAuthorization");

        bytes29 setView = encodedAuthSet.asMintAuthorizationSet();
        vm.expectRevert(expectedRevertData);
        AuthorizationLib.validateMintAuthorizationSet(setView);

        vm.expectRevert(expectedRevertData);
        AuthorizationLib.decodeMintAuthorizationSet(encodedAuthSet);
    }

} 