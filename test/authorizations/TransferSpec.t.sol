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

import {TypedMemView} from "@memview-sol/TypedMemView.sol";
import {TransferSpec, TRANSFER_SPEC_VERSION, TRANSFER_SPEC_MAGIC} from "src/lib/authorizations/TransferSpec.sol";
import {TransferSpecLib} from "src/lib/authorizations/TransferSpecLib.sol";
import {AuthorizationTestUtils} from "./AuthorizationTestUtils.sol";

contract TransferSpecTest is AuthorizationTestUtils {
    using TransferSpecLib for bytes;
    using TransferSpecLib for bytes29;

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
        // The first 4 bytes of data will be the incorrect magic.
        bytes4 incorrectMagic = bytes4(data);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidTransferSpecMagic.selector, incorrectMagic));
        data.asTransferSpec();
    }

    // ===== Field Accessor Tests =====

    function test_transferSpec_readAllFieldsEmptyMetadataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = new bytes(0);
        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.asTransferSpec();
        _verifyTransferSpecFieldsFromView(ref, spec);
    }

    function test_transferSpec_readAllFieldsShortMetadataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = SHORT_METADATA;
        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.asTransferSpec();
        _verifyTransferSpecFieldsFromView(ref, spec);
    }

    function test_transferSpec_readAllFieldsLongMetadataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = LONG_METADATA;
        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.asTransferSpec();
        _verifyTransferSpecFieldsFromView(ref, spec);
    }

    // ===== Hash Utility Tests =====

    function test_getTransferSpecHash_withMetadataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = SHORT_METADATA;
        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.asTransferSpec();

        bytes32 expectedHash = keccak256(encodedSpec);
        bytes32 libHash = TransferSpecLib.getHash(ref);

        assertEq(libHash, expectedHash, "Hash mismatch for non-empty metadata");
    }
}
