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
import {TransferSpec, TRANSFER_SPEC_VERSION, TRANSFER_SPEC_MAGIC} from "src/lib/TransferSpec.sol";
import {TransferSpecLib} from "src/lib/TransferSpecLib.sol";
import {TransferPayloadTestUtils} from "./TransferPayloadTestUtils.sol";

contract TransferSpecTest is TransferPayloadTestUtils {
    using TransferSpecLib for bytes;
    using TransferSpecLib for bytes29;
    using TypedMemView for bytes;
    using TypedMemView for bytes29;

    // ===== Field Accessor Tests =====

    function test_transferSpec_readAllFieldsEmptyMetadataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = new bytes(0);
        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.ref(uint40(uint32(TRANSFER_SPEC_MAGIC)));
        _verifyTransferSpecFieldsFromView(ref, spec);
    }

    function test_transferSpec_readAllFieldsShortMetadataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = SHORT_METADATA;
        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.ref(uint40(uint32(TRANSFER_SPEC_MAGIC)));
        _verifyTransferSpecFieldsFromView(ref, spec);
    }

    function test_transferSpec_readAllFieldsLongMetadataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = LONG_METADATA;
        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.ref(uint40(uint32(TRANSFER_SPEC_MAGIC)));
        _verifyTransferSpecFieldsFromView(ref, spec);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_transferSpec_readMetadata_revertsOnInvalidMetadataFuzz(TransferSpec memory spec) public {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = LONG_METADATA;
        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);

        (bytes memory corruptedData, uint32 corruptedMetadataLength) =
            _getCorruptedInnerSpecMetadataLengthData(encodedSpec, 0, uint32(LONG_METADATA.length), true);
        bytes29 corruptedRef = corruptedData.ref(uint40(uint32(TRANSFER_SPEC_MAGIC)));

        vm.expectRevert(
            abi.encodeWithSelector(
                TransferSpecLib.TransferSpecInvalidMetadata.selector, corruptedMetadataLength, corruptedRef.len()
            )
        );
        TransferSpecLib.getMetadata(corruptedRef);
    }

    // ===== Hash Utility Tests =====

    function test_getTransferSpecHash_withMetadataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = SHORT_METADATA;
        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.ref(uint40(uint32(TRANSFER_SPEC_MAGIC)));

        bytes32 expectedHash = keccak256(encodedSpec);
        bytes32 libHash = TransferSpecLib.getHash(ref);

        assertEq(libHash, expectedHash, "Hash mismatch for non-empty metadata");
    }

    // ===== Failure Tests =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_encode_tooLongMetadata() public {
        // Simulate metadata with a size of `type(uint32).max + 1`
        bytes memory metadata = SHORT_METADATA;
        uint256 maxSize = uint256(type(uint32).max);
        assembly {
            mstore(metadata, add(maxSize, 1))
        }

        // Create a transfer spec with the corrupted metadata
        TransferSpec memory spec;
        spec.version = TRANSFER_SPEC_VERSION;
        spec.metadata = metadata;

        // Expect it to revert because the metadata is too long
        vm.expectRevert(
            abi.encodeWithSelector(TransferSpecLib.TransferSpecMetadataFieldTooLarge.selector, maxSize + 1, maxSize)
        );
        TransferSpecLib.encodeTransferSpec(spec);
    }
}
