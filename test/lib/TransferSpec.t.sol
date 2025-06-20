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
import {TransferPayloadTestUtils} from "test/util/TransferPayloadTestUtils.sol";

contract TransferSpecTest is TransferPayloadTestUtils {
    using TransferSpecLib for bytes;
    using TransferSpecLib for bytes29;
    using TypedMemView for bytes;
    using TypedMemView for bytes29;

    // ===== Field Accessor Tests =====

    function test_transferSpec_readAllFieldsEmptyHookDataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.hookData = new bytes(0);
        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.ref(uint40(uint32(TRANSFER_SPEC_MAGIC)));
        _verifyTransferSpecFieldsFromView(ref, spec);
    }

    function test_transferSpec_readAllFieldsShortHookDataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.hookData = SHORT_HOOK_DATA;
        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.ref(uint40(uint32(TRANSFER_SPEC_MAGIC)));
        _verifyTransferSpecFieldsFromView(ref, spec);
    }

    function test_transferSpec_readAllFieldsLongHookDataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.hookData = LONG_HOOK_DATA;
        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.ref(uint40(uint32(TRANSFER_SPEC_MAGIC)));
        _verifyTransferSpecFieldsFromView(ref, spec);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_transferSpec_readHookData_revertsOnInvalidHookDataFuzz(TransferSpec memory spec) public {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.hookData = LONG_HOOK_DATA;
        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);

        (bytes memory corruptedData, uint32 corruptedHookDataLength) =
            _getCorruptedInnerSpecHookDataLengthData(encodedSpec, 0, uint32(LONG_HOOK_DATA.length), true);
        bytes29 corruptedRef = corruptedData.ref(uint40(uint32(TRANSFER_SPEC_MAGIC)));

        vm.expectRevert(
            abi.encodeWithSelector(
                TransferSpecLib.TransferSpecInvalidHookData.selector, corruptedHookDataLength, corruptedRef.len()
            )
        );
        TransferSpecLib.getHookData(corruptedRef);
    }

    // ===== Hash Utility Tests =====

    function test_getTransferSpecHash_withHookDataFuzz(TransferSpec memory spec) public pure {
        spec.version = TRANSFER_SPEC_VERSION;
        spec.hookData = SHORT_HOOK_DATA;
        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.ref(uint40(uint32(TRANSFER_SPEC_MAGIC)));

        bytes32 expectedHash = keccak256(encodedSpec);
        bytes32 libHash = TransferSpecLib.getHash(ref);

        assertEq(libHash, expectedHash, "Hash mismatch for non-empty hook data");
    }

    // ===== Failure Tests =====

    /// forge-config: default.allow_internal_expect_revert = true
    function test_encode_tooLongHookData() public {
        // Simulate hook data with a size of `type(uint32).max + 1`
        bytes memory hookData = SHORT_HOOK_DATA;
        uint256 maxSize = uint256(type(uint32).max);
        assembly {
            mstore(hookData, add(maxSize, 1))
        }

        // Create a transfer spec with the corrupted hook data
        TransferSpec memory spec;
        spec.version = TRANSFER_SPEC_VERSION;
        spec.hookData = hookData;

        // Expect it to revert because the hook data is too long
        vm.expectRevert(
            abi.encodeWithSelector(TransferSpecLib.TransferSpecHookDataFieldTooLarge.selector, maxSize + 1, maxSize)
        );
        TransferSpecLib.encodeTransferSpec(spec);
    }

    /// @dev The getTypedDataHash function uses the identity precompile (address 0x04) to efficiently
    /// copy memory. While precompile failures are extremely rare, checking the return value is a
    /// security best practice to prevent silent failures that could corrupt hash computation.
    ///
    /// If the staticcall to address 4 returns false, the function will revert with "revert(0, 0)"
    /// rather than continuing with potentially corrupted data, preventing signature validation bypasses.
    //
    // It is difficult to test this in Foundry, so we just check that the function returns a non-zero hash.
    function test_getTypedDataHash_identityPrecompileReturnValueCheck() public view {
        // Create a minimal valid transfer spec
        TransferSpec memory spec;
        spec.version = TRANSFER_SPEC_VERSION;
        spec.hookData = new bytes(0);

        bytes memory encodedSpec = TransferSpecLib.encodeTransferSpec(spec);
        bytes29 ref = encodedSpec.ref(uint40(uint32(TRANSFER_SPEC_MAGIC)));

        // Verify the function executes without reverting (precompile succeeds)
        bytes32 hash = TransferSpecLib.getTypedDataHash(ref);

        // Basic sanity check - the function should return a non-zero hash
        assertTrue(hash != bytes32(0), "getTypedDataHash should return non-zero hash");
    }
}
