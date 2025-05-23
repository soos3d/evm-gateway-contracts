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
import {Test} from "forge-std/Test.sol";
import {AttestationLib} from "src/lib/AttestationLib.sol";
import {Attestation, ATTESTATION_MAGIC} from "src/lib/Attestations.sol";
import {BurnIntentLib} from "src/lib/BurnIntentLib.sol";
import {BurnIntent, BURN_INTENT_MAGIC} from "src/lib/BurnIntents.sol";
import {TransferSpec, TRANSFER_SPEC_MAGIC, TRANSFER_SPEC_HOOK_DATA_LENGTH_OFFSET} from "src/lib/TransferSpec.sol";
import {TransferSpecLib, BYTES4_BYTES} from "src/lib/TransferSpecLib.sol";

contract TransferPayloadTestUtils is Test {
    using TypedMemView for bytes29; // For keccak/len on views

    bytes internal constant SHORT_HOOK_DATA = "Test hook data";
    bytes internal constant LONG_HOOK_DATA = "This is a longer hook data string to test larger hook data payloads";

    function cloneBytes(bytes memory source) internal pure returns (bytes memory target) {
        target = new bytes(source.length);
        for (uint256 i = 0; i < source.length; i++) {
            target[i] = source[i];
        }
    }

    // Helper to create data with specific magic bytes
    function _magic(string memory label) internal pure returns (bytes memory, uint40) {
        bytes4 magic = bytes4(keccak256(bytes(label)));
        return (abi.encodePacked(magic), uint40(uint32(magic)));
    }

    // Verifies all fields read from a TransferSpec view match the original struct
    function _verifyTransferSpecFieldsFromView(bytes29 ref, TransferSpec memory spec) internal pure {
        ref.assertType(TransferSpecLib._toMemViewType(TRANSFER_SPEC_MAGIC));
        assertEq(TransferSpecLib.getVersion(ref), spec.version, "Eq Fail: version");
        assertEq(TransferSpecLib.getSourceDomain(ref), spec.sourceDomain, "Eq Fail: sourceDomain");
        assertEq(TransferSpecLib.getDestinationDomain(ref), spec.destinationDomain, "Eq Fail: destinationDomain");
        assertEq(TransferSpecLib.getSourceContract(ref), spec.sourceContract, "Eq Fail: sourceContract");
        assertEq(TransferSpecLib.getDestinationContract(ref), spec.destinationContract, "Eq Fail: destinationContract");
        assertEq(TransferSpecLib.getSourceToken(ref), spec.sourceToken, "Eq Fail: sourceToken");
        assertEq(TransferSpecLib.getDestinationToken(ref), spec.destinationToken, "Eq Fail: destinationToken");
        assertEq(TransferSpecLib.getSourceDepositor(ref), spec.sourceDepositor, "Eq Fail: sourceDepositor");
        assertEq(
            TransferSpecLib.getDestinationRecipient(ref), spec.destinationRecipient, "Eq Fail: destinationRecipient"
        );
        assertEq(TransferSpecLib.getSourceSigner(ref), spec.sourceSigner, "Eq Fail: sourceSigner");
        assertEq(TransferSpecLib.getDestinationCaller(ref), spec.destinationCaller, "Eq Fail: destinationCaller");
        assertEq(TransferSpecLib.getValue(ref), spec.value, "Eq Fail: value");
        assertEq(TransferSpecLib.getSalt(ref), spec.salt, "Eq Fail: salt");

        // Hook data checks
        uint32 hookDataLength = TransferSpecLib.getHookDataLength(ref);
        assertEq(hookDataLength, spec.hookData.length, "Mismatch: hookData.length");
        bytes29 hookDataView = TransferSpecLib.getHookData(ref);
        if (hookDataLength > 0) {
            assertEq(hookDataView.keccak(), keccak256(spec.hookData), "Mismatch: hookData keccak");
        } else {
            assertEq(hookDataView.len(), 0, "Mismatch: empty hookDataView length");
        }
    }

    // Verifies all fields read from a BurnIntent view match the original struct
    function _verifyBurnIntentFieldsFromView(bytes29 ref, BurnIntent memory intent) internal pure {
        ref.assertType(TransferSpecLib._toMemViewType(BURN_INTENT_MAGIC));
        assertEq(BurnIntentLib.getMaxBlockHeight(ref), intent.maxBlockHeight, "Eq Fail: maxBlockHeight");
        assertEq(BurnIntentLib.getMaxFee(ref), intent.maxFee, "Eq Fail: maxFee");
        bytes29 specRef = BurnIntentLib.getTransferSpec(ref);
        _verifyTransferSpecFieldsFromView(specRef, intent.spec);
    }

    // Verifies all fields read from a Attestation view match the original struct
    function _verifyAttestationFieldsFromView(bytes29 ref, Attestation memory attestation) internal pure {
        ref.assertType(TransferSpecLib._toMemViewType(ATTESTATION_MAGIC));
        assertEq(AttestationLib.getMaxBlockHeight(ref), attestation.maxBlockHeight, "Eq Fail: maxBlockHeight");
        bytes29 specRef = AttestationLib.getTransferSpec(ref);
        _verifyTransferSpecFieldsFromView(specRef, attestation.spec);
    }

    /// @notice Creates corrupted TransferSpec data by modifying the inner spec's declared hookData length.
    ///         Useful for testing direct `TransferSpec` decoding or decoding of structs containing an embedded `TransferSpec`.
    /// @param encodedStruct The original encoded data containing the TransferSpec.
    /// @param specOffset The starting offset of the inner TransferSpec within `encodedStruct` (0 for direct TransferSpec tests).
    /// @param originalHookDataLength The actual length of the hook data in the original `spec`.
    /// @param makeLengthBigger If true, corrupts the length field to be larger; otherwise, makes it smaller.
    /// @return corruptedData The modified byte array with the corrupted hook data length.
    /// @return corruptedHookDataLength The artificially inflated/deflated hook data length value written into the corrupted data.
    function _getCorruptedInnerSpecHookDataLengthData(
        bytes memory encodedStruct,
        uint32 specOffset,
        uint32 originalHookDataLength,
        bool makeLengthBigger
    ) internal pure returns (bytes memory corruptedData, uint32 corruptedHookDataLength) {
        uint256 innerHookDataLengthOffset = specOffset + TRANSFER_SPEC_HOOK_DATA_LENGTH_OFFSET;
        corruptedData = cloneBytes(encodedStruct);

        if (makeLengthBigger) {
            corruptedHookDataLength = originalHookDataLength * 2;
        } else {
            corruptedHookDataLength = originalHookDataLength / 2;
        }

        bytes4 encodedInvalidLength = bytes4(corruptedHookDataLength);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            corruptedData[innerHookDataLengthOffset + i] = encodedInvalidLength[i];
        }

        return (corruptedData, corruptedHookDataLength);
    }
}
