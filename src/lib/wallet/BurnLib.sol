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

import {BurnsStorage} from "src/lib/wallet/Burns.sol";
import {AuthorizationCursor} from "src/lib/authorizations/AuthorizationCursor.sol";
import {BurnAuthorizationLib} from "src/lib/authorizations/BurnAuthorizationLib.sol";
import {TransferSpecLib} from "src/lib/authorizations/TransferSpecLib.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// Handles the implementation of burning, split out as an external library for bytecode size
library BurnLib {
    using MessageHashUtils for bytes32;
    using TransferSpecLib for bytes29;
    using BurnAuthorizationLib for bytes29;

    error InvalidBurnSigner();
    error MismatchedBurn();

    /// Debit the depositor's balance and burn the tokens after a spend was authorized
    ///
    /// @dev `authorizations`, `signatures`, and `fees` must all be the same length
    /// @dev Will revert if `destinationDomain` is the same as `sourceDomain` (since no burn is required)
    /// @dev For a set of burn authorizations, authorizations from other domains are ignored. The whole set is still
    ///      needed to verify the signature.
    /// @dev See `lib/authorizations/BurnAuthorizations.sol` for encoding details
    ///
    /// @param authorizations    An array of byte-encoded burn authorizations
    /// @param signatures        One signature from the authorizer of each burn authorization (set)
    /// @param fees              The fees to be collected for each burn. Fees for burns on other domains are ignored and
    ///                          may be passed as zero. Each fee must be no more than `maxFee` of the corresponding burn
    ///                          authorization.
    /// @param burnerSignature   A signature from `burnSigner` on the abi-encoded first three arguments
    function burnSpent(
        bytes[] memory authorizations,
        bytes[] memory signatures,
        uint256[][] memory fees,
        bytes memory burnerSignature
    ) external view {
        _verifyBurnerSignature(burnerSignature);

        if (signatures.length != authorizations.length || fees.length != authorizations.length) {
            revert MismatchedBurn();
        }

        for (uint256 i = 0; i < authorizations.length; i++) {
            AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(authorizations[i]);
            while (!cursor.done) {
                // TODO
            }
        }
    }

    /// Internal function to verify the signature of the `burnSigner` on the other arguments in calldata, hashing the
    /// arguments from calldata rather than using abi.encode (which does a lot of copying and stack manipulation).
    ///
    /// @dev Must be called only from `burnSpent`, to ensure the calldata is as expected
    ///
    /// @param burnerSignature   The signature from the `burnSigner` to verify
    function _verifyBurnerSignature(bytes memory burnerSignature) internal view {
        // Ensure that the signature is the expected length, to correctly index into the calldata
        if (burnerSignature.length != 65) {
            revert InvalidBurnSigner();
        }

        // Isolate just the arguments that are signed in the calldata by slicing `msg.data`:
        //     - Skips over the beginning of the calldata to get to the first argument
        //         - 4 bytes for the function selector
        //         - 128 bytes for the 4 argument offsets
        //         - 4 + 128 = 132 = 0x84
        //     - Does not include the last argument (the signature itself)
        //         - We know it is 65 bytes (verified above), so takes up 128 (0x80) bytes
        //           (32 for the length, and 96 for the 32-byte-aligned contents)
        bytes memory calldataBytes = msg.data[0x84:msg.data.length - 0x80];

        // Verify the signature and revert if it's invalid
        address recoveredSigner = ECDSA.recover(keccak256(calldataBytes).toEthSignedMessageHash(), burnerSignature);
        if (recoveredSigner != BurnsStorage.get().burnSigner) {
            revert InvalidBurnSigner();
        }
    }
}
