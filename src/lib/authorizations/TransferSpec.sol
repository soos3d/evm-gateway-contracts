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

bytes4 constant TRANSFER_SPEC_MAGIC = 0xca85def7;
uint32 constant TRANSFER_SPEC_VERSION = 1;

// Field offsets
uint16 constant TRANSFER_SPEC_MAGIC_OFFSET = 0;
uint16 constant TRANSFER_SPEC_VERSION_OFFSET = 4;
uint16 constant TRANSFER_SPEC_SOURCE_DOMAIN_OFFSET = 8;
uint16 constant TRANSFER_SPEC_DESTINATION_DOMAIN_OFFSET = 12;
uint16 constant TRANSFER_SPEC_SOURCE_CONTRACT_OFFSET = 16;
uint16 constant TRANSFER_SPEC_DESTINATION_CONTRACT_OFFSET = 48;
uint16 constant TRANSFER_SPEC_SOURCE_TOKEN_OFFSET = 80;
uint16 constant TRANSFER_SPEC_DESTINATION_TOKEN_OFFSET = 112;
uint16 constant TRANSFER_SPEC_SOURCE_DEPOSITOR_OFFSET = 144;
uint16 constant TRANSFER_SPEC_DESTINATION_RECIPIENT_OFFSET = 176;
uint16 constant TRANSFER_SPEC_SOURCE_SIGNER_OFFSET = 208;
uint16 constant TRANSFER_SPEC_DESTINATION_CALLER_OFFSET = 240;
uint16 constant TRANSFER_SPEC_VALUE_OFFSET = 272;
uint16 constant TRANSFER_SPEC_NONCE_OFFSET = 304;
uint16 constant TRANSFER_SPEC_METADATA_LENGTH_OFFSET = 336;
uint16 constant TRANSFER_SPEC_METADATA_OFFSET = 340;

/// Describes a transfer that may happen. Embedded in both a BurnAuthorization and a MintAuthorization.
///
/// @dev Magic: bytes4(keccak256("circle.gateway.TransferSpec"))
/// @dev The keccak256 hash of the encoded TransferSpec is used as a cross-chain identifier, for both linkability
///      and replay protection. As such, repeated transfers with identical parameters must use a different nonce.
///
/// Byte encoding (big-endian):
///     FIELD                     OFFSET   BYTES   NOTES
///     magic                          0       4   Always 0xca85def7
///     version                        4       4   Always 1
///     source domain                  8       4
///     destination domain            12       4
///     source contract               16      32
///     destination contract          48      32
///     source token                  80      32
///     destination token            112      32
///     source depositor             144      32
///     destination recipient        176      32
///     source signer                208      32   May be 0, to indicate the same as depositor
///     destination caller           240      32   May be 0, to allow any caller
///     value                        272      32
///     nonce                        304      32   Any random unique value, not necessarily sequential
///     metadata length              336       4   In bytes, 0 to indicate no metadata
///     metadata                     340       ?   Must be the length indicated above if present
struct TransferSpec {
    uint32 version; //                 To allow for future upgrades
    uint32 sourceDomain; //            The domain of the wallet contract this transfer came from
    uint32 destinationDomain; //       The domain of the minter contract this transfer is valid for
    bytes32 sourceContract; //         The address of the wallet contract on the source domain
    bytes32 destinationContract; //    The address of the minter contract on the destination domain
    bytes32 sourceToken; //            The token address on the source domain
    bytes32 destinationToken; //       The token address on the destination domain
    bytes32 sourceDepositor; //        The address to debit within the wallet contract on the source domain
    bytes32 destinationRecipient; //   The address that should receive the funds on the destination domain
    bytes32 sourceSigner; //           The signer who signed for the transfer, 0 if the same as the depositor
    bytes32 destinationCaller; //      The address of the caller who may use the authorization, 0 if any caller
    uint256 value; //                  The amount to be minted or transferred
    bytes32 nonce; //                  An arbitrary value chosen by the user to be unique
    bytes metadata; //                 Arbitrary bytes that may be used for onchain composition
}
