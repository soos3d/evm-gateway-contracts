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

import {TransferSpec} from "./TransferSpec.sol";

// Magic values for marking byte encodings
bytes4 constant BURN_AUTHORIZATION_MAGIC = 0x71a020ae; // `bytes4(keccak256("circle.gateway.BurnAuthorization"))`
bytes4 constant BURN_AUTHORIZATION_SET_MAGIC = 0xb12eecd9; // `bytes4(keccak256("circle.gateway.BurnAuthorizationSet"))`

// `BurnAuthorization` field offsets
uint16 constant BURN_AUTHORIZATION_MAGIC_OFFSET = 0;
uint16 constant BURN_AUTHORIZATION_MAX_BLOCK_HEIGHT_OFFSET = 4;
uint16 constant BURN_AUTHORIZATION_MAX_FEE_OFFSET = 36;
uint16 constant BURN_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET = 68;
uint16 constant BURN_AUTHORIZATION_TRANSFER_SPEC_OFFSET = 72;

// `BurnAuthorizationSet` field offsets
uint16 constant BURN_AUTHORIZATION_SET_MAGIC_OFFSET = 0;
uint16 constant BURN_AUTHORIZATION_SET_NUM_AUTHORIZATIONS_OFFSET = 4;
uint16 constant BURN_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET = 8;

/// @title BurnAuthorization
///
/// @notice Passed to the `GatewayWallet` contract on the source domain by the operator, in order to burn those funds
///
/// @dev Magic: `bytes4(keccak256("circle.gateway.BurnAuthorization"))`
/// @dev The `keccak256` hash of the encoded `TransferSpec` is used as a cross-chain identifier, for both linkability
///      and replay protection. See `TransferSpecHashes.sol` for more details.
///
/// @dev Byte encoding (big-endian):
///     FIELD                      OFFSET   BYTES   NOTES
///     magic                           0       4   Always 0x71a020ae
///     max block height                4      32
///     max fee                        36      32   Denominated in the token
///     transfer spec length           68       4   In bytes, may vary based on metadata length
///     encoded transfer spec          72       ?   Must be the length indicated above
struct BurnAuthorization {
    uint256 maxBlockHeight; //   Valid until this block height on the source domain
    uint256 maxFee; //           The maximum fee that may be collected by the operator
    TransferSpec spec; //        A description of the transfer
}

// Type hash for the BurnAuthorization struct
// keccak256("BurnAuthorization(uint256 maxBlockHeight,uint256 maxFee,TransferSpec spec)TransferSpec(uint32 version,uint32 sourceDomain,uint32 destinationDomain,bytes32 sourceContract,bytes32 destinationContract,bytes32 sourceToken,bytes32 destinationToken,bytes32 sourceDepositor,bytes32 destinationRecipient,bytes32 sourceSigner,bytes32 destinationCaller,uint256 value,bytes32 nonce,bytes metadata)");
bytes32 constant BURN_AUTHORIZATION_TYPEHASH = 0x2a5e505e2d349189754a316be097c53a1adfcc7854a3c174c65261ef80e81752;

/// @title BurnAuthorizationSet
///
/// @notice Represents multiple `BurnAuthorization`s packed together, which allows a wallet to sign a single payload for
/// a set of burns from multiple domains, as long as the signature scheme is shared.
///
/// @dev Magic: `bytes4(keccak256("circle.gateway.BurnAuthorizationSet"))`
///
/// @dev Byte encoding (big-endian):
///     FIELD                      OFFSET   BYTES   NOTES
///     magic                           0       4   Always 0xb12eecd9
///     number of authorizations        4       4
///     authorizations                  8       ?   Concatenated one after another
struct BurnAuthorizationSet {
    BurnAuthorization[] authorizations;
}

// Type hash for the BurnAuthorizationSet struct
// keccak256("BurnAuthorizationSet(BurnAuthorization[] authorizations)BurnAuthorization(uint256 maxBlockHeight,uint256 maxFee,TransferSpec spec)TransferSpec(uint32 version,uint32 sourceDomain,uint32 destinationDomain,bytes32 sourceContract,bytes32 destinationContract,bytes32 sourceToken,bytes32 destinationToken,bytes32 sourceDepositor,bytes32 destinationRecipient,bytes32 sourceSigner,bytes32 destinationCaller,uint256 value,bytes32 nonce,bytes metadata)")
bytes32 constant BURN_AUTHORIZATION_SET_TYPEHASH = 0x8427c16d063c31591baca080350ea510c04656ef77c3931db6abd845a75be251;
