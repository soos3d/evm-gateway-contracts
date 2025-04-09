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

import {TransferSpec} from "./TransferSpec.sol";

/// @dev Magic: bytes4(keccak256("circle.gateway.MintAuthorization"))
bytes4 constant MINT_AUTHORIZATION_MAGIC = 0x23ba354a;
/// @dev Magic: bytes4(keccak256("circle.gateway.MintAuthorizationSet"))
bytes4 constant MINT_AUTHORIZATION_SET_MAGIC = 0x95f860bd;

// MintAuthorization field offsets
uint16 constant MINT_AUTHORIZATION_MAGIC_OFFSET = 0;
uint16 constant MINT_AUTHORIZATION_MAX_BLOCK_HEIGHT_OFFSET = 4;
uint16 constant MINT_AUTHORIZATION_TRANSFER_SPEC_LENGTH_OFFSET = 36;
uint16 constant MINT_AUTHORIZATION_TRANSFER_SPEC_OFFSET = 40;

// MintAuthorizationSet field offsets
uint16 constant MINT_AUTHORIZATION_SET_MAGIC_OFFSET = 0;
uint16 constant MINT_AUTHORIZATION_SET_NUM_AUTHORIZATIONS_OFFSET = 4;
uint16 constant MINT_AUTHORIZATION_SET_AUTHORIZATIONS_OFFSET = 8;

/// Passed to the GatewayMinter contract on the destination domain by the user or a relayer
///
/// @dev Magic: bytes4(keccak256("circle.gateway.MintAuthorization"))
/// @dev The keccak256 hash of the encoded TransferSpec is used as a cross-chain identifier, for both linkability
///      and replay protection.
///
/// Byte encoding (big-endian):
///     FIELD                      OFFSET   BYTES   NOTES
///     magic                           0       4   Always 0x23ba354a
///     max block height                4      32
///     transfer spec length           36       4   In bytes, may vary based on metadata length
///     encoded transfer spec          40       ?   Must be the length indicated above
struct MintAuthorization {
    uint256 maxBlockHeight; //   Valid until this block height
    TransferSpec spec; //        A description of the transfer
}

/// Represents multiple MintAuthorizations packed together and signed as a single payload, for transferring from
/// multiple domains.
///
/// @dev Magic: bytes4(keccak256("circle.gateway.MintAuthorizationSet"))
///
/// Byte encoding (big-endian):
///     FIELD                      OFFSET   BYTES   NOTES
///     magic                           0       4   Always 0x95f860bd
///     number of authorizations        4       4
///     authorizations                  8       ?   Sorted by source domain and concatenated
struct MintAuthorizationSet {
    MintAuthorization[] authorizations;
}
