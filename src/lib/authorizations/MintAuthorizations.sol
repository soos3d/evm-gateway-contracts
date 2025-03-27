/*
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.

 * SPDX-License-Identifier: GPL-3.0-or-later

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
pragma solidity ^0.8.28;

import {TransferSpec} from "./TransferSpec.sol";

bytes4 constant MINT_AUTHORIZATION_MAGIC = 0x23ba354a;
bytes4 constant MINT_AUTHORIZATION_SET_MAGIC = 0x95f860bd;

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
///     transfer spec length           36       4   In bytes, ay vary based on metadata length
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
