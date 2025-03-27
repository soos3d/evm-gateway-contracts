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

bytes4 constant BURN_AUTHORIZATION_MAGIC = 0x71a020ae;
bytes4 constant BURN_AUTHORIZATIONS_MAGIC = 0xc98d4e93;

/// Passed to the GatewayWallet contract on the source domain by the operator, in order to burn those funds.
///
/// @dev Magic: bytes4(keccak256("circle.gateway.BurnAuthorization")) or
///             bytes4(keccak256("circle.gateway.BurnAuthorization[]"))
/// @dev In addition to a byte encoding for a single burn authorization, there is also an encoding for several
///      authorizations packed together. This allows a wallet to sign a single payload for a set of burns from multiple
///      domains, as long as the signature scheme is shared.
/// @dev The keccak256 hash of the encoded TransferSpec is used as a cross-chain identifier, for both linkability
///      and replay protection.
///
/// Byte encoding (single, big-endian):
///     FIELD                      OFFSET   BYTES   NOTES
///     magic                           0       4   Always 0x71a020ae
///     max block height                4      32
///     max fee                        36      32   Denominated in the token
///     transfer spec length           68       4   In bytes, may vary based on metadata length
///     encoded spend spec             72       ?   Must be the length indicated above
///
/// Byte encoding (multiple, big-endian):
///     FIELD                      OFFSET   BYTES   NOTES
///     magic                           0       4   Always 0xc98d4e93
///     number of authorizations        4       4
///     authorizations                  8       ?   Must be sorted by source domain and concatenated
struct BurnAuthorization {
    uint256 maxBlockHeight; //   Valid until this block height on the source domain
    uint256 maxFee; //           The maximum fee that may be collected by the operator
    TransferSpec spec; //        A description of the transfer
}
