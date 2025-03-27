/*
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.

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

import {SpendSpec} from "./SpendSpec.sol";

/// Passed to the SpendDestination contract on the destination chain by the user
///
/// @dev Magic: bytes4(keccak256("circle.spend.SpendAuthorization")) or
///             bytes4(keccak256("circle.spend.SpendAuthorization[]"))
/// @dev In addition to a byte encoding for a single spend authorization, there is also an encoding for several
///      authorizations packed together. This allows the operator to sign them as a group and enforce that they are all
///      used together.
/// @dev A keccak256 hash of each encoded SpendSpec is emitted as part of an event on the destination chain, to be used
///      as a cross-chain identifier
///
/// Byte encoding (single):
///     FIELD                     BYTES   NOTES
///     magic                         4   Always 0x690995b4
///     max block height             32
///     spend spec length in bytes    4   May vary based on metadata length
///     encoded spend spec            ?   Must be the length indicated above
///
/// Byte encoding (multiple):
///     FIELD                     BYTES   NOTES
///     magic                         4   Always 0x03b4bd77
///     number of authorizations      4
///     authorizations                ?   Sorted by source domain and concatenated
struct SpendAuthorization {
    SpendSpec spend; //          A description of the spend
    uint256 maxBlockHeight; //   Valid until this block height
}
