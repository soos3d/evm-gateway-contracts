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

/// Describes a spend that may happen
///
/// @dev Magic: bytes4(keccak256("circle.spend.SpendSpec"))
///
/// Byte encoding:
///     FIELD                     BYTES   NOTES
///     magic                         4   Always 0x67db5aa9
///     version                       4   Always 1
///     source domain                 4
///     destination domain            4
///     source token                 32
///     destination token            32
///     source spender               32
///     source depositor             32   May be 0, to indicate the same as spender
///     destination recipient        32
///     destination contract         32
///     destination caller           32   May be 0, to allow any caller
///     value                        32
///     nonce                        32
///     metadata length in bytes      4
///     metadata                      ?   Must be the length indicated above
struct SpendSpec {
    uint32 version; //                 To allow for future upgrades
    uint32 sourceDomain; //            The chain this spend came from
    uint32 destinationDomain; //       The chain this spend is valid on
    bytes32 sourceToken; //            The token on the source domain
    bytes32 destinationToken; //       The token on the destination domain
    bytes32 sourceSpender; //          The source chain spender
    bytes32 sourceDepositor; //        The source chain address to debit
    bytes32 destinationRecipient; //   The recipient of the funds
    bytes32 destinationContract; //    The address of the destination contract
    bytes32 destinationCaller; //      The caller who may use the spend
    uint256 value; //                  The amount to be minted / transferred
    bytes32 nonce; //                  Chosen by the user to be unique
    bytes metadata; //                 Arbitrary bytes used for composition
}

/// Passed to the SpendDestination contract on the destination chain by the user
///
/// @dev Magic: bytes4(keccak256("circle.spend.SpendAuthorization")) or
///             bytes4(keccak256("circle.spend.SpendAuthorization[]"))
/// @dev In addition to a byte encoding for a single spend authorization, there
///      is also an encoding for several authorizations packed together. This
///      allows the operator to sign them as a group and enforce that they are
///      all used together.
/// @dev A keccak256 hash of each encoded SpendSpec is emitted as part of an
///      event on the destination chain, to be used as a cross-chain identifier
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

/// Passed to the SpendWallet contract on the source chain by the operator
///
/// @dev Magic: bytes4(keccak256("circle.spend.BurnAuthorization")) or
///             bytes4(keccak256("circle.spend.BurnAuthorization[]"))
/// @dev In addition to a byte encoding for a single burn authorization, there
///      is also an encoding for several authorizations packed together. This
///      allows a wallet to sign a single payload for a set of burns from
///      multiple domains, as long as the signature scheme is shared.
/// @dev A keccak256 hash of each encoded SpendSpec is emitted as part of an
///      event on the source chain, to be used as a cross-chain identifier
///
/// Byte encoding (single):
///     FIELD                     BYTES   NOTES
///     magic                         4   Always 0xa13a4873
///     max block height             32
///     max fee                      32   Denominated in the token
///     spend spec length in bytes    4   May vary based on metadata length
///     encoded spend spec            ?   Must be the length indicated above
///
/// Byte encoding (multiple):
///     FIELD                     BYTES   NOTES
///     magic                         4   Always 0x2ee059ef
///     number of authorizations      4
///     authorizations                ?   Sorted by source domain and concatenated
struct BurnAuthorization {
    SpendSpec spend; //          A description of the spend
    uint256 maxBlockHeight; //   Valid until this block height
    uint256 maxFee; //           The maximum fee that may be collected
}