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
