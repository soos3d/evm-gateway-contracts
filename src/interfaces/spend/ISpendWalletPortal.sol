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

/// Methods for the SpendWallet contract that are only callable by the
///      SpendDestination contract on the same chain
interface ISpendWalletPortal {
    /// Debits the depositor's balance like `burnSpent`, but transfers
    ///      funds instead of burning them. Used when a spend happens on the
    ///      same chain to avoid burning and minting. No fee is charged.
    ///
    /// @dev The caller of this method must be the `destinationContract`
    /// @dev The source and destination domains must both be this contract's
    ///      domain
    /// @dev See the docs for `SpendAuthorization` for encoding details
    ///
    /// @param authorization   The spend authorization that was passed to the
    ///                        destination contract
    /// @param signature       The signature from the operator
    function sameChainSpend(bytes memory authorization, bytes memory signature) external;
}
