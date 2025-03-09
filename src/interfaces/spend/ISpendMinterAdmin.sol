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

/// Methods for the SpendMinter contract that are only callable by various admin roles
interface ISpendMinterAdmin {
    /// Marks a token as supported. Once supported, tokens can not be un-supported.
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param token   The token to be added
    function addSupportedToken(address token) external;

    /// Rejects a recipient from receiving funds from future spends. Used to deny service for legal reasons.
    ///
    /// @param recipient   The recipient to be rejected
    function rejectRecipient(address recipient) external;

    /// Allows a previously-rejected recipient to receive funds again
    ///
    /// @param recipient   The recipient to be allowed
    function allowRecipient(address recipient) external;

    /// Sets the address of the corresponding wallet contract on this chain, in order to call `sameChainSpend`
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newWalletContract   The new wallet contract address
    function updateWalletContract(address newWalletContract) external;
}
