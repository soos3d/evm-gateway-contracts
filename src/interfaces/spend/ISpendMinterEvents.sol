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

/// Events emitted by the SpendMinter contract
interface ISpendMinterEvents {
    /// Emitted when the a spend authorization is used
    ///
    /// @param token                The token that was spent
    /// @param recipient            The recipient of the funds
    /// @param spendHash            The keccak256 hash of the `SpendSpec`
    /// @param sourceDomain         The domain the funds came from
    /// @param depositor            The depositor on the source domain
    /// @param value                The amount that was minted/transferred
    /// @param spendAuthorization   The entire spend authorization that was used
    event Spent(
        address indexed token,
        address indexed recipient,
        bytes32 indexed spendHash,
        uint32 sourceDomain,
        bytes32 depositor,
        uint256 value,
        bytes spendAuthorization
    );

    /// Emitted when a recipient is added to the rejection list
    ///
    /// @param recipient   The address that is rejected from receiving funds
    event RecipientRejected(address recipient);

    /// Emitted when a recipient is removed from the rejection list
    ///
    /// @param recipient   The address that is allowed to receive funds again
    event RecipientAllowed(address recipient);

    /// Emitted when the wallet contract is updated
    ///
    /// @param newWalletContract   The new wallet contract address
    event WalletContractUpdated(address newWalletContract);

    /// Emitted when the pauser address is updated
    ///
    /// @param newPauser   The new pauser address
    event PauserUpdated(address newPauser);
}
