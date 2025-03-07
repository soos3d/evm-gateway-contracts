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

/// Events emitted by the SpendWallet contract
interface ISpendWalletEvents {
    /// Emitted when a deposit is made
    ///
    /// @param token       The token that was deposited
    /// @param depositor   The address that deposited the funds
    /// @param value       The amount that was deposited
    event Deposited(address indexed token, address indexed depositor, uint256 value);

    /// Emitted when a spender is authorized to spend a depositor's balance
    ///
    /// @param token       The token that the spender is now authorized for
    /// @param depositor   The depositor who added the spender
    /// @param spender     The spender that was added
    event SpenderAdded(address indexed token, address indexed depositor, address spender);

    /// Emitted when a spender's authorization is revoked
    ///
    /// @param token       The token the spender is no longer authorized for
    /// @param depositor   The depositor who removed the spender
    /// @param spender     The spender that was removed
    event SpenderRemoved(address indexed token, address indexed depositor, address spender);

    /// Emitted when a withdrawal is initiated
    ///
    /// @param token              The token that is being withdrawn
    /// @param depositor          The owner of the funds being withdrawn
    /// @param spender            The spender that authorized the withdrawal
    /// @param value              The value that is newly being withdrawn
    /// @param totalWithdrawing   The total value that is now being withdrawn
    /// @param withdrawableAt     The block number at which the withdrawal can
    ///                           be completed
    event WithdrawalInitiated(
        address indexed token,
        address indexed depositor,
        address spender,
        uint256 value,
        uint256 totalWithdrawing,
        uint256 withdrawableAt
    );

    /// Emitted when a withdrawal is completed and funds have been transferred
    ///      to the depositor
    ///
    /// @param token       The token that was withdrawn
    /// @param depositor   The owner and recipient of the withdrawn funds
    /// @param spender     The spender that authorized the withdrawal
    /// @param value       The value that was withdrawn
    event WithdrawalCompleted(address indexed token, address indexed depositor, address spender, uint256 value);

    /// Emitted when the operator burns tokens that have been spent on another
    ///      domain
    ///
    /// @param token               The token that was spent
    /// @param depositor           The depositor who owned the spent balance
    /// @param spendHash           The keccak256 hash of the `SpendSpec`
    /// @param destinationDomain   The domain the spend was used on
    /// @param recipient           The recipient of the funds at the destination
    /// @param spender             The spender that authorized the spend
    /// @param value               The value that was spent
    /// @param fee                 The fee charged for the burn
    /// @param total               The total value burnt, including the fee
    /// @param fromSpendable       The value burnt from the `spendable` balance
    /// @param fromWithdrawing     The value burnt from the `withdrawing` balance
    /// @param burnAuthorization   The entire burn authorization that was used
    event BurnedSpent(
        address indexed token,
        address indexed depositor,
        bytes32 indexed spendHash,
        uint32 destinationDomain,
        bytes32 recipient,
        address spender,
        uint256 value,
        uint256 fee,
        uint256 total,
        uint256 fromSpendable,
        uint256 fromWithdrawing,
        bytes burnAuthorization
    );

    /// Emitted when a spend authorization is used on the same chain as its
    ///      source, resulting in a same-chain spend that transfers funds to the
    ///      recipient instead of minting and burning them
    ///
    /// @param token                The token that was spent
    /// @param depositor            The depositor who owned the spent balance
    /// @param spendHash            The keccak256 hash of the SpendSpec
    /// @param recipient            The recipient of the funds
    /// @param spender              The spender that authorized the spend
    /// @param value                The value transferred to the recipient
    /// @param fromSpendable        The value transferred from the `spendable`
    ///                             balance
    /// @param fromWithdrawing      The value transferred from the `withdrawing`
    ///                             balance
    /// @param spendAuthorization   The entire spend authorization that was used
    event TransferredSpent(
        address indexed token,
        address indexed depositor,
        bytes32 indexed spendHash,
        bytes32 recipient,
        address spender,
        uint256 value,
        uint256 fromSpendable,
        uint256 fromWithdrawing,
        bytes spendAuthorization
    );

    /// Emitted when a token is added to the set of supported tokens
    ///
    /// @param token   The token that is now supported
    event TokenSupported(address token);

    /// Emitted when a depositor is added to the rejection list
    ///
    /// @param depositor   The address that is rejected from spending
    event DepositorRejected(address depositor);

    /// Emitted when a depositor is removed from the rejection list
    ///
    /// @param depositor   The address that is allowed to spend again
    event DepositorAllowed(address depositor);

    /// Emitted when the minter contract is updated
    ///
    /// @param newMinterContract   The new minter contract address
    event MinterContractUpdated(address newMinterContract);

    /// Emitted when the withdrawal delay is updated
    ///
    /// @param newDelay   The new value of the delay, in blocks
    event WithdrawalDelayUpdated(uint256 newDelay);

    /// Emitted when the burner address is updated
    ///
    /// @param newBurner   The new burner address
    event BurnerUpdated(address newBurner);

    /// Emitted when the pauser address is updated
    ///
    /// @param newPauser   The new pauser address
    event PauserUpdated(address newPauser);
}
