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

/// User-facing methods for the SpendWallet contract
interface ISpendWalletUser {
    /// Deposit tokens after approving this contract for the token
    ///
    /// @dev The resulting balance in this contract belongs to `msg.sender`
    ///
    /// @param token   The token to deposit
    /// @param value   The amount to be deposited
    function deposit(address token, uint256 value) external;

    /// Deposit tokens with an EIP-2612 permit
    ///
    /// @dev The resulting balance in this contract belongs to `owner`
    /// @dev The permit's `spender` must be the address of this contract
    /// @dev The full permitted `value` is always deposited
    ///
    /// @param token      The token to deposit
    /// @param owner      The depositor's address
    /// @param value      The amount to be deposited
    /// @param deadline   The time at which the signature expires (unix time),
    ///                   or max uint256 value to signal no expiration
    /// @param v          v of the signature
    /// @param r          r of the signature
    /// @param s          s of the signature
    function depositWithPermit(
        address token,
        address owner,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /// Deposit tokens with an EIP-2612 permit, passing the signature as bytes
    ///      to allow for SCA deposits
    ///
    /// @dev The resulting balance in this contract belongs to `owner`
    /// @dev The permit's `spender` must be the address of this contract
    /// @dev The full permitted `value` is always deposited
    /// @dev EOA wallet signatures should be packed in the order of r, s, v
    ///
    /// @param token       The token to deposit
    /// @param owner       The depositor's address
    /// @param value       The amount to be deposited
    /// @param deadline    The time at which the signature expires (unix time),
    ///                    or max uint256 value to signal no expiration
    /// @param signature   Signature bytes signed by an EOA wallet or a contract
    ///                    wallet
    function depositWithPermit(address token, address owner, uint256 value, uint256 deadline, bytes memory signature)
        external;

    /// Deposit tokens with an ERC-3009 authorization
    ///
    /// @dev The resulting balance in this contract belongs to `from`
    /// @dev The authorization's `to` must be the address of this contract
    /// @dev The transfer will be done via `transferWithAuthorization`
    ///
    /// @param token         The token to deposit
    /// @param from          The depositor's address
    /// @param value         The amount to be deposited
    /// @param validAfter    The time after which this is valid (unix time)
    /// @param validBefore   The time before which this is valid (unix time)
    /// @param nonce         Unique nonce
    /// @param v             v of the signature
    /// @param r             r of the signature
    /// @param s             s of the signature
    function depositWithAuthorization(
        address token,
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /// Deposit tokens with an ERC-3009 authorization, passing the signature as
    ///      bytes to allow for SCA deposits
    ///
    /// @dev The resulting balance in this contract belongs to `from`
    /// @dev The authorization's `to` must be the address of this contract
    /// @dev The transfer will be done via `transferWithAuthorization`
    /// @dev EOA wallet signatures should be packed in the order of r, s, v
    ///
    /// @param token         The token to deposit
    /// @param from          The depositor's address
    /// @param value         The amount to be deposited
    /// @param validAfter    The time after which this is valid (unix time)
    /// @param validBefore   The time before which this is valid (unix time)
    /// @param nonce         Unique nonce
    /// @param signature     Signature bytes signed by an EOA wallet or a
    ///                      contract wallet
    function depositWithAuthorization(
        address token,
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external;

    /// Allow `spender` to spend the caller's `token` balance
    ///
    /// @dev This acts as a full allowance for `spender` on the `token` balance
    ///      of `msg.sender` in this contract
    ///
    /// @param token     The token that `spender` should be allowed to spend
    /// @param spender   The address being authorized to spend
    function addSpender(address token, address spender) external;

    /// Stop allowing `spender` to spend the caller's `token` balance
    ///
    /// @dev This revokes the allowance granted by `addSpender`
    ///
    /// @param token     The token that `spender` should be allowed to spend
    /// @param spender   The address being authorized to spend
    function removeSpender(address token, address spender) external;

    /// Starts the withdrawal process. After `withdrawalDelay`, `withdraw` may
    ///      be called to complete the withdrawal. Once a withdrawal has been
    ///      initiated, that amount can no longer be spent. Calling this again
    ///      before `withdrawalDelay` is over will add to the amount and reset
    ///      the timer.
    ///
    /// @param token   The token to initiate a withdrawal for
    /// @param value   The amount to be withdrawn
    function initiateWithdrawal(address token, uint256 value) external;

    /// Starts the withdrawal process on behalf of a depositor who has
    ///      authorized the caller. After `withdrawalDelay`, `withdraw` may be
    ///      called to complete the withdrawal. Once a withdrawal has been
    ///      initiated, that amount can no longer be spent. Calling this again
    ///      before `withdrawalDelay` is over will add to the amount and reset
    ///      the timer.
    ///
    /// @dev The caller of this method must be an authorized spender of
    ///      `depositor` for `token`
    ///
    /// @param token       The token to initiate a withdrawal for
    /// @param depositor   The owner of the balance from which the withdrawal
    ///                    should come
    /// @param value       The amount to be withdrawn
    function initiateWithdrawal(address token, address depositor, uint256 value) external;

    /// Completes a withdrawal that was initiated at least `withdrawalDelay`
    ///      blocks ago.
    ///
    /// @dev The full amount that was initiated is always withdrawn
    ///
    /// @param token   The token to withdraw
    function withdraw(address token) external;

    /// Completes a withdrawal that was initiated at least `withdrawalDelay`
    ///      blocks ago. The funds are sent to the caller of this method, who
    ///      must be an authorized spender of `depositor` for `token`.
    ///
    /// @dev The full amount that was initiated is always withdrawn
    ///
    /// @param token       The token to withdraw
    /// @param depositor   The owner of the balance from which the withdrawal
    ///                    should come
    function withdraw(address token, address depositor) external;
}
