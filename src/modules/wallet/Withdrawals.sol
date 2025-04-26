/*
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.

 * SPDX-License-Identifier: Apache-2.0

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pragma solidity ^0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Pausing} from "src/modules/common/Pausing.sol";
import {TokenSupport} from "src/modules/common/TokenSupport.sol";
import {Balances} from "src/modules/wallet/Balances.sol";
import {Delegation} from "src/modules/wallet/Delegation.sol";
import {WithdrawalDelay} from "src/modules/wallet/WithdrawalDelay.sol";

/// @title Withdrawals
///
/// Manages withdrawals for the GatewayWallet contract
contract Withdrawals is Pausing, TokenSupport, WithdrawalDelay, Balances, Delegation {
    using SafeERC20 for IERC20;

    /// Emitted when a withdrawal is initiated
    ///
    /// @param token              The token that is being withdrawn
    /// @param depositor          The owner of the funds being withdrawn
    /// @param authorizer         The address that initiated the withdrawal
    /// @param value              The value that is newly being withdrawn
    /// @param totalWithdrawing   The total value that is now being withdrawn
    /// @param withdrawalBlock    The block number at which the withdrawal can be completed
    event WithdrawalInitiated(
        address indexed token,
        address indexed depositor,
        address indexed authorizer,
        uint256 value,
        uint256 remainingAvailable,
        uint256 totalWithdrawing,
        uint256 withdrawalBlock
    );

    /// Emitted when a withdrawal is completed and funds have been transferred to the recipient
    ///
    /// @param token        The token that was withdrawn
    /// @param depositor    The owner of the withdrawn funds
    /// @param recipient    The recipient of the funds
    /// @param authorizer   The address that authorized the withdrawal completion
    /// @param value        The value that was withdrawn
    event WithdrawalCompleted(
        address indexed token, address indexed depositor, address indexed recipient, address authorizer, uint256 value
    );

    error WithdrawalValueMustBePositive();
    error WithdrawalValueExceedsAvailableBalance();

    /// Starts the withdrawal process. After `withdrawalDelay`, `withdraw` may be called to complete the withdrawal.
    /// Once a withdrawal has been initiated, that amount can no longer be spent. Repeated calls will add to the amount
    /// and reset the timer.
    ///
    /// @param token   The token to initiate a withdrawal for
    /// @param value   The amount to be withdrawn
    function initiateWithdrawal(address token, uint256 value) external whenNotPaused tokenSupported(token) {
        _initiateWithdrawal(token, msg.sender, msg.sender, value);
    }

    /// Starts the withdrawal process on behalf of a depositor who has authorized the caller. After `withdrawalDelay`,
    /// `withdraw` may be called to complete the withdrawal. Once a withdrawal has been initiated, that amount can no
    /// longer be spent. Repeated calls will add to the amount and reset the timer.
    ///
    /// @dev The caller of this method must be the depositor or an authorized delegate of `depositor` for `token`
    ///
    /// @param token       The token to initiate a withdrawal for
    /// @param depositor   The owner of the balance from which the withdrawal should come
    /// @param value       The amount to be withdrawn
    function initiateWithdrawal(address token, address depositor, uint256 value)
        external
        whenNotPaused
        tokenSupported(token)
        authorizedForBalance(token, depositor, msg.sender)
    {
        _initiateWithdrawal(token, depositor, msg.sender, value);
    }

    /// Completes a withdrawal that was initiated at least `withdrawalDelay` blocks ago.
    ///
    /// @dev The full amount that was initiated is always withdrawn
    ///
    /// @param token   The token to withdraw
    function withdraw(address token) external whenNotPaused tokenSupported(token) {
        _withdraw(token, msg.sender, msg.sender);
    }

    /// Completes a withdrawal that was initiated at least `withdrawalDelay` blocks ago. The funds are sent to the
    /// specified recipient.
    ///
    /// @dev The full amount that was initiated is always withdrawn
    ///
    /// @param token       The token to withdraw
    /// @param depositor   The owner of the balance from which the withdrawal should come
    /// @param recipient   The recipient of the funds
    function withdraw(address token, address depositor, address recipient)
        external
        whenNotPaused
        tokenSupported(token)
        authorizedForBalance(token, depositor, msg.sender)
    {
        _withdraw(token, depositor, recipient);
    }

    /// Internal helper function to initiate a withdrawal
    ///
    /// @param token       The token to initiate a withdrawal for
    /// @param depositor   The owner of the balance from which the withdrawal should come
    /// @param authorizer  The address initiating the withdrawal
    /// @param value       The amount to be withdrawn
    function _initiateWithdrawal(address token, address depositor, address authorizer, uint256 value) internal {
        if (value == 0) {
            revert WithdrawalValueMustBePositive();
        }

        if (value > availableBalance(token, depositor)) {
            revert WithdrawalValueExceedsAvailableBalance();
        }

        (uint256 remainingAvailable, uint256 totalWithdrawing) = _moveBalanceToWithdrawing(token, depositor, value);

        uint256 withdrawalBlock = block.number + withdrawalDelay();
        _setWithdrawalBlock(token, depositor, withdrawalBlock);

        emit WithdrawalInitiated(
            token, depositor, authorizer, value, remainingAvailable, totalWithdrawing, withdrawalBlock
        );
    }

    /// Internal helper function to complete a withdrawal
    ///
    /// @param token       The token to withdraw
    /// @param depositor   The owner of the balance from which the withdrawal should come
    /// @param recipient   The recipient of the funds
    function _withdraw(address token, address depositor, address recipient) internal {
        _ensureWithdrawable(token, depositor);

        uint256 balanceToWithdraw = _emptyWithdrawingBalance(token, depositor);
        _setWithdrawalBlock(token, depositor, 0);

        IERC20(token).safeTransfer(recipient, balanceToWithdraw);

        emit WithdrawalCompleted(token, depositor, recipient, msg.sender, balanceToWithdraw);
    }
}
