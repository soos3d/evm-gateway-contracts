/**
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
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
import {WithdrawalDelay} from "src/modules/wallet/WithdrawalDelay.sol";

/// @title Withdrawals
///
/// @notice Manages withdrawals for the `GatewayWallet` contract
contract Withdrawals is Pausing, TokenSupport, WithdrawalDelay, Balances {
    using SafeERC20 for IERC20;

    /// Emitted when a withdrawal is initiated
    ///
    /// @param token                The token that is being withdrawn
    /// @param depositor            The owner of the funds being withdrawn
    /// @param value                The value that was added to the in-progress withdrawal
    /// @param remainingAvailable   The remaining available balance after the withdrawal
    /// @param totalWithdrawing     The total value that is now being withdrawn
    /// @param withdrawalBlock      The block number at which the full withdrawal can be completed
    event WithdrawalInitiated(
        address indexed token,
        address indexed depositor,
        uint256 value,
        uint256 remainingAvailable,
        uint256 totalWithdrawing,
        uint256 withdrawalBlock
    );

    /// Emitted when a withdrawal is completed and funds have been transferred to the depositor
    ///
    /// @param token        The token that was withdrawn
    /// @param depositor    The owner of the withdrawn funds
    /// @param value        The value that was withdrawn
    event WithdrawalCompleted(address indexed token, address indexed depositor, uint256 value);

    /// Thrown when a zero-value withdrawal is attempted
    error WithdrawalValueMustBePositive();

    /// Thrown with a withdrawal is attempted that exceeds the available balance
    error WithdrawalValueExceedsAvailableBalance();

    /// Initializes the underlying `WithdrawalDelay` module
    ///
    /// @param withdrawalDelay_   The initial value for the delay, in blocks
    function __Withdrawals_init(uint256 withdrawalDelay_) internal onlyInitializing {
        __WithdrawalDelay_init(withdrawalDelay_);
    }

    /// Starts the withdrawal process. After `withdrawalDelay` blocks, `withdraw` may be called to complete the
    /// withdrawal. Once a withdrawal has been initiated, that amount can no longer be used. Repeated calls will add to
    /// the amount and reset the timer.
    ///
    /// @param token   The token to initiate a withdrawal for
    /// @param value   The amount to be withdrawn
    function initiateWithdrawal(address token, uint256 value) external whenNotPaused tokenSupported(token) {
        address depositor = msg.sender;
        _initiateWithdrawal(token, depositor, value);
    }

    /// Completes a withdrawal that was initiated at least `withdrawalDelay` blocks ago. The funds are sent to
    /// the depositor (msg.sender).
    ///
    /// @dev The full amount that is in the process of being withdrawn is always withdrawn
    ///
    /// @param token   The token to withdraw
    function withdraw(address token) external whenNotPaused tokenSupported(token) {
        address depositor = msg.sender;
        _withdraw(token, depositor);
    }

    /// Internal helper function to initiate a withdrawal
    ///
    /// @param token        The token to initiate a withdrawal for
    /// @param depositor    The owner of the balance from which the withdrawal should come
    /// @param value        The amount to be withdrawn
    function _initiateWithdrawal(address token, address depositor, uint256 value) internal {
        // Ensure that the withdrawal value is non-zero
        if (value == 0) {
            revert WithdrawalValueMustBePositive();
        }

        // Ensure that the depositor has enough available balance to cover the withdrawal
        if (value > availableBalance(token, depositor)) {
            revert WithdrawalValueExceedsAvailableBalance();
        }

        // Move the specified amount from the depositor's available balance to their in-progress withdrawal balance
        (uint256 remainingAvailable, uint256 totalWithdrawing) = _moveBalanceToWithdrawing(token, depositor, value);

        // Calculate and set the block height at which the withdrawal may be completed
        uint256 withdrawalBlock = block.number + withdrawalDelay();
        _setWithdrawalBlock(token, depositor, withdrawalBlock);

        // Emit an event to signal the withdrawal initiation
        emit WithdrawalInitiated(token, depositor, value, remainingAvailable, totalWithdrawing, withdrawalBlock);
    }

    /// Internal helper function to complete a withdrawal
    ///
    /// @param token        The token to withdraw
    /// @param depositor    The owner of the balance from which the withdrawal should come
    function _withdraw(address token, address depositor) internal {
        // Ensure that the withdrawal was initiated at least `withdrawalDelay` blocks ago
        _ensureWithdrawable(token, depositor);

        // Empty the depositor's in-progress withdrawal balance and reset the withdrawal block
        uint256 balanceToWithdraw = _emptyWithdrawingBalance(token, depositor);
        _setWithdrawalBlock(token, depositor, 0);

        // Transfer the funds to the depositor
        IERC20(token).safeTransfer(depositor, balanceToWithdraw);

        // Emit an event to signal the withdrawal completion
        emit WithdrawalCompleted(token, depositor, balanceToWithdraw);
    }
}
