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

import {IERC1155Balance} from "src/interfaces/IERC1155Balance.sol";
import {TokenSupport} from "src/modules/common/TokenSupport.sol";
import {WithdrawalDelay} from "src/modules/wallet/WithdrawalDelay.sol";

/// The various balances that are tracked, used for the ERC-1155 balance functions
enum BalanceType {
    Total,
    Available,
    Withdrawing,
    Withdrawable
}

/// @title Balances
///
/// @notice Manages balances for the `GatewayWallet` contract
contract Balances is TokenSupport, WithdrawalDelay, IERC1155Balance {
    /// Thrown during attempted withdrawals when there is no withdrawing balance to withdraw
    error NoWithdrawingBalance();

    /// Thrown when the ERC-1155 `balanceOf` function is called with an invalid `BalanceType`
    error InvalidBalanceType(uint96 balanceType);

    /// Thrown when the ERC-1155 `balanceOfBatch` function is called with arrays of different lengths
    error InputArrayLengthMismatch();

    /// The total balance of a depositor for a token. This will always be equal to the sum of `availableBalance` and
    /// `withdrawingBalance`.
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    /// @return            The total balance of the depositor for the token
    function totalBalance(address token, address depositor) public view returns (uint256) {
        BalancesStorage.Data storage $ = BalancesStorage.get();
        return $.availableBalances[token][depositor] + $.withdrawingBalances[token][depositor];
    }

    /// The balance that is available to the depositor, subject to deposits having been observed by the operator in a
    /// finalized block and no mint authorizations having been issued but not yet burned by the operator or used on the
    /// same chain
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    /// @return            The available balance of the depositor for the token
    function availableBalance(address token, address depositor) public view returns (uint256) {
        return BalancesStorage.get().availableBalances[token][depositor];
    }

    /// The balance that is in the process of being withdrawn
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    /// @return            The withdrawing balance of the depositor for the token
    function withdrawingBalance(address token, address depositor) public view tokenSupported(token) returns (uint256) {
        return BalancesStorage.get().withdrawingBalances[token][depositor];
    }

    /// The balance that is withdrawable as of the current block. This will either be 0 or `withdrawingBalance`.
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    /// @return            The withdrawable balance of the depositor for the token
    function withdrawableBalance(address token, address depositor)
        public
        view
        tokenSupported(token)
        returns (uint256)
    {
        uint256 balanceToWithdraw = BalancesStorage.get().withdrawingBalances[token][depositor];
        if (balanceToWithdraw == 0 || withdrawalBlock(token, depositor) > block.number) {
            return 0;
        }

        return balanceToWithdraw;
    }

    /// The balance of a depositor for a particular token and balance type, compatible with ERC-1155
    ///
    /// @dev The token `id` should be encoded as `uint256(abi.encodePacked(uint12(BALANCE_TYPE), address(token)))`,
    ///      where `BALANCE_TYPE` is 0 for `Total`, 1 for `Available`, 2 for `Withdrawing`, and 3 for `Withdrawable`.
    ///
    /// @param depositor   The depositor of the requested balance
    /// @param id          The packed token and balance type
    /// @return            The balance of the depositor for the token and balance type
    function balanceOf(address depositor, uint256 id) public view override returns (uint256) {
        // Ensure that the token is supported
        address token = address(uint160(id));
        if (!isTokenSupported(token)) {
            revert UnsupportedToken(token);
        }

        // Ensure that the balance type is valid
        uint96 balanceType = uint96(id >> 160);
        if (balanceType > uint96(type(BalanceType).max)) {
            revert InvalidBalanceType(balanceType);
        }

        // Return the correct balance based on the balance type
        if (BalanceType(balanceType) == BalanceType.Total) {
            return totalBalance(token, depositor);
        } else if (BalanceType(balanceType) == BalanceType.Available) {
            return availableBalance(token, depositor);
        } else if (BalanceType(balanceType) == BalanceType.Withdrawing) {
            return withdrawingBalance(token, depositor);
        } else {
            // BalanceType(balanceType) == BalanceType.Withdrawable
            return withdrawableBalance(token, depositor);
        }
    }

    /// The batch version of `balanceOf`, compatible with ERC-1155
    ///
    /// @dev `depositors` and `ids` must be the same length
    ///
    /// @param depositors   The depositor of the requested balance
    /// @param ids          The packed token and balance type
    /// @return             The balances of the depositors for the tokens and balance types
    function balanceOfBatch(address[] calldata depositors, uint256[] memory ids)
        external
        view
        override
        returns (uint256[] memory)
    {
        // Ensure the arrays are the same length
        if (depositors.length != ids.length) {
            revert InputArrayLengthMismatch();
        }

        // Fill in and return the results by calling `balanceOf`
        uint256[] memory batchBalances = new uint256[](depositors.length);
        for (uint256 i = 0; i < depositors.length; i++) {
            batchBalances[i] = balanceOf(depositors[i], ids[i]);
        }

        return batchBalances;
    }

    /// Increases a depositor's available balance by a specified value
    ///
    /// @param token       The token whose balance is being increased
    /// @param depositor   The depositor whose balance is being increased
    /// @param value       The amount to be added
    function _increaseAvailableBalance(address token, address depositor, uint256 value) internal {
        BalancesStorage.get().availableBalances[token][depositor] += value;
    }

    /// Moves a specified value from a depositor's available balance to their withdrawing balance
    ///
    /// @param token                 The token whose balance is being moved
    /// @param depositor             The depositor whose balance is being moved
    /// @param value                 The amount to be moved
    /// @return remainingAvailable   The remaining `available` balance after the move
    /// @return totalWithdrawing     The total `withdrawing` balance after the move
    function _moveBalanceToWithdrawing(address token, address depositor, uint256 value)
        internal
        returns (uint256 remainingAvailable, uint256 totalWithdrawing)
    {
        BalancesStorage.Data storage $ = BalancesStorage.get();

        $.availableBalances[token][depositor] -= value;
        $.withdrawingBalances[token][depositor] += value;

        return ($.availableBalances[token][depositor], $.withdrawingBalances[token][depositor]);
    }

    /// Decreases a depositor's withdrawing balance to zero, returning what it was beforehand
    ///
    /// @dev Reverts if the withdrawing balance is already zero
    ///
    /// @param token        The token whose balance is being withdrawn
    /// @param depositor    The depositor whose balance is being withdrawn
    /// @return withdrawn   The amount that was withdrawn
    function _emptyWithdrawingBalance(address token, address depositor) internal returns (uint256 withdrawn) {
        BalancesStorage.Data storage $ = BalancesStorage.get();

        uint256 balanceToWithdraw = $.withdrawingBalances[token][depositor];
        if (balanceToWithdraw == 0) {
            revert NoWithdrawingBalance();
        }

        $.withdrawingBalances[token][depositor] = 0;

        return balanceToWithdraw;
    }

    /// Reduces a depositor's balances by a specified value, prioritizing the available balance
    ///
    /// @param token               The token whose balance is being reduced
    /// @param depositor           The depositor whose balance is being reduced
    /// @param value               The amount to be reduced
    /// @return fromAvailable      The amount deducted from the `available` balance
    /// @return fromWithdrawing    The amount deducted from the `withdrawing` balance
    function _reduceBalance(address token, address depositor, uint256 value)
        internal
        returns (uint256 fromAvailable, uint256 fromWithdrawing)
    {
        BalancesStorage.Data storage $ = BalancesStorage.get();

        uint256 available = $.availableBalances[token][depositor];
        uint256 needed = value;

        // If there is enough in the available balance, deduct from it and return
        if (available >= needed) {
            $.availableBalances[token][depositor] -= needed;
            return (needed, 0);
        }

        // Otherwise, take it all and continue for the rest
        $.availableBalances[token][depositor] = 0;
        needed -= available;

        uint256 withdrawing = $.withdrawingBalances[token][depositor];

        // If there is enough in the withdrawing balance, deduct from it and return
        if (withdrawing >= needed) {
            $.withdrawingBalances[token][depositor] -= needed;
            return (available, needed);
        }

        // Otherwise, take it all
        $.withdrawingBalances[token][depositor] = 0;

        return (available, withdrawing);
    }
}

/// Implements the EIP-7201 storage pattern for the `Balances` module
library BalancesStorage {
    /// @custom:storage-location 7201:circle.gateway.Balances
    struct Data {
        /// The balances that have been deposited and are available for use (after finalization)
        mapping(address token => mapping(address depositor => uint256 value)) availableBalances;
        /// The balances that are in the process of being withdrawn and are no longer available
        mapping(address token => mapping(address depositor => uint256 value)) withdrawingBalances;
    }

    /// `keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Balances"))) - 1)) & ~bytes32(uint256(0xff))`
    bytes32 public constant SLOT = 0xdd3dca88e892815d13ea80f1982e32e4fe3d0a89f03d14d3565bf56d58c31a00;

    /// EIP-7201 getter for the storage slot
    function get() internal pure returns (Data storage $) {
        assembly {
            $.slot := SLOT
        }
    }
}
