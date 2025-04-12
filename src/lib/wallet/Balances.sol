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
pragma solidity ^0.8.28;

import {TokenSupport} from "src/lib/common/TokenSupport.sol";
import {WithdrawalDelay} from "src/lib/wallet/WithdrawalDelay.sol";
import {IERC1155Balance} from "src/interfaces/IERC1155Balance.sol";

/// @title Balances
///
/// Manages balances for the SpendWallet contract
contract Balances is TokenSupport, WithdrawalDelay, IERC1155Balance {
    /// The various balances that are tracked, used for the ERC-1155 balance functions
    enum BalanceType {
        Total,
        Spendable,
        Withdrawing,
        Withdrawable
    }

    /// The total balance of a depositor for a token. This will always be equal to the sum of `spendableBalance` and
    /// `withdrawingBalance`.
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function totalBalance(address token, address depositor) public view returns (uint256) {
        BalancesStorage.Data storage balances$ = BalancesStorage.get();
        return balances$.spendableBalances[token][depositor] + balances$.withdrawingBalances[token][depositor];
    }

    /// The balance that is spendable by the depositor, subject to deposits having been observed by the API in a
    /// finalized block and no spend authorizations having been issued but not yet burned by the operator or used on the
    /// same chain
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function spendableBalance(address token, address depositor) public view returns (uint256) {
        return BalancesStorage.get().spendableBalances[token][depositor];
    }

    /// The balance that is in the process of being withdrawn
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function withdrawingBalance(address token, address depositor) public view tokenSupported(token) returns (uint256) {
        return BalancesStorage.get().withdrawingBalances[token][depositor];
    }

    /// The balance that is withdrawable as of the current block. This will either be 0 or `withdrawingBalance`.
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
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

    /// Emitted when the ERC-1155 `balanceOf` function is called with an invalid `BalanceType`
    error InvalidBalanceType(uint96 balanceType);

    /// The balance of a depositor for a particular balance specifier, compatible with ERC-1155
    ///
    /// @dev The token `id` should be encoded as `uint256(abi.encodePacked(uint12(BALANCE_TYPE), address(token)))`,
    ///      where `BALANCE_TYPE` is 0 for total, 1 for spendable, 2 for withdrawing, and 3 for withdrawable.
    ///
    /// @param depositor   The depositor of the requested balance
    /// @param id          The packed token and balance id specifier
    function balanceOf(address depositor, uint256 id) public view override returns (uint256) {
        // Verify token is supported
        address token = address(uint160(id));
        if (!isTokenSupported(token)) {
            revert UnsupportedToken(token);
        }

        // Verify balance type is valid
        uint96 balanceType = uint96(id >> 160);
        if (balanceType > uint96(type(BalanceType).max)) {
            revert InvalidBalanceType(balanceType);
        }

        if (BalanceType(balanceType) == BalanceType.Total) return totalBalance(token, depositor);
        if (BalanceType(balanceType) == BalanceType.Spendable) return spendableBalance(token, depositor);
        if (BalanceType(balanceType) == BalanceType.Withdrawing) return withdrawingBalance(token, depositor);
        if (BalanceType(balanceType) == BalanceType.Withdrawable) return withdrawableBalance(token, depositor);

        return 0;
    }

    /// Emitted when the ERC-1155 `balanceOfBatch` function is called with arrays of different lengths
    error InputArrayLengthMismatch();

    /// The batch version of `balanceOf`, compatible with ERC-1155
    ///
    /// @dev `depositors` and `ids` must be the same length
    /// @dev The token `id` should be encoded as `uint256(abi.encodePacked(uint12(BALANCE_TYPE), address(token)))`,
    ///      where `BALANCE_TYPE` is 0 for total, 1 for spendable, 2 for withdrawing, and 3 for withdrawable.
    ///
    /// @param depositors   The depositor of the requested balance
    /// @param ids          The packed token and balance id specifier
    function balanceOfBatch(address[] calldata depositors, uint256[] memory ids)
        external
        view
        override
        returns (uint256[] memory)
    {
        if (depositors.length != ids.length) {
            revert InputArrayLengthMismatch();
        }

        uint256[] memory batchBalances = new uint256[](depositors.length);
        for (uint256 i = 0; i < depositors.length; i++) {
            batchBalances[i] = balanceOf(depositors[i], ids[i]);
        }

        return batchBalances;
    }
}

/// Implements the EIP-7201 storage pattern for the Balances module
library BalancesStorage {
    /// @custom:storage-location 7201:circle.gateway.Balances
    struct Data {
        /// The balances that have been deposited and are available for spending (after finalization)
        mapping(address token => mapping(address depositor => uint256 value)) spendableBalances;
        /// The balances that are in the process of being withdrawn and are no longer spendable
        mapping(address token => mapping(address depositor => uint256 value)) withdrawingBalances;
    }
    // Storage variables will be added here

    /// keccak256(abi.encode(uint256(keccak256("circle.gateway.Balances")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant SLOT = 0xdd3dca88e892815d13ea80f1982e32e4fe3d0a89f03d14d3565bf56d58c31a00;

    /// EIP-7201 getter for the storage slot
    function get() internal pure returns (Data storage $) {
        assembly {
            $.slot := SLOT
        }
    }
}
