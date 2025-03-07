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

import {BurnAuthorization} from "src/lib/Authorizations.sol";
import {IERC1155Balance} from "src/interfaces/IERC1155Balance.sol";

/// Read-only methods for the SpendWallet contract that are callable by anyone
interface ISpendWalletRead is IERC1155Balance {
    /// Whether or not a token is supported
    ///
    /// @param token   The token to check
    function isTokenSupported(address token) external view returns (bool);

    /// The total balance of a depositor for a token. This will always be equal to the sum of `spendableBalance` and
    /// `withdrawingBalance`.
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function totalBalance(address token, address depositor) external view returns (uint256);

    /// The balance that is spendable by the depositor, subject to deposits having been observed by the API in a
    /// finalized block and no spend authorizations having been issued but not yet burned by the operator or used on the
    /// same chain
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function spendableBalance(address token, address depositor) external view returns (uint256);

    /// The balance that is in the process of being withdrawn
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function withdrawingBalance(address token, address depositor) external view returns (uint256);

    /// The balance that is withdrawable as of the current block. This will either be 0 or `withdrawingBalance`.
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function withdrawableBalance(address token, address depositor) external view returns (uint256);

    /// The balance of a depositor for a particular balance specifier, compatible with ERC-1155
    ///
    /// @dev The token `id` should be encoded as `uint256(abi.encodePacked(uint12(BALANCE_TYPE), address(token)))`,
    ///      where `BALANCE_TYPE` is 0 for total, 1 for spendable, 2 for withdrawing, and 3 for withdrawable.
    ///
    /// @param depositor   The depositor of the requested balance
    /// @param id          The packed token and balance id specifier
    function balanceOf(address depositor, uint256 id) external view override returns (uint256);

    /// The batch version of `balanceOf`, compatible with ERC-1155
    ///
    /// @dev `depositors` and `ids` must be the same length
    /// @dev The token `id` should be encoded as `uint256(abi.encodePacked(uint12(BALANCE_TYPE), address(token)))`,
    ///      where `BALANCE_TYPE` is 0 for total, 1 for spendable, 2 for withdrawing, and 3 for withdrawable.
    ///
    /// @param depositors   The depositor of the requested balance
    /// @param ids          The packed token and balance id specifier
    function balanceOfBatch(address[] memory depositors, uint256[] memory ids)
        external
        view
        override
        returns (uint256[] memory);

    /// The block height at which an in-progress withdrawal is withdrawable
    ///
    /// @dev Returns 0 if there is no in-progress withdrawal
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function withdrawalBlock(address token, address depositor) external view returns (uint256);

    /// Returns the byte encoding of a single burn authorization
    ///
    /// @param authorization   The burn authorization to encode
    function encodeBurnAuthorization(BurnAuthorization memory authorization) external pure returns (bytes memory);

    /// Returns the byte encoding of a set of burn authorizations
    ///
    /// @dev The burn authorizations must be sorted by domain
    ///
    /// @param authorizations   The burn authorizations to encode
    function encodeBurnAuthorization(BurnAuthorization[] memory authorizations) external pure returns (bytes memory);

    /// Allows anyone to validate whether a set of burn authorizations is valid along with a signature from the
    /// depositor or an authorized spender
    ///
    /// @dev Returns true if the authorizations and signature are valid
    /// @dev See the docs for `BurnAuthorization` for encoding details
    ///
    /// @param authorizations   A byte-encoded (set of) burn authorization(s)
    /// @param signature        The signature from the spender
    function validateBurnAuthorizations(bytes memory authorizations, bytes memory signature)
        external
        view
        returns (bool);
}
