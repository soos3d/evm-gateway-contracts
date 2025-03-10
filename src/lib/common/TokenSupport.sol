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

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

/// @title TokenSupport
///
/// Manages a set of tokens that are supported, and allows the owner to mark new tokens as supported
contract TokenSupport is Ownable2StepUpgradeable {
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // EIP-7201 Storage

    /// @custom:storage-location 7201:circle.spend.TokenSupport
    struct TokenSupportStorage {
        /// Whether or not a token is supported
        mapping(address token => bool supported) supportedTokens;
    }

    /// keccak256(abi.encode(uint256(keccak256("circle.spend.TokenSupport")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TOKEN_SUPPORT_STORAGE_SLOT =
        0x9504c81a957a40d134f71d3a6c01e888064674c3f380b2ffd4aefef7040d4300;

    function _getTokenSupportStorage() private pure returns (TokenSupportStorage storage $) {
        assembly {
            $.slot := TOKEN_SUPPORT_STORAGE_SLOT
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /// Emitted when a token is added to the set of supported tokens
    ///
    /// @param token   The token that is now supported
    event TokenSupported(address token);

    /// Thrown when an unsupported token is used
    ///
    /// @param token   The unsupported token
    error UnsupportedToken(address token);

    /// Ensures that the given token is supported
    ///
    /// @param token   The token to check
    modifier tokenSupported(address token) {
        _ensureTokenSupported(token);
        _;
    }

    /// Reverts if the given token is not supported
    ///
    /// @param token   The token to check
    function _ensureTokenSupported(address token) private view {
        if (!_getTokenSupportStorage().supportedTokens[token]) {
            revert UnsupportedToken(token);
        }
    }

    /// Whether or not a token is supported
    ///
    /// @param token   The token to check
    function isTokenSupported(address token) external view returns (bool) {
        return _getTokenSupportStorage().supportedTokens[token];
    }

    /// Marks a token as supported. Once supported, tokens can not be un-supported.
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param token   The token to be added
    function addSupportedToken(address token) external onlyOwner {
        _getTokenSupportStorage().supportedTokens[token] = true;
        emit TokenSupported(token);
    }
}
