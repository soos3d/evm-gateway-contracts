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

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

/// @title TokenSupport
///
/// @notice Manages a set of tokens that are supported, and allows the owner to mark new tokens as supported
contract TokenSupport is Ownable2StepUpgradeable {
    /// Emitted when a token is added to the set of supported tokens
    ///
    /// @param token   The token that is now supported
    event TokenSupported(address token);

    /// Thrown when an unsupported token is used
    ///
    /// @param token   The unsupported token
    error UnsupportedToken(address token);

    /// Initializes supported tokens
    ///
    /// @param supportedTokens_   The initially-supported tokens
    function __TokenSupport_init(address[] calldata supportedTokens_) internal onlyInitializing {
        for (uint256 i = 0; i < supportedTokens_.length; i++) {
            addSupportedToken(supportedTokens_[i]);
        }
    }

    /// Ensures that the given token is supported
    ///
    /// @param token   The token to check
    modifier tokenSupported(address token) {
        _ensureTokenSupported(token);
        _;
    }

    /// Whether or not a token is supported
    ///
    /// @param token   The token to check
    /// @return        `true` if the token is supported, `false` otherwise
    function isTokenSupported(address token) public view returns (bool) {
        return TokenSupportStorage.get().supportedTokens[token];
    }

    /// Marks a token as supported. Once supported, tokens cannot be un-supported.
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param token   The token to be added
    function addSupportedToken(address token) public onlyOwner {
        TokenSupportStorage.get().supportedTokens[token] = true;
        emit TokenSupported(token);
    }

    /// Reverts if the given token is not supported
    ///
    /// @param token   The token to check
    function _ensureTokenSupported(address token) internal view {
        if (!isTokenSupported(token)) {
            revert UnsupportedToken(token);
        }
    }
}

/// @title TokenSupportStorage
///
/// @notice Implements the EIP-7201 storage pattern for the `TokenSupport` module
library TokenSupportStorage {
    /// @custom:storage-location 7201:circle.gateway.TokenSupport
    struct Data {
        /// Whether or not a token is supported
        mapping(address token => bool supported) supportedTokens;
    }

    /// `keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.TokenSupport"))) - 1)) & ~bytes32(uint256(0xff))`
    bytes32 public constant SLOT = 0x3ba16516a08fb9c5c48fb6662657ad4ffe1c779829969b4c7abdb9287bbf8500;

    /// EIP-7201 getter for the storage slot
    ///
    /// @return $   The storage struct for the `TokenSupport` module
    function get() internal pure returns (Data storage $) {
        assembly ("memory-safe") {
            $.slot := SLOT
        }
    }
}
