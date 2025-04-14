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

import {Pausing} from "src/lib/common/Pausing.sol";
import {Rejection} from "src/lib/common/Rejection.sol";
import {TokenSupport} from "src/lib/common/TokenSupport.sol";
import {_checkNotZeroAddress} from "src/lib/util/addresses.sol";

/// @title Delegation
///
/// Manages delegation for the SpendWallet contract
contract Delegation is Pausing, Rejection, TokenSupport {
    error NotAuthorized();
    error CannotDelegateToSelf();

    /// Emitted when a delegate is authorized for a depositor's balance
    ///
    /// @param token       The token that the delegate is now authorized for
    /// @param depositor   The depositor who added the delegate
    /// @param delegate    The delegate that was added
    event DelegateAdded(address indexed token, address indexed depositor, address delegate);

    /// Allow `delegate` to withdraw and transfer the caller's `token` balance
    ///
    /// @dev This acts as a full allowance for `delegate` on the `token` balance of `msg.sender`
    ///
    /// @param token      The token that `delegate` should be authorized for
    /// @param delegate   The address being authorized
    function addDelegate(address token, address delegate)
        external
        whenNotPaused
        notRejected(msg.sender)
        notRejected(delegate)
        tokenSupported(token)
    {
        _checkNotZeroAddress(delegate);

        if (delegate == msg.sender) {
            revert CannotDelegateToSelf();
        }

        DelegationStorage.get().authorizedDelegates[token][msg.sender][delegate] = true;
        emit DelegateAdded(token, msg.sender, delegate);
    }

    /// Emitted when a delegate's authorization is revoked
    ///
    /// @param token       The token the delegate is no longer authorized for
    /// @param depositor   The depositor who removed the delegate
    /// @param delegate    The delegate that was removed
    event DelegateRemoved(address indexed token, address indexed depositor, address delegate);

    /// Stop allowing `delegate` to withdraw or transfer the caller's `token` balance. This revokation is not respected
    /// for burn authorizations that have been signed, so that burns cannot be prevented by removing the delegate
    ///
    /// @dev This revokes the allowance granted by `addDelegate`
    ///
    /// @param token      The token the delegate should no longer be authorized for
    /// @param delegate   The address that should no longer be authorized
    function removeDelegate(address token, address delegate)
        external
        whenNotPaused
        notRejected(msg.sender)
        tokenSupported(token)
    {
        _checkNotZeroAddress(delegate);

        DelegationStorage.get().authorizedDelegates[token][msg.sender][delegate] = false;
        emit DelegateRemoved(token, msg.sender, delegate);
    }

    /// Check if an address is authorized to withdraw and transfer tokens on behalf of a depositor
    ///
    /// @param token       The token to check
    /// @param depositor   The depositor to check
    /// @param addr        The address to check
    function isAuthorizedForBalance(address token, address depositor, address addr) public view returns (bool) {
        if (addr == depositor) return true;

        return DelegationStorage.get().authorizedDelegates[token][depositor][addr];
    }
}

/// Implements the EIP-7201 storage pattern for the Delegation module
library DelegationStorage {
    /// @custom:storage-location 7201:circle.gateway.Delegation
    struct Data {
        /// The addresses that are authorized to withdraw and transfer the balances of other depositors for a given token
        mapping(address token => mapping(address depositor => mapping(address delegate => bool isAuthorized)))
            authorizedDelegates;
    }

    /// keccak256(abi.encode(uint256(keccak256("circle.gateway.Delegation")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant SLOT = 0xbcbbce9c37b75586602042f686570dadc3d32ddb14a687daffcfefad2ac57b00;

    /// EIP-7201 getter for the storage slot
    function get() internal pure returns (Data storage $) {
        assembly {
            $.slot := SLOT
        }
    }
}
