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

import {AddressLib} from "src/lib/AddressLib.sol";
import {Denylist} from "src/modules/common/Denylist.sol";
import {Pausing} from "src/modules/common/Pausing.sol";
import {TokenSupport} from "src/modules/common/TokenSupport.sol";

/// @title Authorization Status
///
/// @notice Represents the possible states of a delegate's authorization for a specific token and depositor.
enum AuthorizationStatus {
    /// The delegate has never been authorized
    Unauthorized,
    /// The delegate is currently authorized to act on behalf of the depositor for the token
    Authorized,
    /// The delegate was previously authorized, but the authorization has been revoked. This state is distinct from
    /// `Unauthorized` to handle specific scenarios like signed burn intents.
    Revoked
}

/// @title Delegation
///
/// @notice Manages delegation for the `GatewayWallet` contract
contract Delegation is Pausing, Denylist, TokenSupport {
    /// Emitted when a delegate is authorized for a depositor's balance
    ///
    /// @param token       The token that the delegate is now authorized for
    /// @param depositor   The depositor who added the delegate
    /// @param delegate    The delegate that was added
    event DelegateAdded(address indexed token, address indexed depositor, address delegate);

    /// Emitted when a delegate's authorization is revoked
    ///
    /// @param token       The token the delegate is no longer authorized for
    /// @param depositor   The depositor who removed the delegate
    /// @param delegate    The delegate that was removed
    event DelegateRemoved(address indexed token, address indexed depositor, address delegate);

    /// Thrown when a delegate is not authorized to act on behalf of a depositor
    error NotAuthorized();

    /// Thrown when attempting to authorize an address for itself
    error CannotDelegateToSelf();

    /// Reverts if an address is not authorized to withdraw and transfer tokens on behalf of the depositor
    ///
    /// @param token       The token to check
    /// @param depositor   The depositor to check
    /// @param addr        The address to check
    modifier authorizedForBalance(address token, address depositor, address addr) {
        if (!isAuthorizedForBalance(token, depositor, addr)) {
            revert NotAuthorized();
        }
        _;
    }

    /// Allow `delegate` to withdraw and transfer the caller's `token` balance
    ///
    /// @dev This acts as a full allowance for `delegate` on the `token` balance of `msg.sender`
    ///
    /// @param token      The token that `delegate` should be authorized for
    /// @param delegate   The address being authorized
    function addDelegate(address token, address delegate)
        external
        whenNotPaused
        notDenylisted(msg.sender)
        notDenylisted(delegate)
        tokenSupported(token)
    {
        // Ensure that the delegate is not the zero address
        AddressLib._checkNotZeroAddress(delegate);

        // Ensure that the delegate is not the caller
        if (delegate == msg.sender) {
            revert CannotDelegateToSelf();
        }

        // Store the authorization and emit an event
        DelegationStorage.get().authorizedDelegates[token][msg.sender][delegate] = AuthorizationStatus.Authorized;
        emit DelegateAdded(token, msg.sender, delegate);
    }

    /// Stop allowing `delegate` to withdraw or transfer the caller's `token` balance. This revocation is not respected
    /// for burn intents that have been signed, so that burns cannot be prevented by removing the delegate.
    ///
    /// @param token      The token the delegate should no longer be authorized for
    /// @param delegate   The address that should no longer be authorized
    function removeDelegate(address token, address delegate)
        external
        whenNotPaused
        notDenylisted(msg.sender)
        tokenSupported(token)
    {
        // Ensure that the delegate is not the zero address
        AddressLib._checkNotZeroAddress(delegate);

        // Check the existing authorization status
        DelegationStorage.Data storage $ = DelegationStorage.get();
        AuthorizationStatus existingStatus = $.authorizedDelegates[token][msg.sender][delegate];

        // If the address has never been authorized or is already revoked, take no action
        if (existingStatus == AuthorizationStatus.Unauthorized || existingStatus == AuthorizationStatus.Revoked) {
            return;
        }

        // Otherwise, mark the authorization as revoked and emit an event. The API will treat this the same as
        // `Unauthorized` for the purpose of issuing attestations, but the wallet contract will allow burn
        // intents signed by revoked delegates in order to prevent a front-running attack where an authorization
        // is revoked before the burn has a chance to happen.
        $.authorizedDelegates[token][msg.sender][delegate] = AuthorizationStatus.Revoked;
        emit DelegateRemoved(token, msg.sender, delegate);
    }

    /// Check if an address is authorized to withdraw and transfer tokens on behalf of a depositor
    ///
    /// @param token       The token to check
    /// @param depositor   The depositor to check
    /// @param addr        The address to check
    /// @return            `true` if the address is authorized, `false` otherwise
    function isAuthorizedForBalance(address token, address depositor, address addr) public view returns (bool) {
        // A depositor is always authorized for its own balance
        if (addr == depositor) return true;

        // Otherwise, check that the stored authorization status is `Authorized`
        AuthorizationStatus status = DelegationStorage.get().authorizedDelegates[token][depositor][addr];
        return status == AuthorizationStatus.Authorized;
    }

    /// Check if an address has ever been authorized to withdraw and transfer tokens on behalf of a depositor. This
    /// includes both currently-valid and revoked authorizations.
    ///
    /// @param token       The token to check
    /// @param depositor   The depositor to check
    /// @param addr        The address to check
    /// @return            `true` if the address has ever been authorized, `false` otherwise
    function _wasEverAuthorizedForBalance(address token, address depositor, address addr)
        internal
        view
        returns (bool)
    {
        // A depositor is always authorized for its own balance
        if (addr == depositor) return true;

        // Otherwise, check that the stored authorization status is either `Authorized` or `Revoked`
        AuthorizationStatus status = DelegationStorage.get().authorizedDelegates[token][depositor][addr];
        return status != AuthorizationStatus.Unauthorized;
    }
}

/// @title DelegationStorage
///
/// @notice Implements the EIP-7201 storage pattern for the `Delegation` module
library DelegationStorage {
    /// @custom:storage-location erc7201:circle.gateway.Delegation
    struct Data {
        /// The addresses that are authorized to withdraw and transfer the balances of other depositors for a given token
        mapping(address token => mapping(address depositor => mapping(address delegate => AuthorizationStatus status)))
            authorizedDelegates;
    }

    /// `keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Delegation"))) - 1)) & ~bytes32(uint256(0xff))`
    bytes32 public constant SLOT = 0xbcbbce9c37b75586602042f686570dadc3d32ddb14a687daffcfefad2ac57b00;

    /// EIP-7201 getter for the storage slot
    ///
    /// @return $   The storage struct for the `Delegation` module
    function get() internal pure returns (Data storage $) {
        assembly ("memory-safe") {
            $.slot := SLOT
        }
    }
}
