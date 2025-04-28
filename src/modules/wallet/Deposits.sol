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
import {IERC7597} from "src/interfaces/IERC7597.sol";
import {IERC7598} from "src/interfaces/IERC7598.sol";
import {Denylist} from "src/modules/common/Denylist.sol";
import {Pausing} from "src/modules/common/Pausing.sol";
import {TokenSupport} from "src/modules/common/TokenSupport.sol";
import {Balances} from "src/modules/wallet/Balances.sol";

/// @title Deposits
///
/// @notice Manages deposits for the `GatewayWallet` contract
contract Deposits is Pausing, Denylist, TokenSupport, Balances {
    using SafeERC20 for IERC20;

    /// Emitted when a deposit is made
    ///
    /// @param token       The token that was deposited
    /// @param depositor   The address that deposited the funds
    /// @param value       The amount that was deposited
    event Deposited(address indexed token, address indexed depositor, uint256 value);

    /// Thrown for attempted zero-value deposits
    error DepositValueMustBePositive();

    /// Deposit tokens after approving this contract for the token
    ///
    /// @dev The resulting balance in this contract belongs to `msg.sender`
    ///
    /// @param token   The token to deposit
    /// @param value   The amount to be deposited
    function deposit(address token, uint256 value)
        external
        whenNotPaused
        notDenylisted(msg.sender)
        tokenSupported(token)
    {
        // Ensure that the value is non-zero
        if (value == 0) {
            revert DepositValueMustBePositive();
        }

        // Increase the depositor's available balance
        address depositor = msg.sender;
        _increaseAvailableBalance(token, depositor, value);

        // Transfer the tokens from the depositor to this contract
        IERC20(token).safeTransferFrom(depositor, address(this), value);

        // Emit an event to signal the deposit
        emit Deposited(token, depositor, value);
    }

    /// Deposit tokens with an EIP-2612 permit
    ///
    /// @dev The resulting balance in this contract belongs to the `owner` specified in the permit
    /// @dev The permit's `spender` must be the address of this contract
    /// @dev The full permitted `value` is always deposited
    ///
    /// @param token      The token to deposit
    /// @param owner      The depositor's address
    /// @param value      The amount to be deposited
    /// @param deadline   The unix time at which the signature expires, or max `uint256` value to signal no expiration
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
    ) external whenNotPaused notDenylisted(msg.sender) notDenylisted(owner) tokenSupported(token) {
        _depositWithPermit(token, owner, value, deadline, abi.encodePacked(r, s, v));
    }

    /// Deposit tokens with an EIP-7597 permit, passing the signature as bytes to allow for SCA deposits
    ///
    /// @dev The resulting balance in this contract belongs to the `owner` specified in the permit
    /// @dev The permit's `spender` must be the address of this contract
    /// @dev The full permitted `value` is always deposited
    /// @dev EOA wallet signatures should be packed in the order of r, s, v
    ///
    /// @param token       The token to deposit
    /// @param owner       The depositor's address
    /// @param value       The amount to be deposited
    /// @param deadline    The unix time at which the signature expires, or max `uint256` value to signal no expiration
    /// @param signature   Signature bytes signed by an EOA wallet or a contract wallet
    function depositWithPermit(address token, address owner, uint256 value, uint256 deadline, bytes calldata signature)
        external
        whenNotPaused
        notDenylisted(msg.sender)
        notDenylisted(owner)
        tokenSupported(token)
    {
        _depositWithPermit(token, owner, value, deadline, signature);
    }

    /// Deposit tokens with an ERC-3009 authorization
    ///
    /// @dev The resulting balance in this contract belongs to the `from` specified in the authorization
    /// @dev The authorization's `to` must be the address of this contract
    /// @dev The transfer will be done via `receiveWithAuthorization`
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
    ) external whenNotPaused notDenylisted(msg.sender) notDenylisted(from) tokenSupported(token) {
        _depositWithAuthorization(token, from, value, validAfter, validBefore, nonce, abi.encodePacked(r, s, v));
    }

    /// Deposit tokens with an ERC-7598 authorization, passing the signature as bytes to allow for SCA deposits
    ///
    /// @dev The resulting balance in this contract belongs to the `from` specified in the authorization
    /// @dev The authorization's `to` must be the address of this contract
    /// @dev The transfer will be done via `receiveWithAuthorization`
    /// @dev EOA wallet signatures should be packed in the order of r, s, v
    ///
    /// @param token         The token to deposit
    /// @param from          The depositor's address
    /// @param value         The amount to be deposited
    /// @param validAfter    The time after which this is valid (unix time)
    /// @param validBefore   The time before which this is valid (unix time)
    /// @param nonce         Unique nonce
    /// @param signature     Signature bytes signed by an EOA wallet or a contract wallet
    function depositWithAuthorization(
        address token,
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external whenNotPaused notDenylisted(msg.sender) notDenylisted(from) tokenSupported(token) {
        _depositWithAuthorization(token, from, value, validAfter, validBefore, nonce, signature);
    }

    /// Internal implementation for depositing tokens using an EIP-2612 permit
    ///
    /// @param token       The address of a token that supports EIP-2612 permits
    /// @param owner       The address that owns the tokens and signed the permit
    /// @param value       The amount to deposit
    /// @param deadline    The unix timestamp after which the permit signature expires
    /// @param signature   The signature bytes containing v, r, s components
    function _depositWithPermit(address token, address owner, uint256 value, uint256 deadline, bytes memory signature)
        internal
    {
        // Ensure that the value is non-zero
        if (value == 0) {
            revert DepositValueMustBePositive();
        }

        // Increase the depositor's available balance
        address depositor = owner;
        _increaseAvailableBalance(token, depositor, value);

        // Execute the permit and transfer the tokens from the depositor to this contract
        IERC7597(token).permit(depositor, address(this), value, deadline, signature);
        IERC20(token).safeTransferFrom(depositor, address(this), value);

        // Emit an event to signal the deposit
        emit Deposited(token, owner, value);
    }

    /// @dev Internal implementation for depositing tokens using an ERC-7598 authorization
    ///
    /// @param token         The token to deposit
    /// @param from          The depositor's address
    /// @param value         The amount to be deposited
    /// @param validAfter    The time after which this is valid (unix time)
    /// @param validBefore   The time before which this is valid (unix time)
    /// @param nonce         Unique nonce
    /// @param signature     Signature bytes signed by an EOA wallet or a contract wallet
    function _depositWithAuthorization(
        address token,
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) internal {
        // Ensure that the value is non-zero
        if (value == 0) {
            revert DepositValueMustBePositive();
        }

        // Increase the depositor's available balance
        address depositor = from;
        _increaseAvailableBalance(token, depositor, value);

        // Execute the authorization to transfer the tokens from the depositor to this contract
        IERC7598(token).receiveWithAuthorization(
            depositor, address(this), value, validAfter, validBefore, nonce, signature
        );

        // Emit an event to signal the deposit
        emit Deposited(token, depositor, value);
    }
}
