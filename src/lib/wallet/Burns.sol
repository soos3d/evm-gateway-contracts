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

import {BurnAuthorization, BurnAuthorizationSet} from "src/lib/authorizations/BurnAuthorizations.sol";
import {_checkNotZeroAddress} from "src/lib/util/addresses.sol";
import {BurnLib} from "src/lib/wallet/BurnLib.sol";
import {SpendCommon} from "src/SpendCommon.sol";
import {Delegation} from "src/lib/wallet/Delegation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {TransferSpecLib} from "src/lib/authorizations/TransferSpecLib.sol";
import {BurnAuthorizationLib} from "src/lib/authorizations/BurnAuthorizationLib.sol";
import {AuthorizationCursor} from "src/lib/authorizations/AuthorizationCursor.sol";
import {_bytes32ToAddress} from "src/lib/util/addresses.sol";


/// @title Burns
///
/// Manages burns for the SpendWallet contract
contract Burns is SpendCommon, Delegation {
    using MessageHashUtils for bytes32;
    using TransferSpecLib for bytes29;
    using BurnAuthorizationLib for bytes29;
    using BurnAuthorizationLib for AuthorizationCursor;

    /// Returns the byte encoding of a single burn authorization
    ///
    /// @param authorization   The burn authorization to encode
    function encodeBurnAuthorization(BurnAuthorization memory authorization) external pure returns (bytes memory) {
        return BurnAuthorizationLib.encodeBurnAuthorization(authorization);
    }

    /// Returns the byte encoding of a set of burn authorizations
    ///
    /// @dev The burn authorizations must be sorted by domain
    ///
    /// @param authorizations   The burn authorizations to encode
    function encodeBurnAuthorizations(BurnAuthorization[] memory authorizations) external pure returns (bytes memory) {
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: authorizations});
        return BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);
    }

    /// Allows anyone to validate whether a set of burn authorizations is valid along with a signature from the
    /// depositor or an authorized delegate
    ///
    /// @dev Returns true if the authorizations and signature are valid
    /// @dev See the docs for `BurnAuthorization` for encoding details
    ///
    /// @param authorization   A byte-encoded (set of) burn authorization(s)
    /// @param signature       The signature from the depositor or authorized delegate
    function validateBurnAuthorizations(bytes memory authorization, bytes calldata signature)
        external
        view
        returns (bool)
    {
        address token;
        address recoveredSigner = BurnLib._recoverAuthorizationSigner(authorization, signature);
        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(authorization);

        uint32 index = 0;
        while (!cursor.done) {
            bytes29 auth = cursor.next();
            bytes29 spec = auth.getTransferSpec();

            // Validate that everything about the burn authorization is as expected, and skip if it's not for this domain
            bool relevant = BurnLib._validateBurnAuthorization(auth, recoveredSigner, 0, index);
            if (!relevant) {
                return false;
            }

            // Ensure that each one we've seen so far is for the same token
            address _token = _bytes32ToAddress(spec.getSourceToken());
            if (token != address(0)) {
                if (_token != token) {
                    revert BurnLib.NotAllSameToken();
                }
            } else {
                token = _token;
            }

            index++;
        }

        return true;
    }

    /// Debit the depositor's balance and burn the tokens after a spend was authorized
    ///
    /// @dev `authorizations`, `signatures`, and `fees` must all be the same length
    /// @dev Will revert if `destinationDomain` is the same as `sourceDomain` (since no burn is required)
    /// @dev For a set of burn authorizations, authorizations from other domains are ignored. The whole set is still
    ///      needed to verify the signature.
    /// @dev See `lib/authorizations/BurnAuthorizations.sol` for encoding details
    ///
    /// @param authorizations    An array of byte-encoded burn authorizations
    /// @param signatures        One signature from the authorizer of each burn authorization (set)
    /// @param fees              The fees to be collected for each burn. Fees for burns on other domains are ignored and
    ///                          may be passed as zero. Each fee must be no more than `maxFee` of the corresponding burn
    ///                          authorization.
    /// @param burnerSignature   A signature from `burnSigner` on the abi-encoded first three arguments
    function burnSpent(
        bytes[] calldata authorizations,
        bytes[] calldata signatures,
        uint256[][] calldata fees,
        bytes calldata burnerSignature
    ) external whenNotPaused {
        BurnLib.burnSpent(authorizations, signatures, fees, burnerSignature);
    }

    /// Debits the depositor's balance like `burnSpent`, but transfers funds instead of burning them. Used when a spend
    /// happens on the same chain to avoid burning and minting. No fee is charged.
    ///
    /// @dev The caller of this method must be the `minterContract`
    /// @dev The source and destination domains must both be this contract's domain (enforced by `minterContract`)
    /// @dev See the docs for `SpendAuthorization` for encoding details
    ///
    /// @param token                The token address being transferred
    /// @param depositor            The address of the owner of the funds within the wallet
    /// @param recipient            The address receiving the funds
    /// @param authorizer           The address that authorized the spend
    /// @param value                The amount of tokens transferred
    /// @param spendHash            The keccak256 hash of the SpendSpec
    /// @param spendAuthorization   The byte-encoded SpendAuthorization or SpendAuthorizationSet
    function sameChainSpend(
        address token,
        address depositor,
        address recipient,
        address authorizer,
        uint256 value,
        bytes32 spendHash,
        bytes memory spendAuthorization
    )
        external
        whenNotPaused
        onlyCounterpart
        tokenSupported(token)
        notDenylisted(depositor)
        notDenylisted(authorizer)
        authorizedForBalance(token, depositor, authorizer)
    {
        BurnLib.sameChainSpend(token, depositor, recipient, authorizer, value, spendHash, spendAuthorization);
    }

    /// The address that may sign the calldata for burning tokens that have been spent
    function burnSigner() public view returns (address) {
        return BurnsStorage.get().burnSigner;
    }

    /// Emitted when the burnSigner role is updated
    ///
    /// @param oldBurnSigner   The previous burn signer address
    /// @param newBurnSigner   The new burn signer address
    event BurnSignerUpdated(address oldBurnSigner, address newBurnSigner);

    /// Sets the address that may call `burnSpent`
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newBurnSigner   The new burn caller address
    function updateBurnSigner(address newBurnSigner) external onlyOwner {
        _checkNotZeroAddress(newBurnSigner);

        BurnsStorage.Data storage burns$ = BurnsStorage.get();
        address oldBurnSigner = burns$.burnSigner;
        burns$.burnSigner = newBurnSigner;
        emit BurnSignerUpdated(oldBurnSigner, newBurnSigner);
    }

    /// The address that will receive the onchain fee for burns
    function feeRecipient() public view returns (address) {
        return BurnsStorage.get().feeRecipient;
    }

    /// Emitted when the feeRecipient role is updated
    ///
    /// @param oldFeeRecipient   The previous fee recipient address
    /// @param newFeeRecipient   The new fee recipient address
    event FeeRecipientUpdated(address oldFeeRecipient, address newFeeRecipient);

    /// Sets the address that will receive the fee for burns
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newFeeRecipient   The new fee recipient address
    function updateFeeRecipient(address newFeeRecipient) external onlyOwner {
        _checkNotZeroAddress(newFeeRecipient);

        BurnsStorage.Data storage burns$ = BurnsStorage.get();
        address oldFeeRecipient = burns$.feeRecipient;
        burns$.feeRecipient = newFeeRecipient;
        emit FeeRecipientUpdated(oldFeeRecipient, newFeeRecipient);
    }
}

/// Implements the EIP-7201 storage pattern for the Burns module
library BurnsStorage {
    /// @custom:storage-location 7201:circle.gateway.Burns
    struct Data {
        /// The address that may sign the calldata for burning tokens that have been spent
        address burnSigner;
        /// The address that will receive the onchain fee for burns
        address feeRecipient;
    }

    /// keccak256(abi.encode(uint256(keccak256("circle.gateway.Burns")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant SLOT = 0x931ec06eaaa2cd8a002032d3364041b052af597aa8c169fcc20c959a9f557100;

    /// EIP-7201 getter for the storage slot
    function get() internal pure returns (Data storage $) {
        assembly {
            $.slot := SLOT
        }
    }
}