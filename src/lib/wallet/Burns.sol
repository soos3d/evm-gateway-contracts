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
import {BurnAuthorization} from "src/lib/authorizations/BurnAuthorizations.sol";
import {_checkNotZeroAddress} from "src/lib/util/addresses.sol";
import {AuthorizationCursor} from "src/lib/authorizations/AuthorizationCursor.sol";
import {BurnAuthorizationLib} from "src/lib/authorizations/BurnAuthorizationLib.sol";
import {TransferSpecLib} from "src/lib/authorizations/TransferSpecLib.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title Burns
///
/// Manages burns for the SpendWallet contract
contract Burns is Ownable2StepUpgradeable, Pausing {
    using MessageHashUtils for bytes32;
    using TransferSpecLib for bytes29;
    using BurnAuthorizationLib for bytes29;

    error InvalidBurnSigner();
    error MismatchedBurn();

    /// Returns the byte encoding of a single burn authorization
    ///
    /// @param authorization   The burn authorization to encode
    function encodeBurnAuthorization(BurnAuthorization memory authorization) external pure returns (bytes memory) {}

    /// Returns the byte encoding of a set of burn authorizations
    ///
    /// @dev The burn authorizations must be sorted by domain
    ///
    /// @param authorizations   The burn authorizations to encode
    function encodeBurnAuthorizations(BurnAuthorization[] memory authorizations) external pure returns (bytes memory) {}

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
        pure
        returns (bool)
    {}

    /// Emitted when the operator burns tokens that have been spent on another domain
    ///
    /// @param token               The token that was spent
    /// @param depositor           The depositor who owned the spent balance
    /// @param spendHash           The keccak256 hash of the `SpendSpec`
    /// @param destinationDomain   The domain the spend was used on
    /// @param recipient           The recipient of the funds at the destination
    /// @param authorizer          The address that authorized the transfer
    /// @param value               The value that was spent
    /// @param fee                 The fee charged for the burn
    /// @param total               The total value burnt, including the fee
    /// @param fromSpendable       The value burnt from the `spendable` balance
    /// @param fromWithdrawing     The value burnt from the `withdrawing` balance
    /// @param burnAuthorization   The entire burn authorization that was used
    event BurnedSpent(
        address indexed token,
        address indexed depositor,
        bytes32 indexed spendHash,
        uint32 destinationDomain,
        bytes32 recipient,
        address authorizer,
        uint256 value,
        uint256 fee,
        uint256 total,
        uint256 fromSpendable,
        uint256 fromWithdrawing,
        bytes burnAuthorization
    );

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
        bytes[] memory authorizations,
        bytes[] memory signatures,
        uint256[][] memory fees,
        bytes memory burnerSignature
    ) external view whenNotPaused {
        _verifyBurnerSignature(burnerSignature);

        if (signatures.length != authorizations.length || fees.length != authorizations.length) {
            revert MismatchedBurn();
        }

        for (uint256 i = 0; i < authorizations.length; i++) {
            AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(authorizations[i]);
            while (!cursor.done) {
                // TODO
            }
        }
    }

    /// Internal function to verify the signature of the `burnSigner` on the other arguments in calldata, hashing the
    /// arguments from calldata rather than using abi.encode (which does a lot of copying and stack manipulation).
    ///
    /// @dev Must be called only from `burnSpent`, to ensure the calldata is as expected
    ///
    /// @param burnerSignature   The signature from the `burnSigner` to verify
    function _verifyBurnerSignature(bytes memory burnerSignature) internal view {
        // Ensure that the signature is the expected length, to correctly index into the calldata
        if (burnerSignature.length != 65) {
            revert InvalidBurnSigner();
        }

        // Isolate just the arguments that are signed in the calldata by slicing `msg.data`:
        //     - Skips over the beginning of the calldata to get to the first argument
        //         - 4 bytes for the function selector
        //         - 128 bytes for the 4 argument offsets
        //         - 4 + 128 = 132 = 0x84
        //     - Does not include the last argument (the signature itself)
        //         - We know it is 65 bytes (verified above), so takes up 128 (0x80) bytes
        //           (32 for the length, and 96 for the 32-byte-aligned contents)
        bytes memory calldataBytes = msg.data[0x84:msg.data.length - 0x80];

        // Verify the signature and revert if it's invalid
        address recoveredSigner = ECDSA.recover(keccak256(calldataBytes).toEthSignedMessageHash(), burnerSignature);
        if (recoveredSigner != BurnsStorage.get().burnSigner) {
            revert InvalidBurnSigner();
        }
    }

    /// Emitted when a spend authorization is used on the same chain as its source, resulting in a same-chain spend that
    /// transfers funds to the recipient instead of minting and burning them
    ///
    /// @param token                The token that was spent
    /// @param depositor            The depositor who owned the spent balance
    /// @param spendHash            The keccak256 hash of the SpendSpec
    /// @param recipient            The recipient of the funds
    /// @param authorizer           The address that authorized the transfer
    /// @param value                The value transferred to the recipient
    /// @param fromSpendable        The value transferred from the `spendable`
    ///                             balance
    /// @param fromWithdrawing      The value transferred from the `withdrawing`
    ///                             balance
    /// @param spendAuthorization   The entire spend authorization that was used
    event TransferredSpent(
        address indexed token,
        address indexed depositor,
        bytes32 indexed spendHash,
        bytes32 recipient,
        address authorizer,
        uint256 value,
        uint256 fromSpendable,
        uint256 fromWithdrawing,
        bytes spendAuthorization
    );

    /// Debits the depositor's balance like `burnSpent`, but transfers funds instead of burning them. Used when a spend
    /// happens on the same chain to avoid burning and minting. No fee is charged.
    ///
    /// @dev The caller of this method must be the `minterContract`
    /// @dev The source and destination domains must both be this contract's domain
    /// @dev See the docs for `SpendAuthorization` for encoding details
    ///
    /// @param authorization   The spend authorization that was passed to the minter contract
    /// @param signature       The signature from the operator
    function sameChainSpend(bytes memory authorization, bytes calldata signature) external whenNotPaused {}

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
