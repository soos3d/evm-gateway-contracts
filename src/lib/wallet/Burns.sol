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
import {SpendCommon} from "src/SpendCommon.sol";
import {Balances} from "src/lib/wallet/Balances.sol";
import {Delegation} from "src/lib/wallet/Delegation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {TransferSpecLib} from "src/lib/authorizations/TransferSpecLib.sol";
import {BurnAuthorizationLib} from "src/lib/authorizations/BurnAuthorizationLib.sol";
import {AuthorizationCursor} from "src/lib/authorizations/AuthorizationCursor.sol";
import {_bytes32ToAddress} from "src/lib/util/addresses.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IBurnToken} from "src/interfaces/IBurnToken.sol";

/// @title Burns
///
/// Manages burns for the SpendWallet contract
contract Burns is SpendCommon, Balances, Delegation {
    using MessageHashUtils for bytes32;
    using TransferSpecLib for bytes29;
    using BurnAuthorizationLib for bytes29;
    using BurnAuthorizationLib for AuthorizationCursor;
    using SafeERC20 for IERC20;

    error InvalidBurnSigner();
    error MismatchedBurn();
    error MustHaveAtLeastOneBurnAuthorization();
    error InsufficientBalanceForSameChainSpend();
    error NotAllSameToken();
    error NoRelevantBurnAuthorizations();
    error AuthorizationValueMustBePositiveAtIndex(uint32 index);
    error AuthorizationExpiredAtIndex(uint32 index, uint256 maxBlockHeight, uint256 currentBlock);
    error InvalidAuthorizationSourceSignerAtIndex(uint32 index, address expectedSigner, address actualSigner);
    error InvalidAuthorizationSourceContractAtIndex(uint32 index, address expectedSourceContract);
    error UnsupportedTokenAtIndex(uint32 index, address sourceToken);
    error BurnFeeTooHighAtIndex(uint32 index, uint256 maxFee, uint256 actualFee);

    /// Emitted when the operator burns tokens that have been spent on another domain
    ///
    /// @param token                  The token that was spent
    /// @param depositor              The depositor who owned the spent balance
    /// @param spendHash              The keccak256 hash of the `TransferSpec`
    /// @param destinationDomain      The domain the spend was used on
    /// @param destinationRecipient   The recipient of the funds at the destination
    /// @param signer                 The address that authorized the transfer
    /// @param value                  The value that was spent
    /// @param fee                    The fee charged for the burn
    /// @param fromSpendable          The value burnt from the `spendable` balance
    /// @param fromWithdrawing        The value burnt from the `withdrawing` balance
    event BurnedSpent(
        address indexed token,
        address indexed depositor,
        bytes32 indexed spendHash,
        uint32 destinationDomain,
        bytes32 destinationRecipient,
        address signer,
        uint256 value,
        uint256 fee,
        uint256 fromSpendable,
        uint256 fromWithdrawing
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
    /// @param signatures        One signature for each burn authorization (set)
    /// @param fees              The fees to be collected for each burn. Fees for burns on other domains are ignored and
    ///                          may be passed as zero. Each fee must be no more than `maxFee` of the corresponding burn
    ///                          authorization.
    /// @param burnerSignature   A signature from `burnSigner` on the abi-encoded first three arguments
    function burnSpent(
        bytes[] memory authorizations,
        bytes[] memory signatures,
        uint256[][] memory fees,
        bytes memory burnerSignature
    ) external whenNotPaused {
        if (authorizations.length == 0) {
            revert MustHaveAtLeastOneBurnAuthorization();
        }

        if (signatures.length != authorizations.length || fees.length != authorizations.length) {
            revert MismatchedBurn();
        }

        _verifyBurnerSignature(burnerSignature);

        for (uint256 i = 0; i < authorizations.length; i++) {
            _validateAndProcessAuthorizationPayload(authorizations[i], signatures[i], fees[i]);
        }
    }

    /// Emitted when a spend authorization is used on the same chain as its source, resulting in a same-chain spend that
    /// transfers funds to the recipient instead of minting and burning them
    ///
    /// @param token             The token that was spent
    /// @param depositor         The depositor who owned the spent balance
    /// @param spendHash         The keccak256 hash of the `TransferSpec`
    /// @param recipient         The recipient of the funds
    /// @param signer            The address that authorized the transfer
    /// @param value             The value transferred to the recipient
    /// @param fromSpendable     The value transferred from the `spendable` balance
    /// @param fromWithdrawing   The value transferred from the `withdrawing` balance
    event TransferredSpent(
        address indexed token,
        address indexed depositor,
        bytes32 indexed spendHash,
        address recipient,
        address signer,
        uint256 value,
        uint256 fromSpendable,
        uint256 fromWithdrawing
    );

    /// @notice Transfers funds between accounts on the same chain after a spend authorization
    /// @dev The caller must be the `minterContract`
    /// @dev Source and destination domains must match this contract's domain (enforced by `minterContract`)
    /// @dev No fee is charged for same-chain transfers
    /// @dev See {SpendAuthorization} for authorization encoding details
    /// @param token The token being transferred
    /// @param depositor The owner of the funds in the wallet
    /// @param spendHash The keccak256 hash of the SpendSpec
    /// @param recipient The recipient of the transfer
    /// @param signer The address that authorized the spend
    /// @param value The transfer amount
    function sameChainSpend(
        address token,
        address depositor,
        address recipient,
        address signer,
        uint256 value,
        bytes32 spendHash
    )
        external
        whenNotPaused
        onlyCounterpart
        tokenSupported(token)
        notDenylisted(depositor)
        notDenylisted(signer)
        authorizedForBalance(token, depositor, signer)
    {
        _sameChainSpend(token, depositor, recipient, signer, value, spendHash);
    }

    /// Internal implementation of `sameChainSpend`
    function _sameChainSpend(
        address token,
        address depositor,
        address recipient,
        address signer,
        uint256 value,
        bytes32 spendHash
    ) internal {
        (uint256 fromSpendable, uint256 fromWithdrawing) = _reduceBalance(token, depositor, value);

        if (fromSpendable + fromWithdrawing != value) {
            revert InsufficientBalanceForSameChainSpend();
        }

        IERC20(token).safeTransfer(recipient, value);

        emit TransferredSpent(token, depositor, spendHash, recipient, signer, value, fromSpendable, fromWithdrawing);
    }

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
        address recoveredSigner = _recoverAuthorizationSigner(authorization, signature);
        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(authorization);

        uint32 index = 0;
        while (!cursor.done) {
            index = cursor.index;

            bytes29 auth = cursor.next();
            bytes29 spec = auth.getTransferSpec();

            // Validate that everything about the burn authorization is as expected, and skip if it's not for this domain
            bool relevant = _validateBurnAuthorization(auth, recoveredSigner, 0, index);
            if (!relevant) {
                continue;
            }

            // Ensure that each one we've seen so far is for the same token
            address _token = _bytes32ToAddress(spec.getSourceToken());
            if (token != address(0)) {
                if (_token != token) {
                    revert NotAllSameToken();
                }
            } else {
                token = _token;
            }
        }

        return true;
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

        BurnsStorage.Data storage $ = BurnsStorage.get();
        address oldBurnSigner = $.burnSigner;
        $.burnSigner = newBurnSigner;
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

        BurnsStorage.Data storage $ = BurnsStorage.get();
        address oldFeeRecipient = $.feeRecipient;
        $.feeRecipient = newFeeRecipient;
        emit FeeRecipientUpdated(oldFeeRecipient, newFeeRecipient);
    }

    /**
     * @notice Validates a single authorization or authorization set, recovers the signer, and processes all relevant burns.
     * @param authorization The byte-encoded set of authorizations (potentially containing multiple individual auths).
     * @param signature The ECDSA signature over the `keccak256` hash of `authorization`.
     * @param fees An array containing the fee proposed for each individual authorization within the set. Must match
     *             the number of authorizations encoded in `authorization`.
     */
    function _validateAndProcessAuthorizationPayload(
        bytes memory authorization,
        bytes memory signature,
        uint256[] memory fees
    ) internal {
        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(authorization);
        if (cursor.numAuths == 0) {
            revert MustHaveAtLeastOneBurnAuthorization();
        }

        if (fees.length != cursor.numAuths) {
            revert MismatchedBurn();
        }

        address signer = _recoverAuthorizationSigner(authorization, signature);
        _processAuthorizationsAndBurn(cursor, signer, fees);
    }

    /**
     * @notice Iterates through a set of burn authorizations, validates and processes relevant ones.
     * @param cursor An initialized `AuthorizationCursor` pointing to the start of the authorization set.
     * @param signer The address recovered from the signature covering the entire authorization set.
     * @param fees An array containing the fee proposed for each individual authorization.
     */
    function _processAuthorizationsAndBurn(AuthorizationCursor memory cursor, address signer, uint256[] memory fees)
        internal
    {
        address token;
        uint256 totalFee = 0;
        uint256 totalDeductedAmount = 0;
        bytes29 auth;
        uint32 index = 0;

        while (!cursor.done) {
            index = cursor.index; // cursor.next() increments index

            // Get the next burn authorization and extract its transfer spec
            auth = cursor.next();
            bytes29 spec = auth.getTransferSpec();

            // Validate that everything about the burn authorization is as expected, and skip if it's not for this domain
            bool relevant = _validateBurnAuthorization(auth, signer, fees[index], index);
            if (!relevant) {
                continue;
            }

            // Ensure that each one we've seen so far is for the same token
            address _token = _bytes32ToAddress(spec.getSourceToken());
            if (token != address(0)) {
                if (_token != token) {
                    revert NotAllSameToken();
                }
            } else {
                token = _token;
            }

            // Reduce the balance of the depositor(s) and add to the total fee and burn amount
            (uint256 deductedAmount, uint256 actualFeeCharged) =
                _applySingleBurnAuthorization(spec, signer, fees[index]);
            totalDeductedAmount += deductedAmount;
            totalFee += actualFeeCharged;
        }

        if (totalDeductedAmount == 0) {
            revert NoRelevantBurnAuthorizations();
        }

        // Collect the fee
        IERC20(token).safeTransfer(feeRecipient(), totalFee);

        // Burn everything else
        IBurnToken(token).burn(totalDeductedAmount - totalFee);
    }

    /**
     * @notice Processes a single valid burn authorization: marks the spend hash, reduces balance, and emits event.
     * @dev Assumes the associated `TransferSpec` (`spec`) has already been validated for relevance to the current
     *      domain and basic validity checks (e.g., non-zero value, expiry). It calculates the actual fee charged based
     *      on available balance after deducting the value.
     * @param spec The `TransferSpec` (`bytes29`) derived from the validated burn authorization.
     * @param signer The address that signed the authorization set containing this spec.
     * @param fee The fee requested for this specific burn operation.
     * @return deductedAmount The total amount actually deducted from the depositor's balances (value + actualFeeCharged).
     *                        May be less than `value + fee` if the depositor had insufficient balance.
     * @return actualFeeCharged The fee amount actually charged and collected. May be less than `fee` if the depositor
     *                          had insufficient balance to cover the full value and fee.
     */
    function _applySingleBurnAuthorization(bytes29 spec, address signer, uint256 fee)
        internal
        returns (uint256 deductedAmount, uint256 actualFeeCharged)
    {
        // Mark the spend hash as used
        _checkAndMarkSpendHash(spec.getHash());

        // Extract the relevant parameters from the TransferSpec
        address token = _bytes32ToAddress(spec.getSourceToken());
        address depositor = _bytes32ToAddress(spec.getSourceDepositor());
        uint256 value = spec.getValue();

        // Reduce the balances of the depositor by amount being burned + the fee, returning the overall amounts that were drawn from each balance type
        (uint256 fromSpendable, uint256 fromWithdrawing) = _reduceBalance(token, depositor, value + fee);

        deductedAmount = fromSpendable + fromWithdrawing;
        if (deductedAmount < value + fee) {
            emit InsufficientBalance(token, depositor, value + fee, fromSpendable, fromWithdrawing);
        }

        // If the full amount could not be deducted, we want to prioritize burning over taking the fee
        if (deductedAmount <= value) {
            actualFeeCharged = 0;
        } else {
            actualFeeCharged = deductedAmount - value;
        }

        // Emit an event with all the information about the burn
        emit BurnedSpent(
            token,
            depositor,
            spec.getHash(),
            spec.getDestinationDomain(),
            spec.getDestinationRecipient(),
            signer,
            deductedAmount - actualFeeCharged,
            actualFeeCharged,
            fromSpendable,
            fromWithdrawing
        );

        // Return the amount that was actually deducted and the actual fee charged
        return (deductedAmount, actualFeeCharged);
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

    /**
     * @notice Recovers the signer address from an ECDSA signature over the EIP-712 hash of authorization bytes.
     * @param authorizations The byte array representing the set of authorizations that were signed.
     * @param signature The 65-byte ECDSA signature (r, s, v).
     * @return address The address recovered from the signature. Returns address(0) if the signature is invalid.
     */
    function _recoverAuthorizationSigner(bytes memory authorizations, bytes memory signature)
        internal
        pure
        returns (address)
    {
        return ECDSA.recover(keccak256(authorizations).toEthSignedMessageHash(), signature);
    }

    /**
     * @notice Validates contents of a single burn authorization based on various criteria for the current chain context.
     * @dev Checks include: non-zero value, source domain match, expiry block, fee limit, source contract address,
     *      token support, and signer delegation.
     * @param auth The `bytes29` encoded burn authorization to validate.
     * @param signer The address recovered from the signature covering the entire authorization set.
     *                            This address must have been delegated authority for the specified balance.
     * @param fee The fee proposed for this specific burn authorization.
     * @param index The index of this authorization within the original array (used for detailed error messages).
     * @return relevant A boolean indicating if the authorization is for the current domain (`true`) or a different
     *                  domain (`false`). If `false`, the authorization should be skipped for processing on this chain.
     *                  Further validation checks are skipped if the domain doesn't match.
     */
    function _validateBurnAuthorization(bytes29 auth, address signer, uint256 fee, uint32 index)
        internal
        view
        returns (bool relevant)
    {
        bytes29 spec = auth.getTransferSpec();

        // If any burn authorizations are zero (even if they are for a different domain), refuse to continue so that
        // they all fail together across all source domains
        uint256 value = spec.getValue();
        if (value == 0) {
            revert AuthorizationValueMustBePositiveAtIndex(index);
        }

        // If the burn authorization is for a different domain, ignore futher checks and indicate that to the caller
        // so it can be skipped
        uint32 domain = spec.getSourceDomain();
        if (!_isCurrentDomain(domain)) {
            return false;
        }

        // If the burn authorization is created for a same chain spend, the burn should not be processed
        if (domain == spec.getDestinationDomain()) {
            return false;
        }

        // Ensure the burn authorization is not expired
        uint256 maxBlockHeight = auth.getMaxBlockHeight();
        if (maxBlockHeight < block.number) {
            revert AuthorizationExpiredAtIndex(index, maxBlockHeight, block.number);
        }

        // Ensure the fee is within the allowed range
        uint256 maxFee = auth.getMaxFee();
        if (maxFee < fee) {
            revert BurnFeeTooHighAtIndex(index, maxFee, fee);
        }

        // Ensure this is the correct source contract
        address sourceContract = _bytes32ToAddress(spec.getSourceContract());
        if (sourceContract != address(this)) {
            revert InvalidAuthorizationSourceContractAtIndex(index, sourceContract);
        }

        // Ensure that the source token is supported
        address sourceToken = _bytes32ToAddress(spec.getSourceToken());
        if (!isTokenSupported(sourceToken)) {
            revert UnsupportedTokenAtIndex(index, sourceToken);
        }

        // Ensure that the signer of the burn authorization matches what was provided in the TransferSpec
        address sourceSigner = _bytes32ToAddress(spec.getSourceSigner());
        if (sourceSigner != signer) {
            revert InvalidAuthorizationSourceSignerAtIndex(index, sourceSigner, signer);
        }

        // Ensure that the signer of the burn authorization is authorized for the balance being burned
        address sourceDepositor = _bytes32ToAddress(spec.getSourceDepositor());
        if (!_wasEverAuthorizedForBalance(sourceToken, sourceDepositor, signer)) {
            revert Delegation.NotAuthorized();
        }

        return true;
    }

    /// Emitted when the depositor did not have a sufficient balance to cover what needed to be burned. This should
    /// never happen under normal circumstances.
    ///
    /// @param token                The token being burned
    /// @param depositor            The depositor who owns the balance
    /// @param value                The amount that needed to be burned
    /// @param spendableBalance     The amount that was present in the spendable balance
    /// @param withdrawingBalance   The amount that was present in the withdrawing balance
    event InsufficientBalance(
        address indexed token,
        address indexed depositor,
        uint256 value,
        uint256 spendableBalance,
        uint256 withdrawingBalance
    );
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
