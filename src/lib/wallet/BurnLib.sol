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

import {BurnsStorage} from "src/lib/wallet/Burns.sol";
import {DelegationStorage} from "src/lib/wallet/Delegation.sol";
import {BalancesStorage} from "src/lib/wallet/Balances.sol";
import {SpendHashesStorage} from "src/lib/common/SpendHashes.sol";
import {DomainStorage} from "src/lib/common/Domain.sol";
import {TokenSupportStorage} from "src/lib/common/TokenSupport.sol";
import {AuthorizationCursor} from "src/lib/authorizations/AuthorizationCursor.sol";
import {BurnAuthorizationLib} from "src/lib/authorizations/BurnAuthorizationLib.sol";
import {TransferSpecLib} from "src/lib/authorizations/TransferSpecLib.sol";
import {_checkNotZeroAddress, _bytes32ToAddress} from "src/lib/util/addresses.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IBurnToken} from "src/interfaces/IBurnToken.sol";

/// Handles the implementation of burning, split out as an external library for bytecode size
library BurnLib {
    using MessageHashUtils for bytes32;
    using TransferSpecLib for bytes29;
    using BurnAuthorizationLib for bytes29;
    using BurnAuthorizationLib for AuthorizationCursor;
    using SafeERC20 for IERC20;

    error InvalidBurnSigner();
    error MismatchedBurn();
    error MustHaveAtLeastOneBurnAuthorization();
    error NoRelevantBurnAuthorizations();
    error AuthorizationExpired(uint32 index, uint256 maxBlockHeight, uint256 currentBlock);
    error BurnValueMustBePositive(uint32 index);
    error InvalidAuthorizationSourceContract(uint32 index, address expectedSourceContract);
    error NotAllSameToken();
    error UnsupportedToken(uint32 index, address sourceToken);
    error BurnFeeTooHigh(uint32 index, uint256 maxFee, uint256 actualFee);

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
    /// @param fromSpendable       The value burnt from the `spendable` balance
    /// @param fromWithdrawing     The value burnt from the `withdrawing` balance
    event BurnedSpent(
        address indexed token,
        address indexed depositor,
        bytes32 indexed spendHash,
        uint32 destinationDomain,
        bytes32 recipient,
        address authorizer,
        uint256 value,
        uint256 fee,
        uint256 fromSpendable,
        uint256 fromWithdrawing
    );

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
    ) external {
        if (authorizations.length == 0) {
            revert MustHaveAtLeastOneBurnAuthorization();
        }

        if (signatures.length != authorizations.length || fees.length != authorizations.length) {
            revert MismatchedBurn();
        }

        _verifyBurnerSignature(burnerSignature);

        for (uint256 i = 0; i < authorizations.length; i++) {
            _validateAndBurn(authorizations[i], signatures[i], fees[i]);
        }
    }

    function _validateAndBurn(bytes memory authorization, bytes memory signature, uint256[] memory fees) internal {
        AuthorizationCursor memory cursor = BurnAuthorizationLib.cursor(authorization);
        if (cursor.numAuths == 0) {
            revert MustHaveAtLeastOneBurnAuthorization();
        }

        if (fees.length != cursor.numAuths) {
            revert MismatchedBurn();
        }

        address authorizer = _recoverAuthorizationSigner(authorization, signature);
        _burnAll(cursor, authorizer, fees, BurnsStorage.get().feeRecipient);
    }

    /// Thrown when the burns relevant to this domain are not all for the same token
    error NotAllSameToken();

    function _burnAll(
        AuthorizationCursor memory cursor,
        address authorizer,
        uint256[] memory fees,
        address feeRecipient
    ) internal {
        address token;
        uint256 totalFee = 0;
        uint256 totalDeductedAmount = 0;
        bytes29 auth;
        uint32 index = 0;

        while (!cursor.done) {
            index = cursor.index; // cursor.next() increments index
            
            // Get the next burn authorization and skip if it's not relevant to this domain
            (auth, cursor) = cursor.next();

            // Get the transfer spec
            bytes29 spec = auth.getTransferSpec();

            // Validate that everything about the burn authorization is as expected, and skip if it's not for this domain
            bool relevant = _validateBurnAuthorization(auth, authorizer, fees[index], index);
            if (!relevant) {
                continue;
            }

            // Get the TransferSpec and ensure that each one we've seen so far is for the same token
            address _token = _bytes32ToAddress(spec.getSourceToken());
            if (token != address(0)) {
                if (_token != token) {
                    revert NotAllSameToken();
                }
            } else {
                token = _token;
            }

            // Reduce the balance of the depositor(s) and add to the total fee and burn amount
            uint256 fee = fees[index];
            (uint256 deductedAmount, uint256 actualFeeCharged) = _burn(spec, authorizer, fee);
            totalDeductedAmount += deductedAmount;
            totalFee += actualFeeCharged;
        }

        if (totalDeductedAmount == 0) {
            revert NoRelevantBurnAuthorizations();
        }

        // Collect the fee
        IERC20(token).safeTransfer(feeRecipient, totalFee);
        // Burn everything else
        IBurnToken(token).burn(totalDeductedAmount - totalFee);
    }

    function _burn(bytes29 spec, address authorizer, uint256 fee) internal returns (uint256 deductedAmount, uint256 actualFeeCharged) {
        // Mark the spend hash as used
        SpendHashesStorage._checkAndMark(spec.getHash());

        // Extract the relevant parameters from the TransferSpec
        address token = _bytes32ToAddress(spec.getSourceToken());
        address depositor = _bytes32ToAddress(spec.getSourceDepositor());
        uint256 value = spec.getValue();

        // Reduce the balances of the depositor by amount being burned + the fee, returning the overall amounts that were drawn from each balance type
        (uint256 fromSpendable, uint256 fromWithdrawing) = _reduceBalance(token, depositor, value + fee);
        deductedAmount = fromSpendable + fromWithdrawing;

        // If the full amount could not be deducted, charge a partial fee if possible
        if (deductedAmount <= value) {
            actualFeeCharged = 0;
        } else {
            uint256 potentialFee = deductedAmount - value;
            actualFeeCharged = potentialFee < fee ? potentialFee : fee;
        }

        // Emit an event with all the information about the burn
        emit BurnedSpent(
            token,
            depositor,
            spec.getHash(),
            spec.getDestinationDomain(),
            spec.getDestinationRecipient(),
            authorizer,
            value,
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

    function _recoverAuthorizationSigner(bytes memory authorizations, bytes memory signature)
        internal
        pure
        returns (address)
    {
        return ECDSA.recover(keccak256(authorizations).toEthSignedMessageHash(), signature);
    }

    function _validateBurnAuthorization(bytes29 auth, address authorizationSigner, uint256 fee, uint32 index)
        internal
        view
        returns (bool relevant)
    {
        bytes29 spec = auth.getTransferSpec();

        // If any burn authorizations are zero (even if they are for a different domain), refuse to continue so that
        // they all fail together across all source domains
        uint256 value = spec.getValue();
        if (value == 0) {
            revert BurnValueMustBePositive(index);
        }

        // If the burn authorization is for a different domain, ignore futher checks and indicate that to the caller
        // so it can be skipped
        uint32 domain = spec.getSourceDomain();
        if (!DomainStorage._isCurrentDomain(domain)) {
            return false;
        }

        // Ensure the burn authorization is not expired
        uint256 maxBlockHeight = auth.getMaxBlockHeight();
        if (maxBlockHeight < block.number) {
            revert AuthorizationExpired(index, maxBlockHeight, block.number);
        }

        // Ensure the fee is within the allowed range
        uint256 maxFee = auth.getMaxFee();
        if (maxFee < fee) {
            revert BurnFeeTooHigh(index, maxFee, fee);
        }

        // Ensure this is the correct source contract
        address sourceContract = _bytes32ToAddress(spec.getSourceContract());
        if (sourceContract != address(this)) {
            revert InvalidAuthorizationSourceContract(index, sourceContract);
        }

        // Ensure that the source token is supported
        address sourceToken = _bytes32ToAddress(spec.getSourceToken());
        if (!TokenSupportStorage._isTokenSupported(sourceToken)) {
            revert UnsupportedToken(index, sourceToken);
        }

        // Ensure that the signer of the burn authorization is authorized for the balance being burned
        address sourceDepositor = _bytes32ToAddress(spec.getSourceDepositor());
        if (!DelegationStorage._wasEverAuthorizedForBalance(sourceToken, sourceDepositor, authorizationSigner)) {
            revert DelegationStorage.NotAuthorized();
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
    event InsufficientBalanceForBurning(
        address indexed token,
        address indexed depositor,
        uint256 value,
        uint256 spendableBalance,
        uint256 withdrawingBalance
    );

    function _reduceBalance(address token, address depositor, uint256 value)
        internal
        returns (uint256 fromSpendable, uint256 fromWithdrawing)
    {
        BalancesStorage.Data storage balances$ = BalancesStorage.get();

        uint256 needed = value;
        uint256 spendable = balances$.spendableBalances[token][depositor];

        if (spendable >= needed) {
            // If there is enough in the spendable balance, deduct from it and return
            balances$.spendableBalances[token][depositor] -= needed;
            return (needed, 0);
        }

        // Otherwise, take it all and continue for the rest
        balances$.spendableBalances[token][depositor] = 0;
        needed -= spendable;

        uint256 withdrawing = balances$.withdrawingBalances[token][depositor];

        if (withdrawing >= needed) {
            // If there is enough in the withdrawing balance, deduct from it and return
            balances$.withdrawingBalances[token][depositor] -= needed;
            return (spendable, needed);
        }

        // Otherwise, take it all
        balances$.withdrawingBalances[token][depositor] = 0;

        // Emit an event to alert that something has gone wrong
        emit InsufficientBalanceForBurning(token, depositor, value, spendable, withdrawing);

        return (spendable, withdrawing);
    }
}
