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

import {SpendCommon} from "src/SpendCommon.sol";
import {Delegation} from "src/lib/wallet/Delegation.sol";
import {Balances, BalancesStorage} from "src/lib/wallet/Balances.sol";
import {Withdrawals} from "src/lib/wallet/Withdrawals.sol";
import {SpendMinter} from "src/SpendMinter.sol";
import {BurnAuthorization} from "src/lib/authorizations/BurnAuthorizations.sol";
import {_checkNotZeroAddress} from "src/lib/util/addresses.sol";
import {IERC7597} from "src/interfaces/IERC7597.sol";
import {IERC7598} from "src/interfaces/IERC7598.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title Spend Wallet
///
/// This contract allows users to deposit supported tokens. Once deposits are observed in a finalized block by the API,
/// the user may request an authorization to instantly spend those funds on another chain. Spent funds are then burnt on
/// the chain where they were deposited.
///
/// The spendable balance is the amount the user has deposited that may be spent on other chains, subject to finality
/// observed by the API and an authorization obtained from the API. To obtain an authorization, the user must provide
/// the API with a signed message containing the desired spend parameters along with an authorization to the API that
/// will allow the operator to burn those funds once the spend is observed on the destination chain.
///
/// To spend funds on another chain, the user may request an authorization from the API and then use it to call `spend`
/// on the SpendMinter contract on the desired chain. This will mint the funds to the requested destination, and may be
/// composed with other actions via a multicall contract or SCA implementation.
///
/// To withdraw funds on the same chain, the user may request an authorization from the API just like any other spend
/// authorization. If the source and destination domains of the spend authorization are the same, the minter contract
/// will call `sameChainSpend` on this contract to transfer the funds to the recipient instead of minting. No fee is
/// charged for these spends.
///
/// To ensure funds are withdrawable even if the API is unavailable, users may withdraw permissionlessly using a
/// two-step process. First, the user must call `initiateWithdrawal` with the desired withdrawal amount. After a delay,
/// the user may call `withdraw` to complete the withdrawal and receive the funds. This delay ensures that no
/// double-spends are possible and that the operator has time to burn any funds that are spent. The amount that is in
/// the process of being withdrawn will no longer be spendable as soon as the withdrawal initiation is observed by the
/// API in a finalized block. If a double-spend was attempted, the contract will burn the user's funds from both their
/// `spendable` and `withdrawing` balances.
contract SpendWallet is SpendCommon, Balances, Delegation, Withdrawals {
    using SafeERC20 for IERC20;
    using MessageHashUtils for bytes32;

    error DepositValueMustBePositive();
    error InvalidBurnSigner();

    /// The address that may sign the calldata for burning tokens that have been spent
    address public burnSigner;

    /// The address that will receive the onchain fee for burns
    address public feeRecipient;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Initialization

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Ensure that the implementation contract cannot be initialized, only the proxy
        _disableInitializers();
    }

    /// Initializes the contract with the counterpart minter address
    ///
    /// @param minter   The address of the minter contract on the same chain
    function initialize(address minter) public reinitializer(2) {
        __SpendCommon_init(minter);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Deposits

    /// Emitted when a deposit is made
    ///
    /// @param token       The token that was deposited
    /// @param depositor   The address that deposited the funds
    /// @param value       The amount that was deposited
    event Deposited(address indexed token, address indexed depositor, uint256 value);

    /// Deposit tokens after approving this contract for the token
    ///
    /// @dev The resulting balance in this contract belongs to `msg.sender`
    ///
    /// @param token   The token to deposit
    /// @param value   The amount to be deposited
    function deposit(address token, uint256 value)
        external
        whenNotPaused
        notRejected(msg.sender)
        tokenSupported(token)
    {
        if (value == 0) {
            revert DepositValueMustBePositive();
        }

        BalancesStorage.Data storage balances$ = BalancesStorage.get();
        balances$.spendableBalances[token][msg.sender] += value;

        IERC20(token).safeTransferFrom(msg.sender, address(this), value);

        emit Deposited(token, msg.sender, value);
    }

    /// Deposit tokens with an EIP-2612 permit
    ///
    /// @dev The resulting balance in this contract belongs to `owner`
    /// @dev The permit's `spender` must be the address of this contract
    /// @dev The full permitted `value` is always deposited
    ///
    /// @param token      The token to deposit
    /// @param owner      The depositor's address
    /// @param value      The amount to be deposited
    /// @param deadline   The unix time at which the signature expires, or max uint256 value to signal no expiration
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
    ) external whenNotPaused notRejected(msg.sender) notRejected(owner) tokenSupported(token) {
        _depositWithPermit(token, owner, value, deadline, abi.encodePacked(r, s, v));
    }

    /// Deposit tokens with an EIP-7597 permit, passing the signature as bytes to allow for SCA deposits
    ///
    /// @dev The resulting balance in this contract belongs to `owner`
    /// @dev The permit's `spender` must be the address of this contract
    /// @dev The full permitted `value` is always deposited
    /// @dev EOA wallet signatures should be packed in the order of r, s, v
    ///
    /// @param token       The token to deposit
    /// @param owner       The depositor's address
    /// @param value       The amount to be deposited
    /// @param deadline    The unix time at which the signature expires, or max uint256 value to signal no expiration
    /// @param signature   Signature bytes signed by an EOA wallet or a contract wallet
    function depositWithPermit(address token, address owner, uint256 value, uint256 deadline, bytes calldata signature)
        external
        whenNotPaused
        notRejected(msg.sender)
        notRejected(owner)
        tokenSupported(token)
    {
        _depositWithPermit(token, owner, value, deadline, signature);
    }

    /// @dev Internal implementation for depositing tokens using an EIP-2612 permit
    ///
    /// @param token      The ERC20 token contract address that supports EIP-2612 permits
    /// @param owner      The address that owns the tokens and signed the permit
    /// @param value      The amount of tokens to deposit
    /// @param deadline   The unix timestamp after which the permit signature expires
    /// @param signature  The signature bytes containing v, r, s components
    function _depositWithPermit(address token, address owner, uint256 value, uint256 deadline, bytes memory signature)
        internal
    {
        if (value == 0) {
            revert DepositValueMustBePositive();
        }

        BalancesStorage.Data storage balances$ = BalancesStorage.get();
        balances$.spendableBalances[token][owner] += value;

        IERC7597(token).permit(owner, address(this), value, deadline, signature);
        IERC20(token).safeTransferFrom(owner, address(this), value);

        emit Deposited(token, owner, value);
    }

    /// Deposit tokens with an ERC-3009 authorization
    ///
    /// @dev The resulting balance in this contract belongs to `from`
    /// @dev The authorization's `to` must be the address of this contract
    /// @dev The transfer will be done via `transferWithAuthorization`
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
    ) external whenNotPaused notRejected(msg.sender) notRejected(from) tokenSupported(token) {
        _depositWithAuthorization(token, from, value, validAfter, validBefore, nonce, abi.encodePacked(r, s, v));
    }

    /// Deposit tokens with an ERC-7598 authorization, passing the signature as bytes to allow for SCA deposits
    ///
    /// @dev The resulting balance in this contract belongs to `from`
    /// @dev The authorization's `to` must be the address of this contract
    /// @dev The transfer will be done via `receiveWithAuthorization`
    /// @dev EOA wallet signatures should be packed in the order of r, s, v
    ///
    /// @param token         The token to deposit
    /// @param from          The depositor's address
    /// @param value         The amount to be deposited
    /// @param validAfter    The unix time after which this is valid
    /// @param validBefore   The unix time before which this is valid
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
    ) external whenNotPaused notRejected(msg.sender) notRejected(from) tokenSupported(token) {
        _depositWithAuthorization(token, from, value, validAfter, validBefore, nonce, signature);
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
        if (value == 0) {
            revert DepositValueMustBePositive();
        }

        BalancesStorage.Data storage balances$ = BalancesStorage.get();
        balances$.spendableBalances[token][from] += value;

        IERC7598(token).receiveWithAuthorization(from, address(this), value, validAfter, validBefore, nonce, signature);

        emit Deposited(token, from, value);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Informational

    // TODO: Consider moving this to SpendCommon and make sure SpendMinter bytecode isn't included
    function minterContract() external view returns (SpendMinter) {
        return SpendMinter(_counterpart());
    }

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

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Burning and transferring

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
        if (recoveredSigner != burnSigner) {
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Admin

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

        address oldBurnSigner = burnSigner;
        burnSigner = newBurnSigner;
        emit BurnSignerUpdated(oldBurnSigner, newBurnSigner);
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

        address oldFeeRecipient = feeRecipient;
        feeRecipient = newFeeRecipient;
        emit FeeRecipientUpdated(oldFeeRecipient, newFeeRecipient);
    }
}
