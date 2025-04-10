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
import {SpendMinter} from "src/SpendMinter.sol";
import {BurnAuthorization} from "src/lib/authorizations/BurnAuthorizations.sol";
import {IERC1155Balance} from "src/interfaces/IERC1155Balance.sol";
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
contract SpendWallet is SpendCommon, IERC1155Balance {
    using SafeERC20 for IERC20;
    using MessageHashUtils for bytes32;

    error DepositValueMustBePositive();
    error WithdrawalValueMustBePositive();
    error WithdrawalValueExceedsSpendableBalance();
    error WithdrawalNotYetAvailable();
    error NoWithdrawingBalance();
    error UnauthorizedSpender();
    error CannotAddSelfAsSpender();
    error InputArrayLengthMismatch();
    error InvalidBalanceType(uint96 balanceType);
    error InvalidBurnSigner();

    enum BalanceType {
        Total, // 0
        Spendable, // 1
        Withdrawing, // 2
        Withdrawable // 3

    }

    /// The balances that have been deposited and are available for spending (after finalization)
    mapping(address token => mapping(address depositor => uint256 value)) internal spendableBalances;

    /// The balances that are in the process of being withdrawn and are no longer spendable
    mapping(address token => mapping(address depositor => uint256 value)) internal withdrawingBalances;

    /// The block numbers at which in-progress withdrawals will be withdrawable
    mapping(address token => mapping(address depositor => uint256 block)) internal withdrawableAtBlocks;

    /// The mapping to track authorized spenders for each depositor per token
    mapping(address token => mapping(address depositor => mapping(address spender => bool isAuthorized))) private
        spenderAuthorizations;

    /// The number of blocks a user must wait after initiating a withdrawal before that amount is withdrawable. This
    /// value is added to the current block number when a withdrawal is initiated.
    uint256 public withdrawalDelay;

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
        spendableBalances[token][msg.sender] += value;
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
        spendableBalances[token][owner] += value;
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
        spendableBalances[token][from] += value;
        IERC7598(token).receiveWithAuthorization(from, address(this), value, validAfter, validBefore, nonce, signature);
        emit Deposited(token, from, value);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Spender authorization

    /// Emitted when a spender is authorized to spend a depositor's balance
    ///
    /// @param token       The token that the spender is now authorized for
    /// @param depositor   The depositor who added the spender
    /// @param spender     The spender that was added
    event SpenderAdded(address indexed token, address indexed depositor, address spender);

    /// Allow `spender` to spend the caller's `token` balance
    ///
    /// @dev This acts as a full allowance for `spender` on the `token` balance of `msg.sender` in this contract
    ///
    /// @param token     The token that `spender` should be allowed to spend
    /// @param spender   The address being authorized to spend
    function addSpender(address token, address spender)
        external
        whenNotPaused
        notRejected(msg.sender)
        notRejected(spender)
        tokenSupported(token)
    {
        _checkNotZeroAddress(spender);
        if (spender == msg.sender) {
            revert CannotAddSelfAsSpender();
        }

        spenderAuthorizations[token][msg.sender][spender] = true;
        emit SpenderAdded(token, msg.sender, spender);
    }

    /// Emitted when a spender's authorization is revoked
    ///
    /// @param token       The token the spender is no longer authorized for
    /// @param depositor   The depositor who removed the spender
    /// @param spender     The spender that was removed
    event SpenderRemoved(address indexed token, address indexed depositor, address spender);

    /// Stop allowing `spender` to spend the caller's `token` balance
    ///
    /// @dev This revokes the allowance granted by `addSpender`
    ///
    /// @param token     The token that `spender` should be allowed to spend
    /// @param spender   The address being authorized to spend
    function removeSpender(address token, address spender)
        external
        whenNotPaused
        notRejected(msg.sender)
        tokenSupported(token)
    {
        _checkNotZeroAddress(spender);

        spenderAuthorizations[token][msg.sender][spender] = false;
        emit SpenderRemoved(token, msg.sender, spender);
    }

    /// Check if an spender is authorized to spend tokens on behalf of a depositor
    ///
    /// @dev This verifies if a spender is authorized or not for spending tokens on behalf of depositor
    ///
    /// @param token     The token that `spender` should be allowed to spend
    /// @param spender   The address being authorized to spend
    function isSpender(address token, address spender, address depositor) public view returns (bool) {
        if (spender == depositor) {
            return true;
        }

        return spenderAuthorizations[token][depositor][spender];
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Withdrawals

    /// Emitted when a withdrawal is initiated
    ///
    /// @param token              The token that is being withdrawn
    /// @param depositor          The owner of the funds being withdrawn
    /// @param spender            The spender that authorized the withdrawal
    /// @param value              The value that is newly being withdrawn
    /// @param totalWithdrawing   The total value that is now being withdrawn
    /// @param withdrawableAt     The block number at which the withdrawal can
    ///                           be completed
    event WithdrawalInitiated(
        address indexed token,
        address indexed depositor,
        address spender,
        uint256 value,
        uint256 totalWithdrawing,
        uint256 withdrawableAt
    );

    /// Internal helper function to initiate a withdrawal
    ///
    /// @param token       The token to initiate a withdrawal for
    /// @param depositor   The owner of the balance from which the withdrawal should come
    /// @param spender     The address initiating the withdrawal
    /// @param value       The amount to be withdrawn
    function _initiateWithdrawal(address token, address depositor, address spender, uint256 value) internal {
        if (value == 0) {
            revert WithdrawalValueMustBePositive();
        }
        if (value > spendableBalances[token][depositor]) {
            revert WithdrawalValueExceedsSpendableBalance();
        }
        spendableBalances[token][depositor] -= value;
        withdrawingBalances[token][depositor] += value;
        withdrawableAtBlocks[token][depositor] = block.number + withdrawalDelay;
        emit WithdrawalInitiated(
            token,
            depositor,
            spender,
            value,
            withdrawingBalances[token][depositor],
            withdrawableAtBlocks[token][depositor]
        );
    }

    /// Starts the withdrawal process. After `withdrawalDelay`, `withdraw` may be called to complete the withdrawal.
    /// Once a withdrawal has been initiated, that amount can no longer be spent. Calling this again before
    /// `withdrawalDelay` is over will add to the amount and reset the timer.
    ///
    /// @param token   The token to initiate a withdrawal for
    /// @param value   The amount to be withdrawn
    function initiateWithdrawal(address token, uint256 value) external whenNotPaused tokenSupported(token) {
        _initiateWithdrawal(token, msg.sender, msg.sender, value);
    }

    /// Starts the withdrawal process on behalf of a depositor who has authorized the caller. After `withdrawalDelay`,
    /// `withdraw` may be called to complete the withdrawal. Once a withdrawal has been initiated, that amount can no
    /// longer be spent. Calling this again before `withdrawalDelay` is over will add to the amount and reset the timer.
    ///
    /// @dev The caller of this method must be an authorized spender of `depositor` for `token`
    ///
    /// @param token       The token to initiate a withdrawal for
    /// @param depositor   The owner of the balance from which the withdrawal should come
    /// @param value       The amount to be withdrawn
    function initiateWithdrawal(address token, address depositor, uint256 value)
        external
        whenNotPaused
        tokenSupported(token)
    {
        if (!isSpender(token, msg.sender, depositor)) {
            revert UnauthorizedSpender();
        }
        _initiateWithdrawal(token, depositor, msg.sender, value);
    }

    /// Emitted when a withdrawal is completed and funds have been transferred to the recipient
    ///
    /// @param token       The token that was withdrawn
    /// @param depositor   The owner of the withdrawn funds
    /// @param recipient   The recipient of the funds
    /// @param spender     The spender that authorized the withdrawal
    /// @param value       The value that was withdrawn
    event WithdrawalCompleted(
        address indexed token, address indexed depositor, address indexed recipient, address spender, uint256 value
    );

    /// Internal helper function to complete a withdrawal
    ///
    /// @param token       The token to withdraw
    /// @param depositor   The owner of the balance from which the withdrawal should come
    /// @param recipient   The recipient of the funds
    function _withdraw(address token, address depositor, address recipient) internal {
        uint256 balanceToWithdraw = withdrawingBalances[token][depositor];
        if (balanceToWithdraw == 0) {
            revert NoWithdrawingBalance();
        }
        if (withdrawableAtBlocks[token][depositor] > block.number) {
            revert WithdrawalNotYetAvailable();
        }
        withdrawingBalances[token][depositor] = 0;
        withdrawableAtBlocks[token][depositor] = 0;
        IERC20(token).safeTransfer(recipient, balanceToWithdraw);
        emit WithdrawalCompleted(token, depositor, recipient, msg.sender, balanceToWithdraw);
    }

    /// Completes a withdrawal that was initiated at least `withdrawalDelay` blocks ago.
    ///
    /// @dev The full amount that was initiated is always withdrawn
    ///
    /// @param token   The token to withdraw
    function withdraw(address token) external whenNotPaused tokenSupported(token) {
        _withdraw(token, msg.sender, msg.sender);
    }

    /// Completes a withdrawal that was initiated at least `withdrawalDelay` blocks ago. The funds are sent to the
    /// specified recipient.
    ///
    /// @dev The full amount that was initiated is always withdrawn
    ///
    /// @param token       The token to withdraw
    /// @param depositor   The owner of the balance from which the withdrawal should come
    /// @param recipient   The recipient of the funds
    function withdraw(address token, address depositor, address recipient)
        external
        whenNotPaused
        tokenSupported(token)
    {
        if (!isSpender(token, msg.sender, depositor)) {
            revert UnauthorizedSpender();
        }
        _withdraw(token, depositor, recipient);
    }

    /// The block height at which an in-progress withdrawal is withdrawable
    ///
    /// @dev Returns 0 if there is no in-progress withdrawal
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function withdrawalBlock(address token, address depositor) external view returns (uint256) {
        return withdrawableAtBlocks[token][depositor];
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Balances

    /// The total balance of a depositor for a token. This will always be equal to the sum of `spendableBalance` and
    /// `withdrawingBalance`.
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function totalBalance(address token, address depositor) public view returns (uint256) {
        return spendableBalances[token][depositor] + withdrawingBalances[token][depositor];
    }

    /// The balance that is spendable by the depositor, subject to deposits having been observed by the API in a
    /// finalized block and no spend authorizations having been issued but not yet burned by the operator or used on the
    /// same chain
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function spendableBalance(address token, address depositor) public view returns (uint256) {
        return spendableBalances[token][depositor];
    }

    /// The balance that is in the process of being withdrawn
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function withdrawingBalance(address token, address depositor) public view tokenSupported(token) returns (uint256) {
        return withdrawingBalances[token][depositor];
    }

    /// The balance that is withdrawable as of the current block. This will either be 0 or `withdrawingBalance`.
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function withdrawableBalance(address token, address depositor)
        public
        view
        tokenSupported(token)
        returns (uint256)
    {
        uint256 balanceToWithdraw = withdrawingBalances[token][depositor];
        if (balanceToWithdraw == 0 || withdrawableAtBlocks[token][depositor] > block.number) {
            return 0;
        }
        return balanceToWithdraw;
    }

    /// The balance of a depositor for a particular balance specifier, compatible with ERC-1155
    ///
    /// @dev The token `id` should be encoded as `uint256(abi.encodePacked(uint12(BALANCE_TYPE), address(token)))`,
    ///      where `BALANCE_TYPE` is 0 for total, 1 for spendable, 2 for withdrawing, and 3 for withdrawable.
    ///
    /// @param depositor   The depositor of the requested balance
    /// @param id          The packed token and balance id specifier
    function balanceOf(address depositor, uint256 id) public view override returns (uint256) {
        // Verify token is supported
        address token = address(uint160(id));
        if (!isTokenSupported(token)) {
            revert UnsupportedToken(token);
        }

        // Verify balance type is valid
        uint96 balanceType = uint96(id >> 160);
        if (balanceType > uint96(type(BalanceType).max)) {
            revert InvalidBalanceType(balanceType);
        }

        // Return the appropriate balance
        BalanceType balanceTypeEnum = BalanceType(balanceType);

        if (balanceTypeEnum == BalanceType.Total) return totalBalance(token, depositor);
        if (balanceTypeEnum == BalanceType.Spendable) return spendableBalance(token, depositor);
        if (balanceTypeEnum == BalanceType.Withdrawing) return withdrawingBalance(token, depositor);
        if (balanceTypeEnum == BalanceType.Withdrawable) return withdrawableBalance(token, depositor);

        return 0;
    }

    /// The batch version of `balanceOf`, compatible with ERC-1155
    ///
    /// @dev `depositors` and `ids` must be the same length
    /// @dev The token `id` should be encoded as `uint256(abi.encodePacked(uint12(BALANCE_TYPE), address(token)))`,
    ///      where `BALANCE_TYPE` is 0 for total, 1 for spendable, 2 for withdrawing, and 3 for withdrawable.
    ///
    /// @param depositors   The depositor of the requested balance
    /// @param ids          The packed token and balance id specifier
    function balanceOfBatch(address[] calldata depositors, uint256[] memory ids)
        external
        view
        override
        returns (uint256[] memory)
    {
        if (depositors.length != ids.length) {
            revert InputArrayLengthMismatch();
        }

        uint256[] memory batchBalances = new uint256[](depositors.length);
        for (uint256 i = 0; i < depositors.length; i++) {
            batchBalances[i] = balanceOf(depositors[i], ids[i]);
        }

        return batchBalances;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Informational

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
    /// depositor or an authorized spender
    ///
    /// @dev Returns true if the authorizations and signature are valid
    /// @dev See the docs for `BurnAuthorization` for encoding details
    ///
    /// @param authorizations   A byte-encoded (set of) burn authorization(s)
    /// @param signature        The signature from the spender
    function validateBurnAuthorizations(bytes memory authorizations, bytes calldata signature)
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
    /// @param spender             The spender that authorized the spend
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
        address spender,
        uint256 value,
        uint256 fee,
        uint256 total,
        uint256 fromSpendable,
        uint256 fromWithdrawing,
        bytes burnAuthorization
    );

    /// Debit the depositor's balance and burn the tokens after a spend was authorized
    ///
    /// @dev May only be called by the `burner` role
    /// @dev `authorizations` and `signatures` must be the same length
    /// @dev Will revert if `destinationDomain` is the same as `sourceDomain` (since no burn is required)
    /// @dev For a set of burn authorizations, authorizations from other domains are ignored. The whole set is still
    ///      needed to verify the signature.
    /// @dev See the docs for `BurnAuthorization` for encoding details
    ///
    /// @param authorizations   An array of byte-encoded burn authorizations
    /// @param signatures       One signature from the spender of each burn authorization
    /// @param fees             The fees to be collected for each burn. Fees for burns on other domains are ignored and
    ///                         may be passed as zero. Each fee must be no more than `maxFee` of the corresponding burn
    ///                         authorization.
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
    /// @param spender              The spender that authorized the spend
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
        address spender,
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

    /// Emitted when the withdrawal delay is updated
    ///
    /// @param newDelay   The new value of the delay, in blocks
    event WithdrawalDelayUpdated(uint256 newDelay);

    /// Sets the number of blocks that must pass before a withdrawal can be completed
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newDelay   The new value of the delay, in blocks
    function updateWithdrawalDelay(uint256 newDelay) external onlyOwner {
        withdrawalDelay = newDelay;
        emit WithdrawalDelayUpdated(newDelay);
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
