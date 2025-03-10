/*
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.

 * SPDX-License-Identifier: GPL-3.0-or-later

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
pragma solidity ^0.8.28;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {IERC1155Balance} from "src/interfaces/IERC1155Balance.sol";
import {SpendCommon} from "src/SpendCommon.sol";
import {BurnAuthorization} from "src/lib/Authorizations.sol";

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
    /// The balances that have been deposited and are available for spending (after finalization)
    mapping(address token => mapping(address user => uint256 value)) internal spendableBalances;

    /// The balances that are in the process of being withdrawn and are no longer spendable
    mapping(address token => mapping(address user => uint256 value)) internal withdrawingBalances;

    /// The block numbers at which in-progress withdrawals will be withdrawable
    mapping(address token => mapping(address user => uint256 block)) internal withdrawableAtBlocks;

    /// The number of blocks a user must wait after initiating a withdrawal before that amount is withdrawable. Updating
    /// this value does not affect existing withdrawals, just future ones.
    uint256 public withdrawalDelay;

    /// The address that is allowed to burn tokens that have been spent
    address public burner;

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
    function deposit(address token, uint256 value) external whenNotPaused {}

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
    ) external {}

    /// Deposit tokens with an EIP-2612 permit, passing the signature as bytes to allow for SCA deposits
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
    function depositWithPermit(address token, address owner, uint256 value, uint256 deadline, bytes memory signature)
        external
    {}

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
    ) external {}

    /// Deposit tokens with an ERC-3009 authorization, passing the signature as bytes to allow for SCA deposits
    ///
    /// @dev The resulting balance in this contract belongs to `from`
    /// @dev The authorization's `to` must be the address of this contract
    /// @dev The transfer will be done via `transferWithAuthorization`
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
        bytes memory signature
    ) external {}

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
    function addSpender(address token, address spender) external {}

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
    function removeSpender(address token, address spender) external {}

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

    /// Starts the withdrawal process. After `withdrawalDelay`, `withdraw` may be called to complete the withdrawal.
    /// Once a withdrawal has been initiated, that amount can no longer be spent. Calling this again before
    /// `withdrawalDelay` is over will add to the amount and reset the timer.
    ///
    /// @param token   The token to initiate a withdrawal for
    /// @param value   The amount to be withdrawn
    function initiateWithdrawal(address token, uint256 value) external {}

    /// Starts the withdrawal process on behalf of a depositor who has authorized the caller. After `withdrawalDelay`,
    /// `withdraw` may be called to complete the withdrawal. Once a withdrawal has been initiated, that amount can no
    /// longer be spent. Calling this again before `withdrawalDelay` is over will add to the amount and reset the timer.
    ///
    /// @dev The caller of this method must be an authorized spender of `depositor` for `token`
    ///
    /// @param token       The token to initiate a withdrawal for
    /// @param depositor   The owner of the balance from which the withdrawal should come
    /// @param value       The amount to be withdrawn
    function initiateWithdrawal(address token, address depositor, uint256 value) external {}

    /// Emitted when a withdrawal is completed and funds have been transferred to the depositor
    ///
    /// @param token       The token that was withdrawn
    /// @param depositor   The owner and recipient of the withdrawn funds
    /// @param spender     The spender that authorized the withdrawal
    /// @param value       The value that was withdrawn
    event WithdrawalCompleted(address indexed token, address indexed depositor, address spender, uint256 value);

    /// Completes a withdrawal that was initiated at least `withdrawalDelay` blocks ago.
    ///
    /// @dev The full amount that was initiated is always withdrawn
    ///
    /// @param token   The token to withdraw
    function withdraw(address token) external {}

    /// Completes a withdrawal that was initiated at least `withdrawalDelay` blocks ago. The funds are sent to the
    /// caller of this method, who must be an authorized spender of `depositor` for `token`.
    ///
    /// @dev The full amount that was initiated is always withdrawn
    ///
    /// @param token       The token to withdraw
    /// @param depositor   The owner of the balance from which the withdrawal should come
    function withdraw(address token, address depositor) external {}

    /// The block height at which an in-progress withdrawal is withdrawable
    ///
    /// @dev Returns 0 if there is no in-progress withdrawal
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function withdrawalBlock(address token, address depositor) external pure returns (uint256) {
        return 0;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Balances

    /// The total balance of a depositor for a token. This will always be equal to the sum of `spendableBalance` and
    /// `withdrawingBalance`.
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function totalBalance(address token, address depositor) external pure returns (uint256) {
        return 0;
    }

    /// The balance that is spendable by the depositor, subject to deposits having been observed by the API in a
    /// finalized block and no spend authorizations having been issued but not yet burned by the operator or used on the
    /// same chain
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function spendableBalance(address token, address depositor) external pure returns (uint256) {
        return 0;
    }

    /// The balance that is in the process of being withdrawn
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function withdrawingBalance(address token, address depositor) external pure returns (uint256) {
        return 0;
    }

    /// The balance that is withdrawable as of the current block. This will either be 0 or `withdrawingBalance`.
    ///
    /// @param token       The token of the requested balance
    /// @param depositor   The depositor of the requested balance
    function withdrawableBalance(address token, address depositor) external pure returns (uint256) {
        return 0;
    }

    /// The balance of a depositor for a particular balance specifier, compatible with ERC-1155
    ///
    /// @dev The token `id` should be encoded as `uint256(abi.encodePacked(uint12(BALANCE_TYPE), address(token)))`,
    ///      where `BALANCE_TYPE` is 0 for total, 1 for spendable, 2 for withdrawing, and 3 for withdrawable.
    ///
    /// @param depositor   The depositor of the requested balance
    /// @param id          The packed token and balance id specifier
    function balanceOf(address depositor, uint256 id) external pure override returns (uint256) {
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
        pure
        override
        returns (uint256[] memory)
    {
        return new uint256[](0);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Informational

    /// Returns the byte encoding of a single burn authorization
    ///
    /// @param authorization   The burn authorization to encode
    function encodeBurnAuthorization(BurnAuthorization memory authorization) external pure returns (bytes memory) {
        return new bytes(0);
    }

    /// Returns the byte encoding of a set of burn authorizations
    ///
    /// @dev The burn authorizations must be sorted by domain
    ///
    /// @param authorizations   The burn authorizations to encode
    function encodeBurnAuthorizations(BurnAuthorization[] memory authorizations) external pure returns (bytes memory) {
        return new bytes(0);
    }

    /// Allows anyone to validate whether a set of burn authorizations is valid along with a signature from the
    /// depositor or an authorized spender
    ///
    /// @dev Returns true if the authorizations and signature are valid
    /// @dev See the docs for `BurnAuthorization` for encoding details
    ///
    /// @param authorizations   A byte-encoded (set of) burn authorization(s)
    /// @param signature        The signature from the spender
    function validateBurnAuthorizations(bytes memory authorizations, bytes memory signature)
        external
        pure
        returns (bool)
    {
        return false;
    }

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
    function burnSpent(bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees)
        external
        whenNotPaused
    {}

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
    function sameChainSpend(bytes memory authorization, bytes memory signature) external whenNotPaused {}

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
    function updateWithdrawalDelay(uint256 newDelay) external onlyOwner {}

    /// Emitted when the burner address is updated
    ///
    /// @param newBurner   The new burner address
    event BurnerUpdated(address newBurner);

    /// Sets the address that may call `burnSpent`
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newBurner   The new burner address
    function updateBurner(address newBurner) external onlyOwner {}
}
