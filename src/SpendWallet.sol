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
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {ISpendWallet} from "src/interfaces/spend/ISpendWallet.sol";
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
contract SpendWallet is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable, PausableUpgradeable, ISpendWallet {
    /// Whether or not a token is supported
    mapping(address token => bool supported) internal supportedTokens;

    /// The balances that have been deposited and are available for spending (after finalization)
    mapping(address token => mapping(address user => uint256 value)) internal spendableBalances;

    /// The balances that are in the process of being withdrawn and are no longer spendable
    mapping(address token => mapping(address user => uint256 value)) internal withdrawingBalances;

    /// The block numbers at which in-progress withdrawals will be withdrawable
    mapping(address token => mapping(address user => uint256 block)) internal withdrawableAtBlocks;

    /// Whether or not a given spend hash (the keccak256 hash of a `SpendSpec`) has been used for a burn or same-chain
    /// spend, preventing replay
    mapping(bytes32 spendHash => bool used) public usedSpendHashes;

    /// Whether or not a given depositor should be rejected from spending and must withdraw instead
    mapping(address depositor => bool rejected) public rejectedDepositors;

    /// The address of the corresponding SpendMinter contract
    address public minterContract;

    /// The number of blocks a user must wait after initiating a withdrawal before that amount is withdrawable. Updating
    /// this value does not affect existing withdrawals, just future ones.
    uint256 public withdrawalDelay;

    /// The address that is allowed to burn tokens that have been spent
    address public burner;

    /// The address that is allowed to pause and unpause the contract
    address public pauser;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Deposits

    function deposit(address token, uint256 value) external override whenNotPaused {}

    function depositWithPermit(
        address token,
        address owner,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external override {}

    function depositWithPermit(address token, address owner, uint256 value, uint256 deadline, bytes memory signature)
        external
        override
    {}

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
    ) external override {}

    function depositWithAuthorization(
        address token,
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external override {}

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Spender authorization

    function addSpender(address token, address spender) external override {}

    function removeSpender(address token, address spender) external override {}

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Withdrawals

    function initiateWithdrawal(address token, uint256 value) external override {}

    function initiateWithdrawal(address token, address depositor, uint256 value) external override {}

    function withdraw(address token) external override {}

    function withdraw(address token, address depositor) external override {}

    function withdrawalBlock(address, address) external pure override returns (uint256) {
        return 0;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Balances

    function totalBalance(address, address) external pure override returns (uint256) {
        return 0;
    }

    function spendableBalance(address, address) external pure override returns (uint256) {
        return 0;
    }

    function withdrawingBalance(address, address) external pure override returns (uint256) {
        return 0;
    }

    function withdrawableBalance(address, address) external pure override returns (uint256) {
        return 0;
    }

    function balanceOf(address, uint256) external pure override returns (uint256) {
        return 0;
    }

    function balanceOfBatch(address[] calldata, uint256[] memory) external pure override returns (uint256[] memory) {
        return new uint256[](0);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Informational

    function isTokenSupported(address) external pure override returns (bool) {
        return false;
    }

    function encodeBurnAuthorization(BurnAuthorization memory) external pure override returns (bytes memory) {
        return new bytes(0);
    }

    function encodeBurnAuthorizations(BurnAuthorization[] memory) external pure override returns (bytes memory) {
        return new bytes(0);
    }

    function validateBurnAuthorizations(bytes memory, bytes memory) external pure override returns (bool) {
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Burning and transferring

    function burnSpent(bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees)
        external
        override
        whenNotPaused
    {}

    function sameChainSpend(bytes memory authorization, bytes memory signature) external override whenNotPaused {}

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Admin

    function addSupportedToken(address token) external override onlyOwner {}

    function updateWithdrawalDelay(uint256 newDelay) external override onlyOwner {}

    function updateBurner(address newBurner) external override onlyOwner {}

    function updateMinterContract(address newMinterContract) external override onlyOwner {}

    function rejectDepositor(address depositor) external override onlyOwner {}

    function allowDepositor(address depositor) external override onlyOwner {}

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /// Pausing and unpausing

    modifier onlyPauser() {
        if (pauser != _msgSender()) {
            revert UnauthorizedPauser(_msgSender());
        }
        _;
    }

    function pause() external onlyPauser {
        _pause();
    }

    function unpause() external onlyPauser {
        _unpause();
    }

    function updatePauser(address newPauser) external override onlyOwner {}

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Upgrades

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
