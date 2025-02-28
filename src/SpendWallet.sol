// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import {Initializable} from
    "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Ownable2StepUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {PausableUpgradeable} from
    "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from
    "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {ISpendWallet} from "src/interfaces/spend/ISpendWallet.sol";

/// @title Spend Wallet
///
/// This contract allows users to deposit supported tokens. Once deposits are
/// observed in a finalized block by the API, the user may request an
/// authorization to instantly spend those funds on another chain. Spent funds
/// are then burnt on the chain where they were deposited.
///
/// The spendable balance is the amount the user has deposited that may be spent
/// on other chains, subject to finality observed by the API and an
/// authorization obtained from the API. To obtain an authorization, the user
/// must provide the API with a signed message containing the desired spend
/// parameters along with an authorization to the API that will allow the
/// operator to burn those funds once the spend is observed on the destination
/// chain.
///
/// To spend funds on another chain, the user may request an authorization from
/// the API and then use it to call `spend` on the SpendDestination contract on
/// the desired chain. This will mint the funds to the requested destination,
/// and may be composed with other actions via a multicall contract or SCA
/// implementation.
///
/// To withdraw funds on the same chain, the user may request an authorization
/// from the API just like any other spend authorization. If the source and
/// destination domains of the spend authorization are the same, the destination
/// contract will call `sameChainSpend` on this contract to transfer the funds
/// to the recipient instead of minting. No fee is charged for these spends.
///
/// To ensure funds are withdrawable even if the API is unavailable, users may
/// withdraw permissionlessly using a two-step process. First, the user must
/// call `initiateWithdrawal` with the desired withdrawal amount. After a delay,
/// the user may call `withdraw` to complete the withdrawal and receive the
/// funds. This delay ensures that no double-spends are possible and that the
/// operator has time to burn any funds that are spent. The amount that is in
/// the process of being withdrawn will no longer be spendable as soon as the
/// withdrawal initiation is observed by the API in a finalized block. If a
/// double-spend was attempted, the contract will burn the user's funds from
/// both their `spendable` and `withdrawing` balances.
abstract contract SpendWallet is
    ISpendWallet,
    Initializable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable,
    PausableUpgradeable
{
    /// Whether or not a token is supported
    mapping(address token => bool supported) internal supportedTokens;

    /// The balances that have been deposited and are available for spending
    ///      (after finalization)
    mapping(address token => mapping(address user => uint256 value)) internal
        spendableBalances;

    /// The balances that are in the process of being withdrawn and are no
    ///      longer spendable
    mapping(address token => mapping(address user => uint256 value)) internal
        withdrawingBalances;

    /// The block numbers at which in-progress withdrawals will be withdrawable
    mapping(address token => mapping(address user => uint256 block)) internal
        withdrawableAtBlocks;

    /// Whether or not a given spend hash (the keccak256 hash of a `SpendSpec`)
    ///      has been used for a burn or same-chain spend, preventing replay
    mapping(bytes32 spendHash => bool used) public usedSpendHashes;

    /// Whether or not a given depositor should be denied from spending and must
    ///      withdraw instead
    mapping(address depositor => bool denied) public deniedDepositors;

    /// The number of blocks a user must wait after initiating a withdrawal
    ///      before that amount is withdrawable. Updating this value does not
    ///      affect existing withdrawals, just future ones.
    uint256 public withdrawalDelay;

    /// The address of the corresponding SpendDestination contract
    address public destinationContract;

    /// The address that is allowed to burn tokens that have been spent
    address public burner;

    /// The address that is allowed to pause and unpause the contract
    address public pauser;

    // ...
}