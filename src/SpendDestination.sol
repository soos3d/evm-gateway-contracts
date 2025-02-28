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

import {ISpendDestination} from "src/interfaces/spend/ISpendDestination.sol";

/// @title Spend Destination
///
/// This contract allows the spending of funds from the SpendWallet contract,
/// either on the same chain or on a different chain. Spending requires a
/// signed authorization from the operator. See the documentation for the
/// SpendWallet contract for more details.
abstract contract SpendDestination is
    ISpendDestination,
    Initializable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable,
    PausableUpgradeable
{
    /// The address of the corresponding SpendWallet contract
    address public walletContract;

    /// The address that is allowed to pause and unpause the contract
    address public pauser;

    /// Whether or not a given spend hash (the keccak256 hash of a `SpendSpec`)
    ///      has been used for a spend, preventing replay
    mapping(bytes32 spendHash => bool used) public usedSpendHashes;

    /// Whether or not a given recipient should be denied from receiving funds
    mapping(address recipient => bool denied) public deniedRecipients;

    // ...
}