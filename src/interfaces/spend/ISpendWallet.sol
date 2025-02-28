// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import {ISpendWalletUser} from "src/interfaces/spend/ISpendWalletUser.sol";
import {ISpendWalletPortal} from "src/interfaces/spend/ISpendWalletPortal.sol";
import {ISpendWalletAdmin} from "src/interfaces/spend/ISpendWalletAdmin.sol";
import {ISpendWalletRead} from "src/interfaces/spend/ISpendWalletRead.sol";
import {ISpendWalletEvents} from "src/interfaces/spend/ISpendWalletEvents.sol";

/// The interface for the `SpendWallet` contract where funds are deposited for
///      spending
interface ISpendWallet is
    ISpendWalletUser,
    ISpendWalletPortal,
    ISpendWalletAdmin,
    ISpendWalletRead,
    ISpendWalletEvents
{}
