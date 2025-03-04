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
