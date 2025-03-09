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

import {ISpendMinterUser} from "src/interfaces/spend/ISpendMinterUser.sol";
import {ISpendMinterAdmin} from "src/interfaces/spend/ISpendMinterAdmin.sol";
import {ISpendMinterRead} from "src/interfaces/spend/ISpendMinterRead.sol";
import {ISpendMinterEvents} from "src/interfaces/spend/ISpendMinterEvents.sol";
import {ISpendMinterErrors} from "src/interfaces/spend/ISpendMinterErrors.sol";
import {ISpendErrors} from "src/interfaces/spend/ISpendErrors.sol";

/// The interface for the SpendMinter contract where funds are spent
interface ISpendMinter is
    ISpendMinterUser,
    ISpendMinterAdmin,
    ISpendMinterRead,
    ISpendMinterEvents,
    ISpendMinterErrors,
    ISpendErrors
{}
