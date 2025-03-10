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

import {ISpendMinter} from "src/interfaces/spend/ISpendMinter.sol";
import {SpendCommon} from "src/SpendCommon.sol";

/// @title Spend Minter
///
/// This contract allows the spending of funds from the SpendWallet contract, either on the same chain or on a different
/// chain. Spending requires a signed authorization from the operator. See the documentation for the SpendWallet
/// contract for more details.
contract SpendMinter is ISpendMinter, SpendCommon {
    function spend(bytes memory authorizations, bytes memory signature) external override whenNotPaused {}
}
