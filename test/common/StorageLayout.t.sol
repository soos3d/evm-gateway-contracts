/*
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.

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

import {SpendCommon} from "src/SpendCommon.sol";
import {Test} from "forge-std/Test.sol";

contract Sample is SpendCommon {
    /// The answer to life, the universe, and everything
    uint256 private answer = 42;

    /// Loads the first storage slot
    function getSlotZero() public view returns (uint256 val) {
        assembly {
            val := sload(0)
        }
    }
}

contract SpendCommonStorageLayout is Test {
    /// Ensures that `SpendCommon` uses up no sequential storage slots and uses EIP-7201 for all modules
    function test_storage_conflicts() external {
        Sample sample = new Sample();
        assertEq(sample.getSlotZero(), 42, "At least one module in SpendCommon has declared sequential storage slots");
    }
}
