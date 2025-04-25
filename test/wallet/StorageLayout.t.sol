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

import {Test} from "forge-std/Test.sol";
import {SpendWallet} from "src/SpendWallet.sol";

contract Sample is SpendWallet {
    /// The answer to life, the universe, and everything
    uint256 private answer = 42;

    /// Loads the first storage slot
    function getSlotZero() public view returns (uint256 val) {
        assembly {
            val := sload(0)
        }
    }
}

contract SpendWalletStorageLayout is Test {
    /// Ensures that `SpendWallet` uses up no sequential storage slots and uses EIP-7201 for all modules
    function test_storage_conflicts() external {
        Sample sample = new Sample();
        assertEq(sample.getSlotZero(), 42, "At least one module in SpendWallet has declared sequential storage slots");
    }
}
