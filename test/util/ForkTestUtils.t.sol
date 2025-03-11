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

import {ForkTestUtils} from "test/util/ForkTestUtils.sol";
import {Test} from "forge-std/src/Test.sol";

contract TestForkTestUtils is Test {
    function test_forkVars_ethereum() external {
        vm.chainId(ForkTestUtils.ETHEREUM_CHAIN_ID);
        ForkTestUtils.ForkVars memory vars = ForkTestUtils.forkVars();
        assertEq(vars.usdc, 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    }

    function test_forkVars_local() external {
        vm.chainId(ForkTestUtils.LOCAL_CHAIN_ID);
        ForkTestUtils.ForkVars memory vars = ForkTestUtils.forkVars();
        assertEq(vars.usdc, address(0));
    }

    function test_forkVars_unknown() external {
        vm.chainId(123);
        vm.expectRevert(abi.encodeWithSelector(ForkTestUtils.UnknownChain.selector, 123));
        ForkTestUtils.forkVars();
    }
}
