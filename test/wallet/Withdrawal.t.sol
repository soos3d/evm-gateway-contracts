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

import {SpendWallet} from "src/SpendWallet.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {Test} from "forge-std/Test.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/// Tests withdrawal functionality of SpendWallet
contract SpendWalletWithdrawalTest is Test, DeployUtils {
    address private owner = makeAddr("owner");
    address private nonOwner = makeAddr("nonOwner");
    
    SpendWallet private wallet;

    function setUp() public {
        wallet = deployWalletOnly(owner);
    }

    function test_updateWithdrawalDelay_withdrawalDelayUpdatedByOwner() public {
        uint256 newDelay = 100;
        vm.startPrank(owner);
        vm.expectEmit(false, false, false, true);
        emit SpendWallet.WithdrawalDelayUpdated(newDelay);
        wallet.updateWithdrawalDelay(newDelay);
        vm.stopPrank();
        assertEq(wallet.withdrawalDelay(), newDelay);
    }

    function test_updateWithdrawalDelay_revertIfNotOwner() public {
        uint256 newDelay = 100;
        vm.startPrank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner));
        wallet.updateWithdrawalDelay(newDelay);
        vm.stopPrank();
    }
}
