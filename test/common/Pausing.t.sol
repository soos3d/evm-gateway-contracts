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

import {Test} from "forge-std/Test.sol";
import {Pausing} from "src/lib/common/Pausing.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

contract PausingHarness is Pausing {
    function initialize(address owner, address pauser) public initializer {
        __Ownable_init(owner);
        __Ownable2Step_init();
        __Pausing_init(pauser);
    }

    // Expose internal paused function for testing
    function isPaused() public view returns (bool) {
        return paused();
    }

    // Helper function to specifically test the modifier whenNotPaused
    function verifyWhenNotPausedModifier() public whenNotPaused {}
}

contract PausingTest is Test {
    PausingHarness private pausing;

    address private owner = makeAddr("owner");
    address private pauser = makeAddr("pauser");
    address private otherPauser = makeAddr("otherPauser");

    function setUp() public {
        pausing = new PausingHarness();
    }

    function testInitialization_success() public {
        vm.expectEmit(false, false, false, true);
        emit Pausing.PauserUpdated(pauser);

        pausing.initialize(owner, pauser);

        verifyPauseAndUnpause(pauser);
    }

    function testUpdatePauser_success() public {
        vm.expectEmit(false, false, false, true);
        emit Pausing.PauserUpdated(pauser);

        pausing.initialize(owner, pauser);

        vm.startPrank(owner);
        pausing.updatePauser(otherPauser);
        vm.stopPrank();

        verifyPauseAndUnpause(otherPauser);
    }

    function verifyPauseAndUnpause(address pauserAddress) internal {
        vm.startPrank(pauserAddress);
        assertEq(pausing.isPaused(), false);
        pausing.pause();
        assertEq(pausing.isPaused(), true);
        pausing.unpause();
        assertEq(pausing.isPaused(), false);
        vm.stopPrank();
    }

    function testInitialization_revertIfAlreadyInitialized() public {
        pausing.initialize(owner, pauser);

        vm.expectRevert(abi.encodeWithSelector(Initializable.InvalidInitialization.selector));
        pausing.initialize(owner, otherPauser);
    }

    function testUpdatePauser_revertIfNotOwner() public {
        pausing.initialize(owner, pauser);

        address random = makeAddr("random");
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, random));

        vm.startPrank(random);
        pausing.updatePauser(otherPauser);
        vm.stopPrank();
    }

    function testPause_revertIfNotPauser() public {
        pausing.initialize(owner, pauser);
        vm.expectRevert(abi.encodeWithSelector(Pausing.UnauthorizedPauser.selector, otherPauser));

        vm.startPrank(otherPauser);
        pausing.pause();
        vm.stopPrank();
    }

    function testUnpause_revertIfNotPauser() public {
        pausing.initialize(owner, pauser);
        vm.expectRevert(abi.encodeWithSelector(Pausing.UnauthorizedPauser.selector, otherPauser));

        vm.startPrank(otherPauser);
        pausing.unpause();
        vm.stopPrank();
    }

    function testPause_revertIfTriedToPauseTwiceWithoutUnpausing() public {
        pausing.initialize(owner, pauser);

        vm.startPrank(pauser);
        pausing.pause();
        assertEq(pausing.isPaused(), true);
        vm.expectRevert(abi.encodeWithSelector(PausableUpgradeable.EnforcedPause.selector));
        pausing.pause();
        vm.stopPrank();
    }

    function testPause_revertIfNotPaused() public {
        pausing.initialize(owner, pauser);
        vm.expectRevert(abi.encodeWithSelector(PausableUpgradeable.ExpectedPause.selector));

        vm.startPrank(pauser);
        pausing.unpause();
        vm.stopPrank();
    }

    function testPausingModifier_success() public {
        pausing.initialize(owner, pauser);

        assertEq(pausing.isPaused(), false);

        vm.startPrank(pauser);
        pausing.verifyWhenNotPausedModifier();

        pausing.pause();
        assertEq(pausing.isPaused(), true);

        vm.expectRevert(abi.encodeWithSelector(PausableUpgradeable.EnforcedPause.selector));
        pausing.verifyWhenNotPausedModifier();
        vm.stopPrank();
    }
}
