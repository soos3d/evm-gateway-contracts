/**
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
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
pragma solidity ^0.8.29;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {Test} from "forge-std/Test.sol";
import {Pausing} from "src/modules/common/Pausing.sol";
import {PausingStorage} from "src/modules/common/Pausing.sol";

contract PausingHarness is Pausing {
    function initialize(address owner, address pauser) public initializer {
        __Ownable_init(owner);
        __Ownable2Step_init();
        __Pausing_init(pauser);
    }

    // Helper function to specifically test the modifier whenNotPaused
    function verifyWhenNotPausedModifier() public whenNotPaused {}

    // Helper function to specifically test the modifier whenPaused
    function verifyWhenPausedModifier() public whenPaused {}
}

contract PausingTest is Test {
    PausingHarness private pausing;

    address private owner = makeAddr("owner");
    address private pauser = makeAddr("pauser");
    address private otherPauser = makeAddr("otherPauser");

    function setUp() public {
        pausing = new PausingHarness();
    }

    function _verifyPauseAndUnpause(address pauserAddress) internal {
        vm.startPrank(pauserAddress);
        assertFalse(pausing.paused(), "Contract should not be paused initially");

        vm.expectEmit(false, false, false, true);
        emit PausableUpgradeable.Paused(pauserAddress);
        pausing.pause();
        assertTrue(pausing.paused(), "Contract should be paused after pause()");

        vm.expectEmit(false, false, false, true);
        emit PausableUpgradeable.Unpaused(pauserAddress);
        pausing.unpause();
        assertFalse(pausing.paused(), "Contract should be unpaused after unpause()");
        vm.stopPrank();
    }

    function testInitialization_success() public {
        assertEq(pausing.pauser(), address(0), "Pauser should be zero address before initialization");

        vm.expectEmit(false, false, false, true);
        emit Pausing.PauserUpdated(pauser);

        pausing.initialize(owner, pauser);

        _verifyPauseAndUnpause(pauser);
    }

    function testUpdatePauser_success() public {
        vm.expectEmit(false, false, false, true);
        emit Pausing.PauserUpdated(pauser);

        pausing.initialize(owner, pauser);

        vm.expectEmit(false, false, false, true);
        emit Pausing.PauserUpdated(otherPauser);

        vm.startPrank(owner);
        pausing.updatePauser(otherPauser);
        vm.stopPrank();

        _verifyPauseAndUnpause(otherPauser);
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
        assertTrue(pausing.paused(), "Contract should be paused after first pause()");
        vm.expectRevert(abi.encodeWithSelector(PausableUpgradeable.EnforcedPause.selector));
        pausing.pause();
        vm.stopPrank();
    }

    function testUnpause_revertIfPaused() public {
        pausing.initialize(owner, pauser);
        vm.expectRevert(abi.encodeWithSelector(PausableUpgradeable.ExpectedPause.selector));

        vm.startPrank(pauser);
        pausing.unpause();
        vm.stopPrank();
    }

    function testWhenNotPausedModifier_allowsExecution() public {
        pausing.initialize(owner, pauser);

        assertFalse(pausing.paused(), "Contract should not be paused initially");
        pausing.verifyWhenNotPausedModifier();
    }

    function testWhenNotPausedModifier_blocksExecutionWhenPaused() public {
        pausing.initialize(owner, pauser);

        vm.startPrank(pauser);
        pausing.pause();
        vm.stopPrank();

        assertTrue(pausing.paused(), "Contract should be paused after pause()");
        vm.expectRevert(abi.encodeWithSelector(PausableUpgradeable.EnforcedPause.selector));
        pausing.verifyWhenNotPausedModifier();
    }

    function testWhenPausedModifier_allowsExecution() public {
        pausing.initialize(owner, pauser);

        vm.startPrank(pauser);
        pausing.pause();
        vm.stopPrank();

        assertTrue(pausing.paused(), "Contract should be paused after pause()");
        pausing.verifyWhenPausedModifier();
    }

    function testWhenPausedModifier_blocksExecutionWhenPaused() public {
        pausing.initialize(owner, pauser);

        assertFalse(pausing.paused(), "Contract should not be paused initially");
        vm.expectRevert(abi.encodeWithSelector(PausableUpgradeable.ExpectedPause.selector));
        pausing.verifyWhenPausedModifier();
    }
}
