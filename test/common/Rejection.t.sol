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
import {Rejection} from "src/lib/common/Rejection.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract RejectionHarness is Rejection {
    function initialize(address owner) public initializer {
        __Ownable_init(owner);
        __Ownable2Step_init();
    }

    // Test function to expose the notRejected modifier
    function checkNotRejectedModifier(address addr) public notRejected(addr) {}

    // Test function to expose the onlyRejecter modifier
    function checkOnlyRejecterModifier() public onlyRejecter {}
}

contract RejectionTest is Test {
    address private owner = makeAddr("owner");
    address private rejecter = makeAddr("rejecter");
    address private user = makeAddr("user");

    RejectionHarness private rejection;

    function setUp() public {
        rejection = new RejectionHarness();
        rejection.initialize(owner);
    }

    function test_initialState() public {
        // Verify no rejecter is set initially
        vm.expectRevert(abi.encodeWithSelector(Rejection.UnauthorizedRejecter.selector, rejecter));
        vm.prank(rejecter);
        rejection.checkOnlyRejecterModifier();

        // Verify random address is not rejected initially
        assertFalse(rejection.isRejected(user), "User should not be rejected by default");

        // Verify owner is correctly set
        assertEq(rejection.owner(), owner, "Owner should be set correctly");
    }

    function test_updateRejecter_basicSuccess() public {
        vm.expectEmit(false, false, false, true);
        emit Rejection.RejecterUpdated(rejecter);

        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        // Verify rejecter can reject addresses
        vm.prank(rejecter);
        rejection.rejectAddress(user);

        assertTrue(rejection.isRejected(user), "User should be rejected by rejecter");
    }

    function test_updateRejecter_changeRejecter() public {
        // Set initial rejecter
        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        address newRejecter = makeAddr("newRejecter");
        vm.expectEmit(false, false, false, true);
        emit Rejection.RejecterUpdated(newRejecter);

        // Update to new rejecter
        vm.prank(owner);
        rejection.updateRejecter(newRejecter);

        // Verify new rejecter can reject addresses
        vm.prank(newRejecter);
        rejection.rejectAddress(user);

        assertTrue(rejection.isRejected(user), "User should be rejected by new rejecter");

        // Verify old rejecter cannot reject addresses
        vm.expectRevert(abi.encodeWithSelector(Rejection.UnauthorizedRejecter.selector, rejecter));
        vm.prank(rejecter);
        rejection.rejectAddress(user);
    }

    function test_updateRejecter_isIdempotent() public {
        // Set initial rejecter
        vm.expectEmit(false, false, false, true);
        emit Rejection.RejecterUpdated(rejecter);

        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        // Set same rejecter again
        vm.expectEmit(false, false, false, true);
        emit Rejection.RejecterUpdated(rejecter);

        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        // Verify rejecter still has permissions
        vm.prank(rejecter);
        rejection.rejectAddress(user);

        assertTrue(rejection.isRejected(user), "User should be rejected after idempotent rejecter update");
    }

    function test_updateRejecter_revertIfNotOwner() public {
        address nonOwner = makeAddr("nonOwner");

        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner));

        vm.prank(nonOwner);
        rejection.updateRejecter(rejecter);
    }

    function test_onlyRejecter_success() public {
        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        vm.prank(rejecter);
        rejection.checkOnlyRejecterModifier();
    }

    function test_onlyRejecter_revertIfNotRejecter() public {
        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        address random = makeAddr("random");
        vm.expectRevert(abi.encodeWithSelector(Rejection.UnauthorizedRejecter.selector, random));

        vm.prank(random);
        rejection.checkOnlyRejecterModifier();
    }

    function test_isRejected_returnsCorrectStatus() public {
        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        vm.prank(rejecter);
        rejection.rejectAddress(user);

        assertTrue(rejection.isRejected(user), "User should be rejected");
        address random = makeAddr("random");
        assertFalse(rejection.isRejected(random), "Random user should not be rejected");
    }

    function test_rejectAddress_success() public {
        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        vm.expectEmit(false, false, false, true);
        emit Rejection.AddressRejected(user);

        vm.prank(rejecter);
        rejection.rejectAddress(user);

        assertTrue(rejection.isRejected(user), "User should be rejected");
    }

    function test_rejectAddress_revertIfNotRejecter() public {
        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        address random = makeAddr("random");
        vm.expectRevert(abi.encodeWithSelector(Rejection.UnauthorizedRejecter.selector, random));

        vm.prank(random);
        rejection.rejectAddress(user);
    }

    function test_rejectAddress_isIdempotent() public {
        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        vm.expectEmit(false, false, false, true);
        emit Rejection.AddressRejected(user);

        vm.prank(rejecter);
        rejection.rejectAddress(user);

        assertTrue(rejection.isRejected(user));

        vm.expectEmit(false, false, false, true);
        emit Rejection.AddressRejected(user);

        // Reject the same address again
        vm.prank(rejecter);
        rejection.rejectAddress(user);

        assertTrue(rejection.isRejected(user), "User should still be rejected after second call");
    }

    function test_allowAddress_allowAfterRejecting() public {
        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        vm.expectEmit(false, false, false, true);
        emit Rejection.AddressRejected(user);

        vm.startPrank(rejecter);
        rejection.rejectAddress(user);
        assertTrue(rejection.isRejected(user), "User should be rejected");
        vm.expectEmit(false, false, false, true);
        emit Rejection.AddressAllowed(user);
        rejection.allowAddress(user);
        vm.stopPrank();

        assertFalse(rejection.isRejected(user), "User should not be rejected after allow");
    }

    function test_allowAddress_allowWithoutFirstRejecting() public {
        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        vm.expectEmit(false, false, false, true);
        emit Rejection.AddressAllowed(user);

        vm.prank(rejecter);
        rejection.allowAddress(user);

        assertFalse(rejection.isRejected(user), "User should still not be rejected after allow");
    }

    function test_allowAddress_isIdempotent() public {
        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        vm.expectEmit(false, false, false, true);
        emit Rejection.AddressAllowed(user);

        vm.startPrank(rejecter);
        rejection.allowAddress(user);
        assertFalse(rejection.isRejected(user), "User should not be rejected after first allow");
        vm.expectEmit(false, false, false, true);
        emit Rejection.AddressAllowed(user);
        rejection.allowAddress(user);
        vm.stopPrank();

        assertFalse(rejection.isRejected(user), "User should still not be rejected after second allow");
    }

    function test_allowAddress_revertIfNotRejecter() public {
        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        address random = makeAddr("random");
        vm.expectRevert(abi.encodeWithSelector(Rejection.UnauthorizedRejecter.selector, random));

        vm.prank(random);
        rejection.allowAddress(user);
    }

    function test_notRejectedModifier_success() public {
        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        rejection.checkNotRejectedModifier(user);
    }

    function test_notRejectedModifier_revertIfRejected() public {
        vm.prank(owner);
        rejection.updateRejecter(rejecter);

        vm.prank(rejecter);
        rejection.rejectAddress(user);

        vm.expectRevert(abi.encodeWithSelector(Rejection.NotAllowed.selector, user));
        rejection.checkNotRejectedModifier(user);
    }
}
