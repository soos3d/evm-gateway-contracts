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
import {Denylistable} from "src/modules/common/Denylistable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract DenylistableHarness is Denylistable {
    function initialize(address owner) public initializer {
        __Ownable_init(owner);
        __Ownable2Step_init();
    }

    // Test function to expose the notDenylisted modifier
    function checkNotDenylistedModifier(address addr) public notDenylisted(addr) {}

    // Test function to expose the onlyDenylister modifier
    function checkOnlyDenylisterModifier() public onlyDenylister {}
}

contract DenylistableTest is Test {
    address private owner = makeAddr("owner");
    address private denylister = makeAddr("denylister");
    address private user = makeAddr("user");

    DenylistableHarness private denylistable;

    function setUp() public {
        denylistable = new DenylistableHarness();
        denylistable.initialize(owner);
    }

    function test_initialState() public {
        // Verify no denylister is set initially
        vm.expectRevert(abi.encodeWithSelector(Denylistable.UnauthorizedDenylister.selector, denylister));
        vm.prank(denylister);
        denylistable.checkOnlyDenylisterModifier();

        // Verify random address is not denylisted initially
        assertFalse(denylistable.isDenylisted(user), "User should not be denylisted by default");

        // Verify owner is correctly set
        assertEq(denylistable.owner(), owner, "Owner should be set correctly");
    }

    function test_updateDenylister_basicSuccess() public {
        vm.expectEmit(true, true, false, true);
        emit Denylistable.DenylisterChanged(address(0), denylister);

        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        // Verify denylister can denylist addresses
        vm.prank(denylister);
        denylistable.denylist(user);

        assertTrue(denylistable.isDenylisted(user), "User should be denylisted by denylister");
    }

    function test_updateDenylister_changeDenylister() public {
        // Set initial denylister
        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        address newDenylister = makeAddr("newDenylister");
        vm.expectEmit(true, true, false, true);
        emit Denylistable.DenylisterChanged(denylister, newDenylister);

        // Update to new denylister
        vm.prank(owner);
        denylistable.updateDenylister(newDenylister);

        // Verify new denylister can denylist addresses
        vm.prank(newDenylister);
        denylistable.denylist(user);

        assertTrue(denylistable.isDenylisted(user), "User should be denylisted by new denylister");

        // Verify old denylister cannot denylist addresses
        vm.expectRevert(abi.encodeWithSelector(Denylistable.UnauthorizedDenylister.selector, denylister));
        vm.prank(denylister);
        denylistable.denylist(user);
    }

    function test_updateDenylister_isIdempotent() public {
        // Set initial denylister
        vm.expectEmit(true, true, false, true);
        emit Denylistable.DenylisterChanged(address(0), denylister);

        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        // Set same denylister again
        vm.expectEmit(true, true, false, true);
        emit Denylistable.DenylisterChanged(denylister, denylister);

        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        // Verify denylister still has permissions
        vm.prank(denylister);
        denylistable.denylist(user);

        assertTrue(denylistable.isDenylisted(user), "User should be denylisted after idempotent denylister update");
    }

    function test_updateDenylister_revertIfNotOwner() public {
        address nonOwner = makeAddr("nonOwner");

        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, nonOwner));

        vm.prank(nonOwner);
        denylistable.updateDenylister(denylister);
    }

    function test_onlyDenylister_success() public {
        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        vm.prank(denylister);
        denylistable.checkOnlyDenylisterModifier();
    }

    function test_onlyDenylister_revertIfNotDenylister() public {
        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        address random = makeAddr("random");
        vm.expectRevert(abi.encodeWithSelector(Denylistable.UnauthorizedDenylister.selector, random));

        vm.prank(random);
        denylistable.checkOnlyDenylisterModifier();
    }

    function test_isDenylisted_returnsCorrectStatus() public {
        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        vm.prank(denylister);
        denylistable.denylist(user);

        assertTrue(denylistable.isDenylisted(user), "User should be denylisted");
        address random = makeAddr("random");
        assertFalse(denylistable.isDenylisted(random), "Random user should not be denylisted");
    }

    function test_denylistAddress_success() public {
        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        vm.expectEmit(true, true, false, true);
        emit Denylistable.Denylisted(user);

        vm.prank(denylister);
        denylistable.denylist(user);

        assertTrue(denylistable.isDenylisted(user), "User should be denylisted");
    }

    function test_denylistAddress_revertIfNotDenylister() public {
        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        address random = makeAddr("random");
        vm.expectRevert(abi.encodeWithSelector(Denylistable.UnauthorizedDenylister.selector, random));

        vm.prank(random);
        denylistable.denylist(user);
    }

    function test_denylistAddress_isIdempotent() public {
        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        vm.expectEmit(true, true, false, true);
        emit Denylistable.Denylisted(user);

        vm.prank(denylister);
        denylistable.denylist(user);

        assertTrue(denylistable.isDenylisted(user), "User should be denylisted");

        vm.expectEmit(true, true, false, true);
        emit Denylistable.Denylisted(user);

        // Denylist the same address again
        vm.prank(denylister);
        denylistable.denylist(user);

        assertTrue(denylistable.isDenylisted(user), "User should still be denylisted after second call");
    }

    function test_unDenylistAddress_allowAfterDenylisting() public {
        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        vm.expectEmit(true, true, false, true);
        emit Denylistable.Denylisted(user);

        vm.startPrank(denylister);
        denylistable.denylist(user);
        assertTrue(denylistable.isDenylisted(user), "User should be denylisted");
        vm.expectEmit(true, true, false, true);
        emit Denylistable.UnDenylisted(user);
        denylistable.unDenylist(user);
        vm.stopPrank();

        assertFalse(denylistable.isDenylisted(user), "User should not be denylisted after allow");
    }

    function test_unDenylistAddress_allowWithoutFirstDenylisting() public {
        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        vm.expectEmit(true, true, false, true);
        emit Denylistable.UnDenylisted(user);

        vm.prank(denylister);
        denylistable.unDenylist(user);

        assertFalse(denylistable.isDenylisted(user), "User should still not be denylisted after allow");
    }

    function test_unDenylistAddress_isIdempotent() public {
        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        vm.expectEmit(true, true, false, true);
        emit Denylistable.UnDenylisted(user);

        vm.startPrank(denylister);
        denylistable.unDenylist(user);
        assertFalse(denylistable.isDenylisted(user), "User should not be denylisted after first allow");
        vm.expectEmit(true, true, false, true);
        emit Denylistable.UnDenylisted(user);
        denylistable.unDenylist(user);
        vm.stopPrank();

        assertFalse(denylistable.isDenylisted(user), "User should still not be denylisted after second allow");
    }

    function test_unDenylistAddress_revertIfNotDenylist() public {
        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        address random = makeAddr("random");
        vm.expectRevert(abi.encodeWithSelector(Denylistable.UnauthorizedDenylister.selector, random));

        vm.prank(random);
        denylistable.unDenylist(user);
    }

    function test_notDenylistedModifier_success() public {
        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        denylistable.checkNotDenylistedModifier(user);
    }

    function test_notDenylistedModifier_revertIfDenylisted() public {
        vm.prank(owner);
        denylistable.updateDenylister(denylister);

        vm.prank(denylister);
        denylistable.denylist(user);

        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, user));
        denylistable.checkNotDenylistedModifier(user);
    }
}
