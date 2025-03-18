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

import {Test} from "forge-std/Test.sol";
import {TokenSupport} from "src/lib/common/TokenSupport.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract TokenSupportHarness is TokenSupport {
    function initialize(address owner) public initializer {
        __Ownable_init(owner);
        __Ownable2Step_init();
    }

    function mint(address token) external tokenSupported(token) {}
}

contract TokenSupportTest is Test {
    TokenSupportHarness private tokenSupport;

    address private owner = makeAddr("owner");
    address private usdc = makeAddr("USDC");
    address private eurc = makeAddr("EURC");

    event TokenSupported(address token);

    function setUp() public {
        tokenSupport = new TokenSupportHarness();
        tokenSupport.initialize(owner);
    }

    function testAddSupportedToken_onlyOwner() public {
        vm.startPrank(owner);
        tokenSupport.addSupportedToken(usdc);
        assertTrue(tokenSupport.isTokenSupported(usdc));
        vm.stopPrank();
    }

    function testAddSupportedToken_revertIfNotOwner() public {
        address random = makeAddr("random");

        vm.startPrank(random);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, random));
        tokenSupport.addSupportedToken(usdc);
        vm.stopPrank();
    }

    function testAddSupportedToken_emitEvent() public {
        vm.startPrank(owner);
        vm.expectEmit(true, true, false, true);
        emit TokenSupported(usdc);
        tokenSupport.addSupportedToken(usdc);
        assertTrue(tokenSupport.isTokenSupported(usdc));
        vm.stopPrank();
    }

    function testIsTokenSupported_IfTokenNotAdded() public view {
        assertFalse(tokenSupport.isTokenSupported(eurc));
    }

    function testIfTokenIsSupportedWithModifier() public {
        vm.startPrank(owner);
        tokenSupport.addSupportedToken(eurc);
        assertTrue(tokenSupport.isTokenSupported(eurc));
        tokenSupport.mint(eurc);
        vm.stopPrank();
    }

    function testIfTokenNotSupportedWithModifier() public {
        vm.expectRevert(abi.encodeWithSelector(TokenSupport.UnsupportedToken.selector, eurc));
        tokenSupport.mint(eurc);
    }
}
