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

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Test} from "forge-std/Test.sol";
import {TokenSupport} from "src/modules/common/TokenSupport.sol";

contract TokenSupportHarness is TokenSupport {
    function initialize(address owner) public initializer {
        __Ownable_init(owner);
        __Ownable2Step_init();
    }

    // Helper function to specifically test the modifier tokenSupported
    function mint(address token) public tokenSupported(token) {}
}

contract TokenSupportTest is Test {
    TokenSupportHarness private tokenSupport;

    address private owner = makeAddr("owner");
    address private usdc = makeAddr("USDC");
    address private eurc = makeAddr("EURC");

    function setUp() public {
        tokenSupport = new TokenSupportHarness();
        tokenSupport.initialize(owner);
    }

    function testAddSupportedToken_onlyOwner() public {
        vm.expectEmit(false, false, false, true);
        emit TokenSupport.TokenSupported(usdc);

        vm.startPrank(owner);
        tokenSupport.addSupportedToken(usdc);
        vm.stopPrank();

        assertTrue(tokenSupport.isTokenSupported(usdc));
    }

    function testAddSupportedToken_revertIfNotOwner() public {
        address random = makeAddr("random");

        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, random));

        vm.startPrank(random);
        tokenSupport.addSupportedToken(usdc);
        vm.stopPrank();
    }

    function testAddSupportedToken_addDuplicateToken() public {
        vm.startPrank(owner);
        tokenSupport.addSupportedToken(usdc);
        vm.stopPrank();
        assertTrue(tokenSupport.isTokenSupported(usdc));

        vm.startPrank(owner);
        tokenSupport.addSupportedToken(usdc);
        vm.stopPrank();
        assertTrue(tokenSupport.isTokenSupported(usdc));
    }

    function testAddSupportedToken_addMultipleTokens() public {
        vm.startPrank(owner);
        tokenSupport.addSupportedToken(usdc);
        tokenSupport.addSupportedToken(eurc);
        vm.stopPrank();

        assertTrue(tokenSupport.isTokenSupported(usdc));
        assertTrue(tokenSupport.isTokenSupported(eurc));
    }

    function testIsTokenSupported_IfTokenNotAdded() public view {
        assertFalse(tokenSupport.isTokenSupported(eurc));
    }

    function testIfTokenIsSupportedWithModifier() public {
        vm.startPrank(owner);
        tokenSupport.addSupportedToken(eurc);
        vm.stopPrank();

        assertTrue(tokenSupport.isTokenSupported(eurc));
        tokenSupport.mint(eurc);
    }

    function testIfTokenNotSupportedWithModifier() public {
        vm.expectRevert(abi.encodeWithSelector(TokenSupport.UnsupportedToken.selector, eurc));
        tokenSupport.mint(eurc);
    }
}
