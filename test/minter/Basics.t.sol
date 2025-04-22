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

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {SpendCommon} from "src/SpendCommon.sol";
import {SpendMinter} from "src/SpendMinter.sol";
import {TokenSupport} from "src/lib//common/TokenSupport.sol";
import {OwnershipTest} from "test/util/OwnershipTest.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";

/// Tests ownership and initialization functionality of SpendMinter
contract SpendMinterBasicsTest is OwnershipTest, DeployUtils {
    uint32 private domain = 99;

    SpendMinter private minter;

    /// Used by OwnershipTest
    function _subject() internal view override returns (address) {
        return address(minter);
    }

    function setUp() public {
        minter = deployMinterOnly(owner, ForkTestUtils.forkVars().domain);
    }

    function test_initialize_revertWhenReinitialized() public {
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(Initializable.InvalidInitialization.selector));
        minter.initialize(makeAddr("random"), domain);
    }

    function test_updateMintAuthority_revertWhenNotOwner() public {
        address randomCaller = makeAddr("random");
        address token = makeAddr("token");
        address newMintAuthority = makeAddr("newMintAuthority");

        vm.startPrank(randomCaller);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, randomCaller));
        minter.updateMintAuthority(token, newMintAuthority);
    }

    function test_updateMintAuthority_revertWhenTokenNotSupported() public {
        address token = makeAddr("token");
        address newMintAuthority = makeAddr("newMintAuthority");

        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(TokenSupport.UnsupportedToken.selector, token));
        minter.updateMintAuthority(token, newMintAuthority);
    }

    function test_updateMintAuthority_revertWhenZeroAddress() public {
        address token = makeAddr("token");

        // Add token support first
        vm.startPrank(owner);
        minter.addSupportedToken(token);

        vm.expectRevert(abi.encodeWithSelector(SpendCommon.InvalidAddress.selector));
        minter.updateMintAuthority(token, address(0));
    }

    function test_updateMintAuthority_successFuzz(address token, address newMintAuthority) public {
        vm.assume(newMintAuthority != address(0));
        address oldMintAuthority = minter.tokenMintAuthorities(token);

        // Add token support first
        vm.startPrank(owner);
        minter.addSupportedToken(token);

        vm.expectEmit(false, false, false, true);
        emit SpendMinter.MintAuthorityUpdated(token, oldMintAuthority, newMintAuthority);

        minter.updateMintAuthority(token, newMintAuthority);
        assertEq(minter.tokenMintAuthorities(token), newMintAuthority);
    }

    function test_updateMintAuthority_idempotent() public {
        address token = makeAddr("token");
        address mintAuthority = makeAddr("mintAuthority");

        // Add token support and set initial mint authority
        vm.startPrank(owner);
        minter.addSupportedToken(token);
        minter.updateMintAuthority(token, mintAuthority);

        // Update to same address again
        vm.expectEmit(false, false, false, true);
        emit SpendMinter.MintAuthorityUpdated(token, mintAuthority, mintAuthority);
        minter.updateMintAuthority(token, mintAuthority);

        assertEq(minter.tokenMintAuthorities(token), mintAuthority);
    }

    function test_updateMintAuthorizationSigner_revertWhenNotOwner() public {
        address randomCaller = makeAddr("random");
        address newMintAuthorizationSigner = makeAddr("newMintAuthorizationSigner");

        vm.startPrank(randomCaller);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, randomCaller));
        minter.updateMintAuthorizationSigner(newMintAuthorizationSigner);
        vm.stopPrank();
    }

    function test_updateMintAuthorizationSigner_revertWhenZeroAddress() public {
        vm.startPrank(owner);
        vm.expectRevert(SpendCommon.InvalidAddress.selector);
        minter.updateMintAuthorizationSigner(address(0));
        vm.stopPrank();
    }

    function test_updateMintAuthorizationSigner_success(address newMintAuthorizationSigner) public {
        vm.assume(newMintAuthorizationSigner != address(0));

        address oldMintAuthorizationSigner = minter.mintAuthorizationSigner();

        vm.expectEmit(false, false, false, true);
        emit SpendMinter.MintAuthorizationSignerUpdated(oldMintAuthorizationSigner, newMintAuthorizationSigner);

        vm.startPrank(owner);
        minter.updateMintAuthorizationSigner(newMintAuthorizationSigner);
        vm.stopPrank();

        assertEq(minter.mintAuthorizationSigner(), newMintAuthorizationSigner);
    }

    function test_updateMintAuthorizationSigner_idempotent() public {
        address newMintAuthorizationSigner = makeAddr("newMintAuthorizationSigner");
        vm.startPrank(owner);
        minter.updateMintAuthorizationSigner(newMintAuthorizationSigner); // first update
        assertEq(minter.mintAuthorizationSigner(), newMintAuthorizationSigner);

        vm.expectEmit(false, false, false, true);
        emit SpendMinter.MintAuthorizationSignerUpdated(newMintAuthorizationSigner, newMintAuthorizationSigner);
        minter.updateMintAuthorizationSigner(newMintAuthorizationSigner); // second update
        vm.stopPrank();

        assertEq(minter.mintAuthorizationSigner(), newMintAuthorizationSigner);
    }
}
