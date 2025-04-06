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

import {AuthorizationTestUtils} from "./AuthorizationTestUtils.sol";
import {
    TRANSFER_SPEC_MAGIC
} from "src/lib/authorizations/TransferSpec.sol";
import {
    BURN_AUTHORIZATION_MAGIC,
    BURN_AUTHORIZATION_SET_MAGIC
} from "src/lib/authorizations/BurnAuthorizations.sol";
import {
    MINT_AUTHORIZATION_MAGIC,
    MINT_AUTHORIZATION_SET_MAGIC
} from "src/lib/authorizations/MintAuthorizations.sol";
import {AuthorizationLib} from "src/lib/authorizations/AuthorizationLib.sol";

contract AuthorizationLibCommonTest is AuthorizationTestUtils {
    using AuthorizationLib for bytes;

    // ===== isAuthorizationSet Tests =====

    function test_isAuthorizationSet_returnsTrueForBurnSet() public pure {
        bytes memory data = abi.encodePacked(BURN_AUTHORIZATION_SET_MAGIC);
        assertTrue(data.isAuthorizationSet());
    }

    function test_isAuthorizationSet_returnsTrueForMintSet() public pure {
        bytes memory data = abi.encodePacked(MINT_AUTHORIZATION_SET_MAGIC);
        assertTrue(data.isAuthorizationSet());
    }

    function test_isAuthorizationSet_returnsFalseForBurnAuth() public pure {
        bytes memory data = abi.encodePacked(BURN_AUTHORIZATION_MAGIC);
        assertFalse(data.isAuthorizationSet());
    }

    function test_isAuthorizationSet_returnsFalseForMintAuth() public pure {
        bytes memory data = abi.encodePacked(MINT_AUTHORIZATION_MAGIC);
        assertFalse(data.isAuthorizationSet());
    }

    function test_isAuthorizationSet_returnsFalseForTransferSpec() public pure {
        bytes memory data = abi.encodePacked(TRANSFER_SPEC_MAGIC);
        assertFalse(data.isAuthorizationSet());
    }

    function test_isAuthorizationSet_returnsFalseForArbitraryBytes() public pure {
        bytes memory data = abi.encodePacked(bytes4(hex"12345678"));
        assertFalse(data.isAuthorizationSet());
    }

    function test_isAuthorizationSet_returnsFalseForLongerArbitraryBytes() public pure {
        bytes memory data = abi.encodePacked(bytes4(hex"12345678"), uint256(1)); // Add extra data
        assertFalse(data.isAuthorizationSet());
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_isAuthorizationSet_revertsForShortBytes() public {
        bytes memory data = hex"123456";
        vm.expectRevert(
            bytes(
                string.concat(
                    "TypedMemView/index - Overran the view. ",
                    "Slice is at 0x0000a0 with length 0x000003. ",
                    "Attempted to index at offset 0x000000 with length 0x000004."
                )
            )
        );
        data.isAuthorizationSet();
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_isAuthorizationSet_revertsForEmptyBytes() public {
         bytes memory data = new bytes(0);
         vm.expectRevert(
             bytes(
                 string.concat(
                    "TypedMemView/index - Overran the view. ",
                    "Slice is at 0x0000a0 with length 0x000000. ",
                    "Attempted to index at offset 0x000000 with length 0x000004."
                 )
            )
         );
         data.isAuthorizationSet();
    }
} 