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

import {TypedMemView} from "@memview-sol/TypedMemView.sol";
import {TransferSpec, TRANSFER_SPEC_MAGIC, TRANSFER_SPEC_VERSION} from "src/lib/authorizations/TransferSpec.sol";
import {
    BurnAuthorization,
    BURN_AUTHORIZATION_MAGIC,
    BURN_AUTHORIZATION_SET_MAGIC
} from "src/lib/authorizations/BurnAuthorizations.sol";
import {
    MintAuthorization,
    MINT_AUTHORIZATION_MAGIC,
    MINT_AUTHORIZATION_SET_MAGIC
} from "src/lib/authorizations/MintAuthorizations.sol";
import {AuthorizationLib} from "src/lib/authorizations/AuthorizationLib.sol";
import {Test} from "forge-std/Test.sol";

contract AuthorizationLibCastingTest is Test {
    using AuthorizationLib for bytes;
    using AuthorizationLib for bytes29;

    function _magic(string memory label) internal pure returns (bytes memory, uint40) {
        bytes4 magic = bytes4(keccak256(bytes(label)));
        return (abi.encodePacked(magic), uint40(uint32(magic)));
    }

    function test_asBurnAuthorization_correctMagic() external pure {
        (bytes memory data, uint40 magicType) = _magic("circle.gateway.BurnAuthorization");
        bytes29 ref = data.asBurnAuthorization();
        assertEq(TypedMemView.typeOf(ref), magicType);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asBurnAuthorization_incorrectMagic() external {
        (bytes memory data,) = _magic("something else");
        vm.expectRevert(abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorization.selector, data));
        data.asBurnAuthorization();
    }

    function test_asBurnAuthorizationSet_correctMagic() external pure {
        (bytes memory data, uint40 magicType) = _magic("circle.gateway.BurnAuthorizationSet");
        bytes29 ref = data.asBurnAuthorizationSet();
        assertEq(TypedMemView.typeOf(ref), magicType);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asBurnAuthorizationSet_incorrectMagic() external {
        (bytes memory data,) = _magic("something else");
        vm.expectRevert(abi.encodeWithSelector(AuthorizationLib.MalformedBurnAuthorizationSet.selector, data));
        data.asBurnAuthorizationSet();
    }

    function test_asMintAuthorization_correctMagic() external pure {
        (bytes memory data, uint40 magicType) = _magic("circle.gateway.MintAuthorization");
        bytes29 ref = data.asMintAuthorization();
        assertEq(TypedMemView.typeOf(ref), magicType);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asMintAuthorization_incorrectMagic() external {
        (bytes memory data,) = _magic("something else");
        vm.expectRevert(abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorization.selector, data));
        data.asMintAuthorization();
    }

    function test_asMintAuthorizationSet_correctMagic() external pure {
        (bytes memory data, uint40 magicType) = _magic("circle.gateway.MintAuthorizationSet");
        bytes29 ref = data.asMintAuthorizationSet();
        assertEq(TypedMemView.typeOf(ref), magicType);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asMintAuthorizationSet_incorrectMagic() external {
        (bytes memory data,) = _magic("something else");
        vm.expectRevert(abi.encodeWithSelector(AuthorizationLib.MalformedMintAuthorizationSet.selector, data));
        data.asMintAuthorizationSet();
    }

    function test_asTransferSpec_correctMagic() external pure {
        (bytes memory data, uint40 magicType) = _magic("circle.gateway.TransferSpec");
        bytes29 ref = data.asTransferSpec();
        assertEq(TypedMemView.typeOf(ref), magicType);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_asTransferSpec_incorrectMagic() external {
        (bytes memory data,) = _magic("something else");
        vm.expectRevert(abi.encodeWithSelector(AuthorizationLib.MalformedTransferSpec.selector, data));
        data.asTransferSpec();
    }
}
