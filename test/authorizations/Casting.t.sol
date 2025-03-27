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
