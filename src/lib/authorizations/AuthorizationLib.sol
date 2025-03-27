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
import {TransferSpec, TRANSFER_SPEC_MAGIC, TRANSFER_SPEC_VERSION} from "./TransferSpec.sol";
import {BurnAuthorization, BURN_AUTHORIZATION_MAGIC, BURN_AUTHORIZATION_SET_MAGIC} from "./BurnAuthorizations.sol";
import {MintAuthorization, MINT_AUTHORIZATION_MAGIC, MINT_AUTHORIZATION_SET_MAGIC} from "./MintAuthorizations.sol";

library AuthorizationLib {
    using TypedMemView for bytes;
    using TypedMemView for bytes29;

    error MalformedBurnAuthorization(bytes data);
    error MalformedBurnAuthorizationSet(bytes data);
    error MalformedMintAuthorization(bytes data);
    error MalformedMintAuthorizationSet(bytes data);
    error MalformedTransferSpec(bytes data);

    function asBurnAuthorization(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(uint40(uint32(BURN_AUTHORIZATION_MAGIC)));
        if (ref.index(0, 4) != BURN_AUTHORIZATION_MAGIC) {
            revert MalformedBurnAuthorization(data);
        }
    }

    function asBurnAuthorizationSet(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(uint40(uint32(BURN_AUTHORIZATION_SET_MAGIC)));
        if (ref.index(0, 4) != BURN_AUTHORIZATION_SET_MAGIC) {
            revert MalformedBurnAuthorizationSet(data);
        }
    }

    function asMintAuthorization(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(uint40(uint32(MINT_AUTHORIZATION_MAGIC)));
        if (ref.index(0, 4) != MINT_AUTHORIZATION_MAGIC) {
            revert MalformedMintAuthorization(data);
        }
    }

    function asMintAuthorizationSet(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(uint40(uint32(MINT_AUTHORIZATION_SET_MAGIC)));
        if (ref.index(0, 4) != MINT_AUTHORIZATION_SET_MAGIC) {
            revert MalformedMintAuthorizationSet(data);
        }
    }

    function asTransferSpec(bytes memory data) internal pure returns (bytes29 ref) {
        ref = data.ref(uint40(uint32(TRANSFER_SPEC_MAGIC)));
        if (ref.index(0, 4) != TRANSFER_SPEC_MAGIC) {
            revert MalformedTransferSpec(data);
        }
    }
}
