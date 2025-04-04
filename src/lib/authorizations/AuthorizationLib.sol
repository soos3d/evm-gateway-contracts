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
