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
pragma solidity ^0.8.29;

import {BURN_AUTHORIZATION_MAGIC, BURN_AUTHORIZATION_SET_MAGIC} from "src/lib/authorizations/BurnAuthorizations.sol";
import {MINT_AUTHORIZATION_MAGIC, MINT_AUTHORIZATION_SET_MAGIC} from "src/lib/authorizations/MintAuthorizations.sol";
import {CounterpartStorage} from "src/modules/common/Counterpart.sol";
import {DenylistStorage} from "src/modules/common/Denylist.sol";
import {DomainStorage} from "src/modules/common/Domain.sol";
import {PausingStorage} from "src/modules/common/Pausing.sol";
import {TokenSupportStorage} from "src/modules/common/TokenSupport.sol";
import {TransferSpecHashesStorage} from "src/modules/common/TransferSpecHashes.sol";
import {MintsStorage} from "src/modules/minter/Mints.sol";
import {BalancesStorage} from "src/modules/wallet/Balances.sol";
import {BurnsStorage} from "src/modules/wallet/Burns.sol";
import {DelegationStorage} from "src/modules/wallet/Delegation.sol";
import {WithdrawalDelayStorage} from "src/modules/wallet/WithdrawalDelay.sol";
import {Test} from "forge-std/Test.sol";

/// Ensures the magic values used throughout the codebase are correct
contract TestMagicValues is Test {
    function test_burn_authorization() external pure {
        assertEq(BURN_AUTHORIZATION_MAGIC, bytes4(keccak256("circle.gateway.BurnAuthorization")));
    }

    function test_burn_authorization_set() external pure {
        assertEq(BURN_AUTHORIZATION_SET_MAGIC, bytes4(keccak256("circle.gateway.BurnAuthorizationSet")));
    }

    function test_mint_authorization() external pure {
        assertEq(MINT_AUTHORIZATION_MAGIC, bytes4(keccak256("circle.gateway.MintAuthorization")));
    }

    function test_mint_authorization_set() external pure {
        assertEq(MINT_AUTHORIZATION_SET_MAGIC, bytes4(keccak256("circle.gateway.MintAuthorizationSet")));
    }

    function test_CounterpartStorage_slot() external pure {
        assertEq(
            CounterpartStorage.SLOT,
            keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Counterpart"))) - 1)) & ~bytes32(uint256(0xff))
        );
    }

    function test_DenylistStorage_slot() external pure {
        assertEq(
            DenylistStorage.SLOT,
            keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Denylist"))) - 1)) & ~bytes32(uint256(0xff))
        );
    }

    function test_DomainStorage_slot() external pure {
        assertEq(
            DomainStorage.SLOT,
            keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Domain"))) - 1)) & ~bytes32(uint256(0xff))
        );
    }

    function test_PausingStorage_slot() external pure {
        assertEq(
            PausingStorage.SLOT,
            keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Pausing"))) - 1)) & ~bytes32(uint256(0xff))
        );
    }

    function test_TokenSupportStorage_slot() external pure {
        assertEq(
            TokenSupportStorage.SLOT,
            keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.TokenSupport"))) - 1))
                & ~bytes32(uint256(0xff))
        );
    }

    function test_TransferSpecHashesStorage_slot() external pure {
        assertEq(
            TransferSpecHashesStorage.SLOT,
            keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.TransferSpecHashes"))) - 1))
                & ~bytes32(uint256(0xff))
        );
    }

    function test_MintsStorage_slot() external pure {
        assertEq(
            MintsStorage.SLOT,
            keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Mints"))) - 1)) & ~bytes32(uint256(0xff))
        );
    }

    function test_BalancesStorage_slot() external pure {
        assertEq(
            BalancesStorage.SLOT,
            keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Balances"))) - 1)) & ~bytes32(uint256(0xff))
        );
    }

    function test_BurnsStorage_slot() external pure {
        assertEq(
            BurnsStorage.SLOT,
            keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Burns"))) - 1)) & ~bytes32(uint256(0xff))
        );
    }

    function test_DelegationStorage_slot() external pure {
        assertEq(
            DelegationStorage.SLOT,
            keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Delegation"))) - 1)) & ~bytes32(uint256(0xff))
        );
    }

    function test_WithdrawalDelayStorage_slot() external pure {
        assertEq(
            WithdrawalDelayStorage.SLOT,
            keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.WithdrawalDelay"))) - 1))
                & ~bytes32(uint256(0xff))
        );
    }
}
