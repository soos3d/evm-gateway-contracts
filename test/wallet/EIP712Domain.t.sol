/**
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
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

import {Test} from "forge-std/Test.sol";
import {GatewayWallet} from "src/GatewayWallet.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";

contract GatewayWalletEIP712DomainTest is Test, DeployUtils {
    address private owner = makeAddr("owner");
    GatewayWallet private wallet;

    function setUp() public {
        wallet = deployWalletOnly(owner, ForkTestUtils.forkVars().domain);
    }

    function test_domainSeparator_evaluatesToConsistentValue() public view {
        // Expected domain separator calculation:
        // keccak256(abi.encode(
        //     keccak256("EIP712Domain(string name,string version)"),
        //     keccak256("GatewayWallet"),
        //     keccak256("1")
        // ))
        bytes32 expectedDomainSeparator = 0x23a37920eca61226c76d13c4462857a362147e4b18da665dba894fa297ae4f34;
        assertEq(wallet.domainSeparator(), expectedDomainSeparator);
    }

    function test_eip712Domain_returnsExpectedValues() public view {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        ) = wallet.eip712Domain();

        // Verify fields bitmap indicates only name and version are used (00011)
        assertEq(fields, hex"03");

        // Verify name and version
        assertEq(name, "GatewayWallet");
        assertEq(version, "1");

        // Verify unused fields are zero/empty
        assertEq(chainId, 0);
        assertEq(verifyingContract, address(0));
        assertEq(salt, bytes32(0));
        assertEq(extensions.length, 0);
    }
}
