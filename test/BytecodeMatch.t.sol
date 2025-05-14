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

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Test} from "forge-std/Test.sol";
import {GatewayMinter} from "src/GatewayMinter.sol";
import {GatewayWallet} from "src/GatewayWallet.sol";
import {UpgradeablePlaceholder} from "src/UpgradeablePlaceholder.sol";

/// @title BytecodeMatchTest
/// @notice Tests to verify that the bytecode of contract implementations match the expected bytecode
contract BytecodeMatchTest is Test {
    /// @notice Test to verify that the creation bytecode of GatewayMinter matches the expected hash
    function testGatewayMinterCreationBytecodeMatch() public view {
        // Get the expected creation bytecode from the compiled artifact file
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/script/compiled-contract-artifacts/GatewayMinter.json");
        string memory json = vm.readFile(path);
        bytes memory expectedCreationBytecode = abi.decode(vm.parseJson(json, ".bytecode.object"), (bytes));
        bytes32 expectedCreationHash = keccak256(expectedCreationBytecode);

        // Get the creation bytecode of the GatewayMinter contract
        bytes memory creationCode = type(GatewayMinter).creationCode;
        bytes32 creationHash = keccak256(creationCode);

        // Verify that the hash matches the expected hash from the compiled artifact
        assertEq(
            creationHash,
            expectedCreationHash,
            "GatewayMinter creation bytecode hash does not match the expected hash from the compiled artifact"
        );
    }

    /// @notice Test to verify that the creation bytecode of GatewayWallet matches the expected hash
    function testGatewayWalletCreationBytecodeMatch() public view {
        // Get the expected creation bytecode from the compiled artifact file
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/script/compiled-contract-artifacts/GatewayWallet.json");
        string memory json = vm.readFile(path);
        bytes memory expectedCreationBytecode = abi.decode(vm.parseJson(json, ".bytecode.object"), (bytes));
        bytes32 expectedCreationHash = keccak256(expectedCreationBytecode);

        // Get the creation bytecode of the GatewayWallet contract
        bytes memory creationCode = type(GatewayWallet).creationCode;
        bytes32 creationHash = keccak256(creationCode);

        // Verify that the hash matches the expected hash from the compiled artifact
        assertEq(
            creationHash,
            expectedCreationHash,
            "GatewayWallet creation bytecode hash does not match the expected hash from the compiled artifact"
        );
    }

    /// @notice Test to verify that the creation bytecode of UpgradeablePlaceholder matches the expected hash
    function testUpgradeablePlaceholderCreationBytecodeMatch() public view {
        // Get the expected creation bytecode from the compiled artifact file
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/script/compiled-contract-artifacts/UpgradeablePlaceholder.json");
        string memory json = vm.readFile(path);
        bytes memory expectedCreationBytecode = abi.decode(vm.parseJson(json, ".bytecode.object"), (bytes));
        bytes32 expectedCreationHash = keccak256(expectedCreationBytecode);

        // Get the creation bytecode of the UpgradeablePlaceholder contract
        bytes memory creationCode = type(UpgradeablePlaceholder).creationCode;
        bytes32 creationHash = keccak256(creationCode);

        // Verify that the hash matches the expected hash from the compiled artifact
        assertEq(
            creationHash,
            expectedCreationHash,
            "UpgradeablePlaceholder creation bytecode hash does not match the expected hash from the compiled artifact"
        );
    }

    /// @notice Test to verify that the creation bytecode of ERC1967Proxy matches the expected hash
    function testERC1967ProxyCreationBytecodeMatch() public view {
        // Get the expected creation bytecode from the compiled artifact file
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/script/compiled-contract-artifacts/ERC1967Proxy.json");
        string memory json = vm.readFile(path);
        bytes memory expectedCreationBytecode = abi.decode(vm.parseJson(json, ".bytecode.object"), (bytes));
        bytes32 expectedCreationHash = keccak256(expectedCreationBytecode);

        // Get the creation bytecode of the ERC1967Proxy contract
        bytes memory creationCode = type(ERC1967Proxy).creationCode;
        bytes32 creationHash = keccak256(creationCode);

        // Verify that the hash matches the expected hash from the compiled artifact
        assertEq(
            creationHash,
            expectedCreationHash,
            "ERC1967Proxy creation bytecode hash does not match the expected hash from the compiled artifact"
        );
    }
}
