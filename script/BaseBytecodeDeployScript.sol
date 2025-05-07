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

import {Script, console} from "forge-std/Script.sol";

/// @title BaseBytecodeDeployScript
/// @notice Base contract for deploying contracts using CREATE2 factory with deterministic addresses
/// @dev Abstract contract that provides functionality for deploying contracts with predetermined addresses
abstract contract BaseBytecodeDeployScript is Script {
    /// @notice Deploys a contract using CREATE2 factory with a predetermined address
    /// @dev If the contract already exists at the expected address, returns the existing contract
    /// @param contractFileName Name of the contract's compiled artifact file
    /// @param salt The salt used for CREATE2 deployment
    /// @param args The constructor arguments for the contract
    /// @param expectedAddress The predetermined address where the contract should be deployed
    /// @return exists Boolean indicating if contract already existed
    /// @return deployedAddress Address where the contract is deployed or exists
    function deployContract(string memory contractFileName, bytes32 salt, bytes memory args, address expectedAddress)
        internal
        returns (bool exists, address deployedAddress)
    {
        // Check if contract already exists at the expected address
        if (expectedAddress.code.length == 0) {
            exists = false;
            // Get project root directory and construct path to compiled contract artifact
            string memory root = vm.projectRoot();
            string memory path = string.concat(root, "/script/compiled-contract-artifacts/", contractFileName);
            string memory json = vm.readFile(path);

            // Extract bytecode from the compiled contract artifact.
            // Foundry compiled artifact file uses JSON format. The bytecode is stored in a second-level key (".bytecode.object") in the json file.
            bytes memory initCode = abi.decode(vm.parseJson(json, ".bytecode.object"), (bytes));

            // Deploy contract using CREATE2 factory.
            // Foundry's CREATE2 factory expects the deployment data to be encoded as follows: salt + contract bytecode + constructor arguments
            bytes memory callData = abi.encodePacked(salt, initCode, args);
            (bool success, bytes memory result) = CREATE2_FACTORY.call(callData);

            if (!success) {
                revert("Failed to deploy contract.");
            }

            // Extract deployed contract address from the result
            deployedAddress = address(bytes20(result));
        } else {
            // Contract already exists, return existing address
            exists = true;
            deployedAddress = expectedAddress;
        }
    }
}
