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

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {
    WALLET_PLACEHOLDER_IMPL_ADDRESS,
    WALLET_PROXY_ADDRESS,
    MINTER_PLACEHOLDER_IMPL_ADDRESS,
    MINTER_PROXY_ADDRESS
} from "./000_ContractAddress.sol";
import "./BaseBytecodeDeployScript.sol";

/// @title DeployUpgradeablePlaceholder
/// @notice Deployment script for wallet and minter placeholder implementations and their proxies
/// @dev Uses CREATE2 factory for deterministic deployment addresses
contract DeployUpgradeablePlaceholder is BaseBytecodeDeployScript {
    address internal constant EXPECTED_WALLET_PLACEHOLDER_IMPL_ADDRESS = WALLET_PLACEHOLDER_IMPL_ADDRESS;
    address internal constant EXPECTED_WALLET_PROXY_ADDRESS = WALLET_PROXY_ADDRESS;
    address internal constant EXPECTED_MINTER_PLACEHOLDER_IMPL_ADDRESS = MINTER_PLACEHOLDER_IMPL_ADDRESS;
    address internal constant EXPECTED_MINTER_PROXY_ADDRESS = MINTER_PROXY_ADDRESS;

    /// @notice Deploys wallet and minter placeholder implementations and their proxies
    /// @dev Uses environment variables for deployer key and temporary owners
    /// @dev Deploys in sequence: wallet implementation -> wallet proxy -> minter implementation -> minter proxy
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address temporaryWalletOwner = vm.envAddress("TEMP_GATEWAY_WALLET_PLACEHOLDER_OWNER_ADDRESS");
        address temporaryMinterOwner = vm.envAddress("TEMP_GATEWAY_MINTER_PLACEHOLDER_OWNER_ADDRESS");
        vm.startBroadcast(key);

        // Deploy wallet placeholder implementation and proxy
        // First deploy the placeholder implementation
        bool exists;
        address deployedAddress;
        (exists, deployedAddress) = deployContract("UpgradeablePlaceholder.json", bytes32(0), bytes(""), EXPECTED_WALLET_PLACEHOLDER_IMPL_ADDRESS);
        if (exists) {
            console.log("Wallet placeholder implementation already deployed at", deployedAddress);
        } else {
            console.log("Wallet placeholder implementation deployed at", deployedAddress);
        }

        // Then deploy the proxy
        (exists, deployedAddress) = deployContract(
            "ERC1967Proxy.json",
            bytes32(0xab43ca3aeb90abc29a32d7d694048dbe70e318b860b06c237e0127f5ef0faeb9),
            abi.encode(EXPECTED_WALLET_PLACEHOLDER_IMPL_ADDRESS, abi.encodeWithSignature("initialize(address)", temporaryWalletOwner)),
            EXPECTED_WALLET_PROXY_ADDRESS
        );
        if (exists) {
            console.log("Wallet proxy already deployed at", deployedAddress);
        } else {
            console.log("Wallet proxy deployed at", deployedAddress);
        }

        // Deploy minter placeholder implementation and proxy
        // First deploy the placeholder implementation. Use a different salt to avoid collision with the wallet placeholder implementation.
        (exists, deployedAddress) = deployContract("UpgradeablePlaceholder.json", bytes32(uint256(1)), bytes(""), EXPECTED_MINTER_PLACEHOLDER_IMPL_ADDRESS);
        if (exists) {
            console.log("Minter placeholder implementation already deployed at", deployedAddress);
        } else {
            console.log("Minter placeholder implementation deployed at", deployedAddress);
        }

        // Then deploy the proxy
        (exists, deployedAddress) = deployContract(
            "ERC1967Proxy.json",
            bytes32(0x499508b504993bc2fdab3f6188e1b9969b2d9653ea6021d41953ae668257bedf),
            abi.encode(EXPECTED_MINTER_PLACEHOLDER_IMPL_ADDRESS, abi.encodeWithSignature("initialize(address)", temporaryMinterOwner)),
            EXPECTED_MINTER_PROXY_ADDRESS
        );
        if (exists) {
            console.log("Minter proxy already deployed at", deployedAddress);
        } else {
            console.log("Minter proxy deployed at", deployedAddress);
        }

        vm.stopBroadcast();
    }
}