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
import {MINTER_PLACEHOLDER_IMPL_ADDRESS, MINTER_IMPL_ADDRESS, MINTER_PROXY_ADDRESS} from "./000_ContractAddress.sol";
import "./BaseBytecodeDeployScript.sol";

/// @title DeployGatewayMinter
/// @notice Deployment script for GatewayMinter implementation and proxy with initialization
/// @dev Deploys in sequence:
///      1. UpgradeablePlaceholder implementation (temporary implementation)
///      2. GatewayMinter implementation (actual implementation)
///      3. ERC1967Proxy pointing to placeholder, then upgrades to actual implementation
contract DeployGatewayMinter is BaseBytecodeDeployScript {
    /// @dev Predefined addresses for deterministic deployment
    address internal constant EXPECTED_MINTER_PLACEHOLDER_IMPL_ADDRESS = MINTER_PLACEHOLDER_IMPL_ADDRESS;
    address internal constant EXPECTED_MINTER_IMPL_ADDRESS = MINTER_IMPL_ADDRESS;
    address internal constant EXPECTED_MINTER_PROXY_ADDRESS = MINTER_PROXY_ADDRESS;

    /// @dev Prepares initialization data for GatewayMinter
    /// @return Encoded initialization call data including all configuration parameters
    function prepareInitData() internal view returns (bytes memory) {
        address gatewayMinterPauser = vm.envAddress("GATEWAYMINTER_PAUSER_ADDRESS");
        address gatewayMinterDenylister = vm.envAddress("GATEWAYMINTER_DENYLISTER_ADDRESS");
        address gatewayMinterWallet = vm.envAddress("GATEWAYMINTER_WALLET_ADDRESS");
        address[] memory supportedTokens = new address[](1);
        supportedTokens[0] = vm.envAddress("GATEWAYMINTER_SUPPORTED_TOKEN_1");
        uint32 domain = uint32(vm.envUint("GATEWAYMINTER_DOMAIN"));
        address mintAuthSigner = vm.envAddress("GATEWAYMINTER_AUTH_SIGNER");

        address[] memory tokenAuthorities = new address[](1);
        tokenAuthorities[0] = vm.envAddress("GATEWAYMINTER_TOKEN_AUTH_1");

        return abi.encodeWithSignature(
            "initialize(address,address,address,address[],uint32,address,address[])",
            gatewayMinterPauser,
            gatewayMinterDenylister,
            gatewayMinterWallet,
            supportedTokens,
            domain,
            mintAuthSigner,
            tokenAuthorities
        );
    }

    /// @notice Main deployment function that sets up the entire GatewayMinter system
    /// @dev Deployment process:
    ///      1. Deploy placeholder implementation (minimal implementation for proxy initialization)
    ///      2. Deploy actual GatewayMinter implementation
    ///      3. Prepare proxy deployment data
    ///      4. Deploy and initialize proxy with prepared calls
    function run() public {
        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        address factory = vm.envAddress("CREATE2_FACTORY_ADDRESS");
        address gatewayMinterOwner = vm.envAddress("GATEWAYMINTER_OWNER_ADDRESS");

        vm.startBroadcast(deployer);

        // Step 1: Deploy placeholder implementation. Use a different salt to avoid collision with GatewayWallet
        deploy(
            factory, "UpgradeablePlaceholder.json", bytes32(uint256(1)), hex"", EXPECTED_MINTER_PLACEHOLDER_IMPL_ADDRESS
        );

        // Step 2: Deploy actual GatewayMinter implementation
        deploy(factory, "GatewayMinter.json", bytes32(0), hex"", EXPECTED_MINTER_IMPL_ADDRESS);

        // Step 3: Prepare proxy deployment data

        // Prepare UpgradeablePlaceholder constructor call data for initialization
        bytes memory constructorCallData = abi.encode(
            EXPECTED_MINTER_PLACEHOLDER_IMPL_ADDRESS, abi.encodeWithSignature("initialize(address)", factory)
        );

        bytes[] memory proxyMultiCallData = new bytes[](2);
        // First call: Upgrade to actual implementation with initialization
        proxyMultiCallData[0] =
            abi.encodeWithSignature("upgradeToAndCall(address,bytes)", EXPECTED_MINTER_IMPL_ADDRESS, prepareInitData());

        // Second call: Transfer ownership to final owner
        proxyMultiCallData[1] = abi.encodeWithSignature("transferOwnership(address)", gatewayMinterOwner);

        // Step 4: Deploy and initialize proxy
        deployAndMultiCall(
            factory,
            "ERC1967Proxy.json",
            bytes32(0),
            constructorCallData,
            proxyMultiCallData,
            EXPECTED_MINTER_PROXY_ADDRESS
        );

        vm.stopBroadcast();
    }
}
