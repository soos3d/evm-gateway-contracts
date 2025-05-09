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
import {WALLET_PLACEHOLDER_IMPL_ADDRESS, WALLET_IMPL_ADDRESS, WALLET_PROXY_ADDRESS} from "./000_ContractAddress.sol";
import "./BaseBytecodeDeployScript.sol";

/// @title DeployGatewayWallet
/// @notice Deployment script for GatewayWallet implementation and proxy with initialization
/// @dev Deploys in sequence:
///      1. UpgradeablePlaceholder implementation (temporary implementation)
///      2. GatewayWallet implementation (actual implementation)
///      3. ERC1967Proxy pointing to placeholder, then upgrades to actual implementation
contract DeployGatewayWallet is BaseBytecodeDeployScript {
    /// @dev Predefined addresses for deterministic deployment
    address internal constant EXPECTED_WALLET_PLACEHOLDER_IMPL_ADDRESS = WALLET_PLACEHOLDER_IMPL_ADDRESS;
    address internal constant EXPECTED_WALLET_IMPL_ADDRESS = WALLET_IMPL_ADDRESS;
    address internal constant EXPECTED_WALLET_PROXY_ADDRESS = WALLET_PROXY_ADDRESS;

    /// @dev Prepares initialization data for GatewayWallet
    /// @return Encoded initialization call data including all configuration parameters
    function prepareInitData() internal view returns (bytes memory) {
        address gatewayWalletPauser = vm.envAddress("GATEWAYWALLET_PAUSER_ADDRESS");
        address gatewayWalletDenylister = vm.envAddress("GATEWAYWALLET_DENYLISTER_ADDRESS");
        address gatewayWalletMinter = vm.envAddress("GATEWAYWALLET_MINTER_ADDRESS");
        address[] memory supportedTokens = new address[](1);
        supportedTokens[0] = vm.envAddress("GATEWAYWALLET_SUPPORTED_TOKEN_1");
        uint32 domain = uint32(vm.envUint("GATEWAYWALLET_DOMAIN"));
        uint256 withdrawalDelay = vm.envUint("GATEWAYWALLET_WITHDRAWAL_DELAY");
        address gatewayWalletBurnSigner = vm.envAddress("GATEWAYWALLET_BURNSIGNER_ADDRESS");
        address gatewayWalletFeeRecipient = vm.envAddress("GATEWAYWALLET_FEERECIPIENT_ADDRESS");

        // Encode initialization call with all parameters
        return abi.encodeWithSignature(
            "initialize(address,address,address,address[],uint32,uint256,address,address)",
            gatewayWalletPauser,
            gatewayWalletDenylister,
            gatewayWalletMinter,
            supportedTokens,
            domain,
            withdrawalDelay,
            gatewayWalletBurnSigner,
            gatewayWalletFeeRecipient
        );
    }

    /// @notice Main deployment function that sets up the entire GatewayWallet system
    /// @dev Deployment process:
    ///      1. Deploy placeholder implementation (minimal implementation for proxy initialization)
    ///      2. Deploy actual GatewayWallet implementation
    ///      3. Prepare proxy deployment data
    ///      4. Deploy and initialize proxy with prepared calls
    function run() public {
        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        address factory = vm.envAddress("CREATE2_FACTORY_ADDRESS");
        address gatewayWalletOwner = vm.envAddress("GATEWAYWALLET_OWNER_ADDRESS");

        vm.startBroadcast(deployer);

        // Step 1: Deploy placeholder implementation (minimal implementation for proxy initialization)
        deploy(factory, "UpgradeablePlaceholder.json", bytes32(0), hex"", EXPECTED_WALLET_PLACEHOLDER_IMPL_ADDRESS);

        // Step 2: Deploy actual GatewayWallet implementation
        deploy(factory, "GatewayWallet.json", bytes32(0), hex"", EXPECTED_WALLET_IMPL_ADDRESS);

        // Step 3: Prepare proxy deployment data

        // Prepare UpgradeablePlaceholder constructor call data for initialization
        bytes memory constructorCallData = abi.encode(
            EXPECTED_WALLET_PLACEHOLDER_IMPL_ADDRESS,
            abi.encodeWithSignature("initialize(address)", factory)
        );

        bytes[] memory proxyMultiCallData = new bytes[](2);
        // First call: Upgrade to actual implementation with initialization
        proxyMultiCallData[0] = abi.encodeWithSignature(
            "upgradeToAndCall(address,bytes)",
            EXPECTED_WALLET_IMPL_ADDRESS,
            prepareInitData()
        );

        // Second call: Transfer ownership to final owner
        proxyMultiCallData[1] = abi.encodeWithSignature(
            "transferOwnership(address)",
            gatewayWalletOwner
        );

        // Step 4: Deploy and initialize proxy with prepared calls
        deployAndMultiCall(
            factory,
            "ERC1967Proxy.json",
            bytes32(0),
            constructorCallData,
            proxyMultiCallData,
            EXPECTED_WALLET_PROXY_ADDRESS
        );

        vm.stopBroadcast();
    }
}
