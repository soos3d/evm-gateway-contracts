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
import {DeployGatewayWallet} from "../../script/001_DeployGatewayWallet.sol";
import {Create2Factory} from "../../script/Create2Factory.sol";

contract DeployGatewayWalletTest is Test {
    DeployGatewayWallet private deployer;

    function setUp() public {
        // Setup test environment variables
        vm.setEnv("ENV", "SMOKEBOX");

        // Create a factory for deterministic deployments
        address deployerAddress = makeAddr("deployer");
        Create2Factory factory = new Create2Factory(deployerAddress);

        // Set required environment variables
        vm.setEnv("CREATE2_FACTORY_ADDRESS", vm.toString(address(factory)));
        vm.setEnv("DEPLOYER_ADDRESS", vm.toString(deployerAddress));
        vm.setEnv("GATEWAYWALLET_OWNER_ADDRESS", vm.toString(makeAddr("walletOwner")));
        vm.setEnv("GATEWAYWALLET_PAUSER_ADDRESS", vm.toString(makeAddr("walletPauser")));
        vm.setEnv("GATEWAYWALLET_DENYLISTER_ADDRESS", vm.toString(makeAddr("walletDenylister")));
        vm.setEnv("GATEWAYWALLET_MINTER_ADDRESS", vm.toString(makeAddr("walletMinter")));
        vm.setEnv("GATEWAYWALLET_SUPPORTED_TOKEN_1", vm.toString(makeAddr("token1")));
        vm.setEnv("GATEWAYWALLET_DOMAIN", "1");
        vm.setEnv("GATEWAYWALLET_WITHDRAWAL_DELAY", "86400"); // 1 day
        vm.setEnv("GATEWAYWALLET_BURNSIGNER_ADDRESS", vm.toString(makeAddr("burnSigner")));
        vm.setEnv("GATEWAYWALLET_FEERECIPIENT_ADDRESS", vm.toString(makeAddr("feeRecipient")));

        // Initialize the deployer script
        deployer = new DeployGatewayWallet();
    }

    function testDeployGatewayWallet() public {
        // Execute the deployment script and verify the addresses.
        (address placeholderAddress, address implAddress, address proxyAddress) = deployer.run();
        assertEq(placeholderAddress, 0x704b433a9dA0cF5959857c77A6BE1A90844964Cf);
        assertEq(implAddress, 0xBD44151F5594969e99c870206E1FBF788df1CA42);
        assertEq(proxyAddress, 0xe0a3831610C2E2a0367adAcdb65a28dBafa5CA88);
    }
}
