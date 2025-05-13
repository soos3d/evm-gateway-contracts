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

/**
 * @title Constants
 * @notice Library containing environment-specific constants for deployment
 * @dev Defines constants for three environments: SMOKEBOX, SANDBOX and PROD
 */
library Constants {
    // Smokebox environment constants
    bytes32 constant SMOKEBOX_SALT = bytes32(uint256(0));
    bytes32 constant SMOKEBOX_WALLET_PROXY_SALT = bytes32(uint256(0));
    bytes32 constant SMOKEBOX_MINTER_PROXY_SALT = bytes32(uint256(0));

    // Sandbox environment constants
    bytes32 constant SANDBOX_SALT = bytes32(uint256(1));
    bytes32 constant SANDBOX_WALLET_PROXY_SALT = bytes32(uint256(1));
    bytes32 constant SANDBOX_MINTER_PROXY_SALT = bytes32(uint256(1));
    address constant SANDBOX_CREATE2FACTORY_ADDRESS = 0x643151056F7cCCD36030d6507a8C07Ed4a46E8D2;
    address constant SANDBOX_DEPLOYER_ADDRESS = 0xD1e4098de8667a491Eb2Bf5acf09ED7F67260BCA;

    // Production environment constants
    bytes32 constant PROD_SALT = bytes32(uint256(2));
    bytes32 constant PROD_WALLET_PROXY_SALT = bytes32(uint256(2));
    bytes32 constant PROD_MINTER_PROXY_SALT = bytes32(uint256(2));
    address constant PROD_CREATE2FACTORY_ADDRESS = 0xe7b84D8846c96Bb83155Da5537625c75e42d6E42;
    address constant PROD_DEPLOYER_ADDRESS = 0xadB384F7fa7486422051D2a896417EAAb9E5A9D1;
}

/**
 * @title EnvConfig
 * @notice Configuration struct that holds all environment-specific parameters
 * @dev Used to pass environment configuration between contracts in a structured way
 * @param salt The base salt value used for non proxy contract deployment
 * @param walletProxySalt The salt value used for GatewayWallet proxy deployment
 * @param minterProxySalt The salt value used for GatewayMinter proxy deployment
 * @param factoryAddress The CREATE2 factory address for deterministic deployment
 * @param deployerAddress The address that will deploy the contracts
 */
struct EnvConfig {
    bytes32 salt;
    bytes32 walletProxySalt;
    bytes32 minterProxySalt;
    address factoryAddress;
    address deployerAddress;
}

/**
 * @title EnvSelector
 * @notice Helper contract to select environment configuration based on ENV variable
 * @dev Provides configuration for different deployment environments (SMOKEBOX, SANDBOX, PROD)
 *      The environment is selected by setting the ENV environment variable before running the script
 *      Default environment is SMOKEBOX if ENV is not specified
 */
contract EnvSelector is Script {
    /**
     * @notice Get configuration for the selected environment
     * @dev Reads ENV environment variable and returns the appropriate configuration
     * @return EnvConfig struct containing environment-specific parameters
     */
    function getEnvironmentConfig() public view returns (EnvConfig memory) {
        // Read environment from forge environment variable, default to SMOKEBOX
        string memory env = vm.envOr("ENV", string("SMOKEBOX"));
        console.log("Selected environment:", env);

        // Select environment configuration based on ENV value
        if (keccak256(bytes(env)) == keccak256(bytes("PROD"))) {
            return getProdConfig();
        } else if (keccak256(bytes(env)) == keccak256(bytes("SANDBOX"))) {
            return getSandboxConfig();
        } else {
            return getSmokeboxConfig();
        }
    }

    /**
     * @notice Get configuration for the SMOKEBOX environment
     * @dev Salt value for SMOKEBOX is 0, addresses read from environment variables
     * @return EnvConfig with SMOKEBOX-specific values
     */
    function getSmokeboxConfig() public view returns (EnvConfig memory) {
        // Read SMOKEBOX specific addresses from environment variables
        address create2Factory = vm.envAddress("CREATE2_FACTORY_ADDRESS");
        address deployer = vm.envAddress("DEPLOYER_ADDRESS");

        return EnvConfig({
            salt: Constants.SMOKEBOX_SALT,
            walletProxySalt: Constants.SMOKEBOX_WALLET_PROXY_SALT,
            minterProxySalt: Constants.SMOKEBOX_MINTER_PROXY_SALT,
            factoryAddress: create2Factory,
            deployerAddress: deployer
        });
    }

    /**
     * @notice Get configuration for the SANDBOX environment
     * @dev Salt value for SANDBOX is 1
     * @return EnvConfig with SANDBOX-specific values
     */
    function getSandboxConfig() public pure returns (EnvConfig memory) {
        return EnvConfig({
            salt: Constants.SANDBOX_SALT,
            walletProxySalt: Constants.SANDBOX_WALLET_PROXY_SALT,
            minterProxySalt: Constants.SANDBOX_MINTER_PROXY_SALT,
            factoryAddress: Constants.SANDBOX_CREATE2FACTORY_ADDRESS,
            deployerAddress: Constants.SANDBOX_DEPLOYER_ADDRESS
        });
    }

    /**
     * @notice Get configuration for the PROD environment
     * @dev Salt value for PROD is 2
     * @return EnvConfig with PROD-specific values
     */
    function getProdConfig() public pure returns (EnvConfig memory) {
        return EnvConfig({
            salt: Constants.PROD_SALT,
            walletProxySalt: Constants.PROD_WALLET_PROXY_SALT,
            minterProxySalt: Constants.PROD_MINTER_PROXY_SALT,
            factoryAddress: Constants.PROD_CREATE2FACTORY_ADDRESS,
            deployerAddress: Constants.PROD_DEPLOYER_ADDRESS
        });
    }
}
