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

import {console} from "forge-std/console.sol";
import {Script} from "forge-std/Script.sol";

/**
 * @title Constants
 * @notice Library containing environment-specific constants for deployment
 * @dev Defines constants for three environments: TESTNET_STAGING, TESTNET_PROD and MAINNET_PROD
 */
library Constants {
    // Testnet staging environment constants
    bytes32 internal constant TESTNET_STAGING_WALLET_SALT = bytes32(uint256(0));
    bytes32 internal constant TESTNET_STAGING_MINTER_SALT = bytes32(uint256(1));
    bytes32 internal constant TESTNET_STAGING_WALLET_PROXY_SALT =
        0x9cbda7e0f6d60dec396dc2343f58a33bf719a7ea38821e529c66dd5dbfe97323;
    bytes32 internal constant TESTNET_STAGING_MINTER_PROXY_SALT =
        0xdd1b1b4c40f09a6d41d3ed71ce3dd136b2e261a5a032ede31264165084c36760;
    address internal constant TESTNET_STAGING_CREATE2FACTORY_ADDRESS = 0x643151056F7cCCD36030d6507a8C07Ed4a46E8D2;
    address internal constant TESTNET_STAGING_DEPLOYER_ADDRESS = 0xD1e4098de8667a491Eb2Bf5acf09ED7F67260BCA;

    // Testnet prod environment constants
    bytes32 internal constant TESTNET_PROD_WALLET_SALT = bytes32(uint256(2));
    bytes32 internal constant TESTNET_PROD_MINTER_SALT = bytes32(uint256(3));
    bytes32 internal constant TESTNET_PROD_WALLET_PROXY_SALT =
        0x21bb75deb372a377707a6372a4c1137cec94e9425f0562e95f94eeb0763f7ee6;
    bytes32 internal constant TESTNET_PROD_MINTER_PROXY_SALT =
        0xa7aec328d70f1bf388addc85467318c00d67f2387dd11b7e29404091c4bcb51b;
    address internal constant TESTNET_PROD_CREATE2FACTORY_ADDRESS = 0x643151056F7cCCD36030d6507a8C07Ed4a46E8D2;
    address internal constant TESTNET_PROD_DEPLOYER_ADDRESS = 0xD1e4098de8667a491Eb2Bf5acf09ED7F67260BCA;

    // Mainnet prod environment constants
    bytes32 internal constant MAINNET_PROD_WALLET_SALT = bytes32(uint256(4));
    bytes32 internal constant MAINNET_PROD_MINTER_SALT = bytes32(uint256(5));
    bytes32 internal constant MAINNET_PROD_WALLET_PROXY_SALT =
        0x7ca52db4fc3f0e0f1f0af08e43e70f149bfbe314de9a1ab13acbe1fc122e8238;
    bytes32 internal constant MAINNET_PROD_MINTER_PROXY_SALT =
        0x6df87339f2bf63538063427ae112ca61dad04e4d35f7f4984fa3f924f7207d67;
    address internal constant MAINNET_PROD_CREATE2FACTORY_ADDRESS = 0xe7b84D8846c96Bb83155Da5537625c75e42d6E42;
    address internal constant MAINNET_PROD_DEPLOYER_ADDRESS = 0xadB384F7fa7486422051D2a896417EAAb9E5A9D1;
}

/**
 * @title EnvConfig
 * @notice Configuration struct that holds all environment-specific parameters
 * @dev Used to pass environment configuration between contracts in a structured way
 * @param walletSalt The base salt value used for non proxy contract deployment
 * @param minterSalt The base salt value used for non proxy contract deployment
 * @param walletProxySalt The salt value used for GatewayWallet proxy deployment
 * @param minterProxySalt The salt value used for GatewayMinter proxy deployment
 * @param factoryAddress The CREATE2 factory address for deterministic deployment
 * @param deployerAddress The address that will deploy the contracts
 */
struct EnvConfig {
    bytes32 walletSalt;
    bytes32 minterSalt;
    bytes32 walletProxySalt;
    bytes32 minterProxySalt;
    address factoryAddress;
    address deployerAddress;
}

/**
 * @title EnvSelector
 * @notice Helper contract to select environment configuration based on ENV variable
 * @dev Provides configuration for different deployment environments (TESTNET_STAGING, TESTNET_PROD, MAINNET_PROD)
 *      The environment is selected by setting the ENV environment variable before running the script
 *      Default environment is TESTNET_STAGING if ENV is not specified
 */
contract EnvSelector is Script {
    /**
     * @notice Get configuration for the selected environment
     * @dev Reads ENV environment variable and returns the appropriate configuration
     * @return EnvConfig struct containing environment-specific parameters
     */
    function getEnvironmentConfig() public view returns (EnvConfig memory) {
        // Read environment from forge environment variable, default to SMOKEBOX
        string memory env = vm.envOr("ENV", string("TESTNET_STAGING"));
        console.log("Selected environment:", env);

        // Select environment configuration based on ENV value
        if (keccak256(bytes(env)) == keccak256(bytes("MAINNET_PROD"))) {
            return getMainnetProdConfig();
        } else if (keccak256(bytes(env)) == keccak256(bytes("TESTNET_PROD"))) {
            return getTestnetProdConfig();
        } else if (keccak256(bytes(env)) == keccak256(bytes("TESTNET_STAGING"))) {
            return getTestnetStagingConfig();
        } else {
            return getLocalConfig();
        }
    }

    /**
     * @notice Get configuration for the local environment
     * @dev Addresses read from environment variables
     * @return EnvConfig with local development values
     */
    function getLocalConfig() public view returns (EnvConfig memory) {
        // For testing purposes, we must override the factory address and deployer address
        address testCreate2Factory = vm.envAddress("TEST_ONLY_CREATE2_FACTORY_ADDRESS");
        address testDeployer = vm.envAddress("TEST_ONLY_DEPLOYER_ADDRESS");

        return EnvConfig({
            walletSalt: Constants.TESTNET_STAGING_WALLET_SALT,
            minterSalt: Constants.TESTNET_STAGING_MINTER_SALT,
            walletProxySalt: Constants.TESTNET_STAGING_WALLET_PROXY_SALT,
            minterProxySalt: Constants.TESTNET_STAGING_MINTER_PROXY_SALT,
            factoryAddress: testCreate2Factory != address(0)
                ? testCreate2Factory
                : Constants.TESTNET_STAGING_CREATE2FACTORY_ADDRESS,
            deployerAddress: testDeployer != address(0) ? testDeployer : Constants.TESTNET_STAGING_DEPLOYER_ADDRESS
        });
    }

    /**
     * @notice Get configuration for the TESTNET_STAGING environment
     * @dev Salt value for TESTNET_STAGING is 0
     * @return EnvConfig with TESTNET_STAGING-specific values
     */
    function getTestnetStagingConfig() public pure returns (EnvConfig memory) {
        return EnvConfig({
            walletSalt: Constants.TESTNET_STAGING_WALLET_SALT,
            minterSalt: Constants.TESTNET_STAGING_MINTER_SALT,
            walletProxySalt: Constants.TESTNET_STAGING_WALLET_PROXY_SALT,
            minterProxySalt: Constants.TESTNET_STAGING_MINTER_PROXY_SALT,
            factoryAddress: Constants.TESTNET_STAGING_CREATE2FACTORY_ADDRESS,
            deployerAddress: Constants.TESTNET_STAGING_DEPLOYER_ADDRESS
        });
    }

    /**
     * @notice Get configuration for the TESTNET_PROD environment
     * @dev Salt value for TESTNET_PROD is 1
     * @return EnvConfig with TESTNET_PROD-specific values
     */
    function getTestnetProdConfig() public pure returns (EnvConfig memory) {
        return EnvConfig({
            walletSalt: Constants.TESTNET_PROD_WALLET_SALT,
            minterSalt: Constants.TESTNET_PROD_MINTER_SALT,
            walletProxySalt: Constants.TESTNET_PROD_WALLET_PROXY_SALT,
            minterProxySalt: Constants.TESTNET_PROD_MINTER_PROXY_SALT,
            factoryAddress: Constants.TESTNET_PROD_CREATE2FACTORY_ADDRESS,
            deployerAddress: Constants.TESTNET_PROD_DEPLOYER_ADDRESS
        });
    }

    /**
     * @notice Get configuration for the PROD environment
     * @dev Salt value for PROD is 2
     * @return EnvConfig with PROD-specific values
     */
    function getMainnetProdConfig() public pure returns (EnvConfig memory) {
        return EnvConfig({
            walletSalt: Constants.MAINNET_PROD_WALLET_SALT,
            minterSalt: Constants.MAINNET_PROD_MINTER_SALT,
            walletProxySalt: Constants.MAINNET_PROD_WALLET_PROXY_SALT,
            minterProxySalt: Constants.MAINNET_PROD_MINTER_PROXY_SALT,
            factoryAddress: Constants.MAINNET_PROD_CREATE2FACTORY_ADDRESS,
            deployerAddress: Constants.MAINNET_PROD_DEPLOYER_ADDRESS
        });
    }
}
