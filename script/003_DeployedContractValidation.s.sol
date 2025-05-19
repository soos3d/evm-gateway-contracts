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

/// @title DeployedContractValidation
/// @notice Script to verify deployed contract bytecode matches expected bytecode and contract state matches expected
///         values
contract DeployedContractValidation is Script {
    /// @notice Verifies bytecode of a deployed contract against expected bytecode
    /// @param deployedAddress Address of the deployed contract to verify
    /// @param contractName Name of the contract artifact in scripts/compiled-contract-artifacts/
    /// @return success True if the bytecode matches
    function verifyContractBytecode(address deployedAddress, string memory contractName)
        public
        view
        returns (bool success)
    {
        // Get the deployed bytecode
        bytes memory deployedCode = deployedAddress.code;

        // When a contract inherits from UUPSUpgradeable which sets address(this) to an immutable address field,
        // Foundry compiled artifact uses `address(0)` while the actual bytecode uses the deployed address.
        // This is a problem because the bytecode will not match.
        // We need to manually replace the deployed address in the bytecode with all zeros.
        for (uint256 i = 0; i < deployedCode.length - 20; i++) {
            // Check if the next 20 bytes match the address pattern
            // We need to manually extract and compare the bytes instead of using slice notation
            bytes memory chunk = new bytes(20);
            for (uint256 k = 0; k < 20; k++) {
                chunk[k] = deployedCode[i + k];
            }

            if (keccak256(chunk) == keccak256(abi.encodePacked(deployedAddress))) {
                // Zero out the address bytes to match the expected bytecode
                for (uint256 j = 0; j < 20; j++) {
                    deployedCode[i + j] = bytes1(0);
                }
            }
        }
        bytes32 deployedCodeHash = keccak256(deployedCode);

        // Get the expected bytecode from the compiled artifact
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/script/compiled-contract-artifacts/", contractName, ".json");
        string memory json = vm.readFile(path);
        bytes memory expectedBytecode = abi.decode(vm.parseJson(json, ".deployedBytecode.object"), (bytes));

        bytes32 expectedCodeHash = keccak256(expectedBytecode);

        // Check if bytecode matches
        if (expectedCodeHash != deployedCodeHash) {
            return false;
        }
        return true;
    }

    /// @notice Verifies a contract state value from a contract against expected value
    /// @param deployedAddress Address of the contract to query
    /// @param functionSignature Function signature to call (e.g., "domain()")
    /// @param encodedFunctionParameter Encoded function parameter to pass (e.g., abi.encode(vm.envAddress("GATEWAYMINTER_SUPPORTED_TOKEN_1")))
    /// @param expectedValue Expected return value
    function verifyContractStateValue(
        address deployedAddress,
        string memory functionSignature,
        bytes memory encodedFunctionParameter,
        bytes memory expectedValue
    ) public {
        // Call the function on the deployed contract
        (bool callSuccess, bytes memory returnData) = deployedAddress.call(
            abi.encodePacked(bytes4(keccak256(bytes(functionSignature))), encodedFunctionParameter)
        );
        require(callSuccess, string(abi.encodePacked("Function call failed: ", functionSignature)));

        // Check if values match
        require(keccak256(expectedValue) == keccak256(returnData), "Value verification failed");
    }

    /// @notice Example verification for GatewayMinter
    /// @param minterProxyAddress Address of the deployed GatewayMinter contract
    /// @param minterImplAddress Address of the deployed GatewayMinter implementation contract
    function verifyGatewayMinter(address minterProxyAddress, address minterImplAddress) public {
        // Verify bytecode
        bool bytecodeOk = verifyContractBytecode(minterProxyAddress, "ERC1967Proxy");
        require(bytecodeOk, "GatewayMinter proxy bytecode verification failed");

        bytecodeOk = verifyContractBytecode(minterImplAddress, "GatewayMinter");
        require(bytecodeOk, "GatewayMinter implementation bytecode verification failed");

        // Verify proxy implementation address matches expected implementation address
        bytes32 raw = vm.load(minterProxyAddress, bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1));
        address proxyImpl = address(uint160(uint256(raw)));
        require(proxyImpl == minterImplAddress, "GatewayMinter proxy implementation address verification failed");

        // Verify important state variables
        verifyContractStateValue(
            minterProxyAddress, "owner()", "", abi.encode(vm.envAddress("GATEWAYMINTER_OWNER_ADDRESS"))
        );
        verifyContractStateValue(
            minterProxyAddress, "pauser()", "", abi.encode(vm.envAddress("GATEWAYMINTER_PAUSER_ADDRESS"))
        );
        verifyContractStateValue(
            minterProxyAddress, "denylister()", "", abi.encode(vm.envAddress("GATEWAYMINTER_DENYLISTER_ADDRESS"))
        );
        verifyContractStateValue(
            minterProxyAddress,
            "isTokenSupported(address)",
            abi.encode(vm.envAddress("GATEWAYMINTER_SUPPORTED_TOKEN_1")),
            abi.encode(true)
        );
        verifyContractStateValue(minterProxyAddress, "domain()", "", abi.encode(vm.envUint("GATEWAYMINTER_DOMAIN")));
        verifyContractStateValue(
            minterProxyAddress, "attestationSigner()", "", abi.encode(vm.envAddress("GATEWAYMINTER_ATTESTATION_SIGNER"))
        );
        verifyContractStateValue(
            minterProxyAddress,
            "tokenMintAuthority(address)",
            abi.encode(vm.envAddress("GATEWAYMINTER_SUPPORTED_TOKEN_1")),
            abi.encode(vm.envAddress("GATEWAYMINTER_TOKEN_AUTH_1"))
        );
    }

    /// @notice Example verification for GatewayWallet
    /// @param walletProxyAddress Address of the deployed GatewayWallet contract
    /// @param walletImplAddress Address of the deployed GatewayWallet implementation contract
    function verifyGatewayWallet(address walletProxyAddress, address walletImplAddress) public {
        // Verify bytecode
        bool bytecodeOk = verifyContractBytecode(walletProxyAddress, "ERC1967Proxy");
        require(bytecodeOk, "GatewayWallet proxy bytecode verification failed");

        bytecodeOk = verifyContractBytecode(walletImplAddress, "GatewayWallet");
        require(bytecodeOk, "GatewayWallet implementation bytecode verification failed");

        // Verify proxy implementation address matches expected implementation address
        bytes32 raw = vm.load(walletProxyAddress, bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1));
        address proxyImpl = address(uint160(uint256(raw)));
        require(proxyImpl == walletImplAddress, "GatewayWallet proxy implementation address verification failed");

        // Verify important state variables
        verifyContractStateValue(
            walletProxyAddress, "owner()", "", abi.encode(vm.envAddress("GATEWAYWALLET_OWNER_ADDRESS"))
        );
        verifyContractStateValue(
            walletProxyAddress, "pauser()", "", abi.encode(vm.envAddress("GATEWAYWALLET_PAUSER_ADDRESS"))
        );
        verifyContractStateValue(
            walletProxyAddress, "denylister()", "", abi.encode(vm.envAddress("GATEWAYWALLET_DENYLISTER_ADDRESS"))
        );
        verifyContractStateValue(
            walletProxyAddress,
            "isTokenSupported(address)",
            abi.encode(vm.envAddress("GATEWAYWALLET_SUPPORTED_TOKEN_1")),
            abi.encode(true)
        );
        verifyContractStateValue(walletProxyAddress, "domain()", "", abi.encode(vm.envUint("GATEWAYWALLET_DOMAIN")));
        verifyContractStateValue(
            walletProxyAddress, "withdrawalDelay()", "", abi.encode(vm.envUint("GATEWAYWALLET_WITHDRAWAL_DELAY"))
        );
        verifyContractStateValue(
            walletProxyAddress, "burnSigner()", "", abi.encode(vm.envAddress("GATEWAYWALLET_BURNSIGNER_ADDRESS"))
        );
        verifyContractStateValue(
            walletProxyAddress, "feeRecipient()", "", abi.encode(vm.envAddress("GATEWAYWALLET_FEERECIPIENT_ADDRESS"))
        );
    }

    /// @notice Main run function for validation
    function run() public {
        // Load contract addresses from environment variables
        address minterProxyAddress = vm.envAddress("GATEWAYWALLET_MINTER_ADDRESS");
        address walletProxyAddress = vm.envAddress("GATEWAYMINTER_WALLET_ADDRESS");
        address minterImplAddress = vm.envAddress("GATEWAYMINTER_IMPL_ADDRESS");
        address walletImplAddress = vm.envAddress("GATEWAYWALLET_IMPL_ADDRESS");

        // Run all validations
        verifyGatewayMinter(minterProxyAddress, minterImplAddress);
        verifyGatewayWallet(walletProxyAddress, walletImplAddress);
    }
}
