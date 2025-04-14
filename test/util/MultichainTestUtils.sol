/*
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.

 * SPDX-License-Identifier: Apache-2.0

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
pragma solidity ^0.8.28;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {DeployUtils} from "./DeployUtils.sol";
import {ForkTestUtils} from "./ForkTestUtils.sol";
import {SpendWallet} from "src/SpendWallet.sol";
import {SpendMinter} from "src/SpendMinter.sol";
import {FiatTokenV2_2} from "../mock_fiattoken/contracts/v2/FiatTokenV2_2.sol";
import {MasterMinter} from "../mock_fiattoken/contracts/minting/MasterMinter.sol";
import {SignatureTestUtils} from "./SignatureTestUtils.sol";

contract MultichainTestUtils is DeployUtils, SignatureTestUtils {
    using MessageHashUtils for bytes32;

    // Based on Ethereum, assuming 12 seconds per block, 21,600 blocks in 3 days.
    uint256 public constant WITHDRAW_DELAY = (3 * 24 * 60 * 60) / 12;

    struct ChainSetup {
        uint256 forkId;
        uint32 domain;
        uint256 walletBurnSignerKey;
        uint256 minterMintSignerKey;
        SpendWallet wallet;
        SpendMinter minter;
        FiatTokenV2_2 usdc;
    }

    /// @dev Helper for setting up multi-chain test environments with SpendWallet and SpendMinter contracts
    /// @param chainName The name of the chain to fork, must match an RPC endpoint name in foundry.toml (e.g. "ethereum", "arbitrum")
    /// @return ChainSetup Struct containing all relevant contract instances and addresses
    function _initializeGatewayContracts(string memory chainName) internal returns (ChainSetup memory) {
        // Create and select fork for specified chain
        uint256 forkId = vm.createFork(vm.rpcUrl(chainName));
        vm.selectFork(forkId);

        FiatTokenV2_2 usdc = FiatTokenV2_2(ForkTestUtils.forkVars().usdc);
        uint32 domain = ForkTestUtils.forkVars().domain;

        // Generate role addresses based on chain ID
        uint256 chainId = block.chainid;
        address owner = vm.addr(chainId + 1);
        address walletFeeRecipient = vm.addr(chainId + 2);
        uint256 walletBurnSignerKey = chainId + 3;
        address walletBurnSigner = vm.addr(walletBurnSignerKey);
        uint256 minterMintSignerKey = chainId + 4;
        address minterMintSigner = vm.addr(minterMintSignerKey);

        // Deploy core contracts
        (SpendWallet wallet, SpendMinter minter) = deploy(owner, domain);
        vm.makePersistent(address(wallet));
        vm.makePersistent(address(minter));

        vm.startPrank(owner);
        {
            // Configure minter settings
            minter.addSupportedToken(address(usdc));
            minter.updateMintAuthorizationSigner(minterMintSigner);
            minter.updateMintAuthority(address(usdc), address(usdc));

            // Configure wallet settings
            wallet.addSupportedToken(address(usdc));
            wallet.updateBurnSigner(walletBurnSigner);
            wallet.updateFeeRecipient(walletFeeRecipient);
            wallet.updateWithdrawalDelay(WITHDRAW_DELAY);
        }
        vm.stopPrank();

        // Setup wallet and minter as USDC minter / burner
        MasterMinter masterMinter = MasterMinter(usdc.masterMinter());
        address masterMinterOwner = masterMinter.owner();

        vm.startPrank(masterMinterOwner);
        {
            // Configure minter with maximum allowance
            masterMinter.configureController(masterMinterOwner, address(minter));
            masterMinter.configureMinter(type(uint256).max);

            // Configure wallet with zero allowance (burn only)
            masterMinter.configureController(masterMinterOwner, address(wallet));
            masterMinter.configureMinter(0);
        }
        vm.stopPrank();

        return ChainSetup({
            forkId: forkId,
            domain: domain,
            walletBurnSignerKey: walletBurnSignerKey,
            minterMintSignerKey: minterMintSignerKey,
            wallet: wallet,
            minter: minter,
            usdc: usdc
        });
    }
}
