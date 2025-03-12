/*
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.

 * SPDX-License-Identifier: GPL-3.0-or-later

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
pragma solidity ^0.8.28;

/// Helpers for managing values and dependencies between forks
library ForkTestUtils {
    error UnknownChain(uint256 id);

    uint256 public constant LOCAL_CHAIN_ID = 31337;
    uint256 public constant ETHEREUM_CHAIN_ID = 1;
    uint256 public constant ETHEREUM_SEPOLIA_CHAIN_ID = 11155111;
    uint256 public constant ARBITRUM_CHAIN_ID = 42161;
    uint256 public constant ARBITRUM_SEPOLIA_CHAIN_ID = 421614;
    uint256 public constant BASE_CHAIN_ID = 8453;
    uint256 public constant BASE_SEPOLIA_CHAIN_ID = 84532;

    struct ForkVars {
        address usdc;
    }

    function forkVars() public view returns (ForkVars memory) {
        if (block.chainid == LOCAL_CHAIN_ID) {
            return deployLocalDependencies();
        }

        if (block.chainid == ETHEREUM_CHAIN_ID) {
            return ForkVars({usdc: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48});
        }

        if (block.chainid == ETHEREUM_SEPOLIA_CHAIN_ID) {
            return ForkVars({usdc: 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238});
        }

        if (block.chainid == ARBITRUM_CHAIN_ID) {
            return ForkVars({usdc: 0xaf88d065e77c8cC2239327C5EDb3A432268e5831});
        }

        if (block.chainid == ARBITRUM_SEPOLIA_CHAIN_ID) {
            return ForkVars({usdc: 0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d});
        }

        if (block.chainid == BASE_CHAIN_ID) {
            return ForkVars({usdc: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913});
        }

        if (block.chainid == BASE_SEPOLIA_CHAIN_ID) {
            return ForkVars({usdc: 0x036CbD53842c5426634e7929541eC2318f3dCF7e});
        }

        revert UnknownChain(block.chainid);
    }

    function deployLocalDependencies() public pure returns (ForkVars memory) {
        // TODO: deploy mock version of USDC and return its address
        return ForkVars({usdc: address(0)});
    }
}
