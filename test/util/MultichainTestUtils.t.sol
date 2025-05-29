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

import {MultichainTestUtils} from "test/util/MultichainTestUtils.sol";

contract MultichainTestUtilsTest is MultichainTestUtils {
    function test_forkSelectionReturnsExpectedFork() public {
        string memory chainName = "ethereum";
        ChainSetup memory setup = _initializeGatewayContracts(chainName);

        // Select the fork and verify
        vm.selectFork(setup.forkId);
        assertEq(vm.activeFork(), setup.forkId);
        assertEq(block.chainid, 1);
    }

    function test_initializeGatewayContracts_setsUpGatewayContractState() public {
        string memory chainName = "ethereum";
        ChainSetup memory setup = _initializeGatewayContracts(chainName);

        // Verify both wallet and minter are persistent
        assert(vm.isPersistent(address(setup.wallet)));
        assert(vm.isPersistent(address(setup.minter)));

        // Verify wallet configuration
        assertTrue(setup.wallet.isBurnSigner(vm.addr(setup.walletBurnSignerKey)));
        assertTrue(setup.minter.isAttestationSigner(vm.addr(setup.minterAttestationSignerKey)));
        assertEq(setup.wallet.withdrawalDelay(), WITHDRAW_DELAY);
        assertTrue(setup.wallet.isTokenSupported(address(setup.usdc)));
        assertTrue(setup.minter.isTokenSupported(address(setup.usdc)));
        assertEq(setup.minter.tokenMintAuthority(address(setup.usdc)), address(setup.usdc));

        // Verify both contracts are configured as USDC minters
        assertTrue(setup.usdc.isMinter(address(setup.wallet)));
        assertEq(setup.usdc.minterAllowance(address(setup.minter)), type(uint256).max);
        assertTrue(setup.usdc.isMinter(address(setup.minter)));
        assertEq(setup.usdc.minterAllowance(address(setup.wallet)), 0);
    }
}
