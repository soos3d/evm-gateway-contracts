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
pragma solidity ^0.8.29;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CommonBase} from "forge-std/Base.sol";
import {SpendMinter} from "src/SpendMinter.sol";
import {SpendWallet} from "src/SpendWallet.sol";
import {UpgradeablePlaceholder} from "src/UpgradeablePlaceholder.sol";

/// Helpers for deploying the contracts during tests
abstract contract DeployUtils is CommonBase {
    function deploy(address owner, uint32 domain) public returns (SpendWallet, SpendMinter) {
        // Deploy both placeholders
        UpgradeablePlaceholder walletProxy = deployPlaceholder(owner);
        UpgradeablePlaceholder minterProxy = deployPlaceholder(owner);

        // Deploy both implementation contracts
        SpendWallet walletImpl = new SpendWallet();
        SpendMinter minterImpl = new SpendMinter();

        // Upgrade both placeholders and tell them about each other
        vm.prank(owner);
        walletProxy.upgradeToAndCall(
            address(walletImpl), abi.encodeCall(SpendWallet.initialize, (address(minterProxy), domain))
        );
        vm.prank(owner);
        minterProxy.upgradeToAndCall(
            address(minterImpl), abi.encodeCall(SpendMinter.initialize, (address(walletProxy), domain))
        );
        vm.stopPrank();

        // Return the upgraded proxies
        SpendWallet wallet = SpendWallet(address(walletProxy));
        SpendMinter minter = SpendMinter(address(minterProxy));
        return (wallet, minter);
    }

    function deployWalletOnly(address owner, uint32 domain) public returns (SpendWallet) {
        UpgradeablePlaceholder walletProxy = deployPlaceholder(owner);
        SpendWallet walletImpl = new SpendWallet();
        vm.prank(owner);
        walletProxy.upgradeToAndCall(address(walletImpl), abi.encodeCall(SpendWallet.initialize, (address(0), domain)));
        return SpendWallet(address(walletProxy));
    }

    function deployMinterOnly(address owner, uint32 domain) public returns (SpendMinter) {
        UpgradeablePlaceholder minterProxy = deployPlaceholder(owner);
        SpendMinter minterImpl = new SpendMinter();
        vm.prank(owner);
        minterProxy.upgradeToAndCall(address(minterImpl), abi.encodeCall(SpendMinter.initialize, (address(0), domain)));
        return SpendMinter(address(minterProxy));
    }

    function deployPlaceholder(address owner) public returns (UpgradeablePlaceholder) {
        return _deployPlaceholder(abi.encodeCall(UpgradeablePlaceholder.initialize, owner));
    }

    function deployPlaceholderWithoutInitializing() public returns (UpgradeablePlaceholder) {
        return _deployPlaceholder(new bytes(0));
    }

    function _deployPlaceholder(bytes memory initData) private returns (UpgradeablePlaceholder) {
        UpgradeablePlaceholder placeholder = new UpgradeablePlaceholder();
        ERC1967Proxy proxy = new ERC1967Proxy(address(placeholder), initData);
        return UpgradeablePlaceholder(address(proxy));
    }
}
