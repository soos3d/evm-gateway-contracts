/*
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.

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

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UpgradeablePlaceholder} from "src/UpgradeablePlaceholder.sol";
import {SpendWallet} from "src/SpendWallet.sol";
import {SpendMinter} from "src/SpendMinter.sol";
import {CommonBase} from "forge-std/Base.sol";

/// Helpers for deploying the contracts during tests
abstract contract DeployUtils is CommonBase {
    function deploy(address owner) public returns (SpendWallet, SpendMinter) {
        // Deploy both placeholders
        UpgradeablePlaceholder walletProxy = deployPlaceholder(owner);
        UpgradeablePlaceholder minterProxy = deployPlaceholder(owner);

        // Deploy both implementation contracts
        SpendWallet walletImpl = new SpendWallet();
        SpendMinter minterImpl = new SpendMinter();

        // Upgrade both placeholders and tell them about each other
        vm.prank(owner);
        walletProxy.upgradeToAndCall(address(walletImpl), abi.encodeCall(SpendWallet.initialize, address(minterProxy)));
        vm.prank(owner);
        minterProxy.upgradeToAndCall(address(minterImpl), abi.encodeCall(SpendMinter.initialize, address(walletProxy)));
        vm.stopPrank();

        // Return the upgraded proxies
        SpendWallet wallet = SpendWallet(address(walletProxy));
        SpendMinter minter = SpendMinter(address(minterProxy));
        return (wallet, minter);
    }

    function deployWalletOnly(address owner) public returns (SpendWallet) {
        UpgradeablePlaceholder walletProxy = deployPlaceholder(owner);
        SpendWallet walletImpl = new SpendWallet();
        vm.prank(owner);
        walletProxy.upgradeToAndCall(address(walletImpl), abi.encodeCall(SpendWallet.initialize, address(0)));
        return SpendWallet(address(walletProxy));
    }

    function deployMinterOnly(address owner) public returns (SpendMinter) {
        UpgradeablePlaceholder minterProxy = deployPlaceholder(owner);
        SpendMinter minterImpl = new SpendMinter();
        vm.prank(owner);
        minterProxy.upgradeToAndCall(address(minterImpl), abi.encodeCall(SpendMinter.initialize, address(0)));
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
