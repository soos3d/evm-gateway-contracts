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

import {CommonBase} from "forge-std/Base.sol";
import {MasterMinter} from "../mock_fiattoken/contracts/minting/MasterMinter.sol";
import {FiatTokenProxy} from "../mock_fiattoken/contracts/v1/FiatTokenProxy.sol";
import {FiatTokenV2_2} from "../mock_fiattoken/contracts/v2/FiatTokenV2_2.sol";
import {DeployFiatToken} from "../mock_fiattoken/deploy-fiat-token.s.sol";

// Contract to deploy mock FiatToken (USDC) contract for local testing. Copied with minor modification from @circlefin/stablecoin-evm/test/scripts/deploy/TestUtils.sol
contract DeployMockFiatToken is CommonBase {
    uint256 internal deployerPrivateKey = 1;
    uint256 internal proxyAdminPrivateKey = 2;
    uint256 internal masterMinterOwnerPrivateKey = 3;
    uint256 internal ownerPrivateKey = 4;
    uint256 internal pauserPrivateKey = 5;
    uint256 internal blacklisterPrivateKey = 6;

    address public deployer = vm.addr(deployerPrivateKey);
    address public proxyAdmin = vm.addr(proxyAdminPrivateKey);
    address public masterMinterOwner = vm.addr(masterMinterOwnerPrivateKey);
    address public owner = vm.addr(ownerPrivateKey);
    address public pauser = vm.addr(pauserPrivateKey);
    address public blacklister = vm.addr(blacklisterPrivateKey);

    uint8 internal decimals = 6;
    string internal tokenName = "USDC";
    string internal tokenSymbol = "USDC";
    string internal tokenCurrency = "USD";

    DeployFiatToken private deployScript;

    function setUpMockFiatTokenConfig() private {
        vm.setEnv("TOKEN_NAME", tokenName);
        vm.setEnv("TOKEN_SYMBOL", tokenSymbol);
        vm.setEnv("TOKEN_CURRENCY", tokenCurrency);
        vm.setEnv("TOKEN_DECIMALS", "6");
        vm.setEnv("DEPLOYER_PRIVATE_KEY", vm.toString(deployerPrivateKey));
        vm.setEnv("PROXY_ADMIN_ADDRESS", vm.toString(proxyAdmin));
        vm.setEnv("MASTER_MINTER_OWNER_ADDRESS", vm.toString(masterMinterOwner));
        vm.setEnv("OWNER_ADDRESS", vm.toString(owner));
        vm.setEnv("PAUSER_ADDRESS", vm.toString(pauser));
        vm.setEnv("BLACKLISTER_ADDRESS", vm.toString(blacklister));

        // Deploy an instance of proxy contract to configure contract address in env
        vm.prank(deployer);
        FiatTokenV2_2 v2_2 = new FiatTokenV2_2();

        vm.prank(proxyAdmin);
        FiatTokenProxy proxy = new FiatTokenProxy(address(v2_2));

        vm.startPrank(deployer);
        MasterMinter masterMinter = new MasterMinter(address(proxy));
        masterMinter.transferOwnership(masterMinterOwner);

        FiatTokenV2_2 proxyAsV2_2 = FiatTokenV2_2(address(proxy));

        proxyAsV2_2.initialize(
            tokenName,
            tokenSymbol,
            "USD",
            decimals,
            address(masterMinter),
            pauser,
            blacklister,
            vm.addr(ownerPrivateKey)
        );
        proxyAsV2_2.initializeV2(tokenName);
        proxyAsV2_2.initializeV2_1(owner);
        proxyAsV2_2.initializeV2_2(new address[](0), tokenSymbol);
        vm.setEnv("FIAT_TOKEN_PROXY_ADDRESS", vm.toString(address(proxy)));

        vm.stopPrank();
    }

    function deploy() public returns (FiatTokenV2_2, MasterMinter, FiatTokenProxy) {
        setUpMockFiatTokenConfig();

        vm.prank(deployer);
        deployScript = new DeployFiatToken();
        deployScript.setUp();
        return deployScript.run();
    }
}
