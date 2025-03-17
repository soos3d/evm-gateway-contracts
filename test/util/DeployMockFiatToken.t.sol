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

import {Test} from "forge-std/Test.sol";
import {DeployMockFiatToken} from "./DeployMockFiatToken.sol";
import {FiatTokenV2_2} from "../mock_fiattoken/contracts/v2/FiatTokenV2_2.sol";
import {MasterMinter} from "../mock_fiattoken/contracts/minting/MasterMinter.sol";
import {FiatTokenProxy} from "../mock_fiattoken/contracts/v1/FiatTokenProxy.sol";
import {ForkTestUtils} from "./ForkTestUtils.sol";

contract TestDeployMockFiatToken is Test {
    DeployMockFiatToken private mockTokenDeployer;

    function setUp() public {
        mockTokenDeployer = new DeployMockFiatToken();
    }
    
    function test_deployMockFiatToken() public {
        vm.skip(block.chainid != ForkTestUtils.LOCAL_CHAIN_ID);
        (
            FiatTokenV2_2 v2_2,
            MasterMinter masterMinter,
            FiatTokenProxy proxy
        ) = mockTokenDeployer.deploy();

        validateImpl(v2_2);
        validateMasterMinter(masterMinter, address(proxy));
        validateProxy(proxy, address(v2_2), address(masterMinter));
    }

    function validateImpl(FiatTokenV2_2 impl) view internal {
        assertEq(impl.name(), "");
        assertEq(impl.symbol(), "");
        assertEq(impl.currency(), "");
        assert(impl.decimals() == 0);
        assertEq(impl.owner(), address(1));
        assertEq(impl.masterMinter(), address(1));
        assertEq(impl.pauser(), address(1));
        assertEq(impl.blacklister(), address(1));
    }

    function validateProxy(
        FiatTokenProxy proxy,
        address _impl,
        address _masterMinter
    ) view internal {
        assertEq(proxy.admin(), mockTokenDeployer.proxyAdmin());
        assertEq(proxy.implementation(), _impl);

        FiatTokenV2_2 proxyAsV2_2 = FiatTokenV2_2(address(proxy));
        assertEq(proxyAsV2_2.name(), "USDC");
        assertEq(proxyAsV2_2.symbol(), "USDC");
        assertEq(proxyAsV2_2.currency(), "USD");
        assert(proxyAsV2_2.decimals() == 6);
        assertEq(proxyAsV2_2.owner(), mockTokenDeployer.owner());
        assertEq(proxyAsV2_2.pauser(), mockTokenDeployer.pauser());
        assertEq(proxyAsV2_2.blacklister(), mockTokenDeployer.blacklister());
        assertEq(proxyAsV2_2.masterMinter(), _masterMinter);
    }

    function validateMasterMinter(MasterMinter masterMinter, address _proxy) view internal {
        assertEq(masterMinter.owner(), mockTokenDeployer.masterMinterOwner());
        assertEq(address(masterMinter.getMinterManager()), _proxy);
    }
}