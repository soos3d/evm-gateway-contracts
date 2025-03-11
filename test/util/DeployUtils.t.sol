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

import {UpgradeablePlaceholder} from "src/UpgradeablePlaceholder.sol";
import {SpendWallet} from "src/SpendWallet.sol";
import {SpendMinter} from "src/SpendMinter.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {Test} from "forge-std/src/Test.sol";

contract TestDeployUtils is Test, DeployUtils {
    address private owner = makeAddr("owner");

    function test_deployPlaceholder() external {
        UpgradeablePlaceholder placeholder = deployPlaceholder(owner);

        assertNotEq(address(placeholder), address(0));
        assertEq(placeholder.owner(), owner);
    }

    function test_deployPlaceholderWithoutInitializing() external {
        UpgradeablePlaceholder placeholder = deployPlaceholderWithoutInitializing();

        assertNotEq(address(placeholder), address(0));
        assertEq(placeholder.owner(), address(0));
    }

    function test_deploy() external {
        (SpendWallet wallet, SpendMinter minter) = deploy(owner);

        assertNotEq(address(wallet), address(0));
        assertNotEq(address(minter), address(0));
        assertEq(wallet.owner(), owner);
        assertEq(minter.owner(), owner);
        assert(!wallet.paused());
        assert(!minter.paused());
        assertEq(address(wallet.minterContract()), address(minter));
        assertEq(address(minter.walletContract()), address(wallet));
    }

    function test_deployWalletOnly() external {
        SpendWallet wallet = deployWalletOnly(owner);

        assertNotEq(address(wallet), address(0));
        assertEq(wallet.owner(), owner);
        assert(!wallet.paused());
        assertEq(address(wallet.minterContract()), address(0));
    }

    function test_deployMinterOnly() external {
        SpendMinter minter = deployMinterOnly(owner);

        assertNotEq(address(minter), address(0));
        assertEq(minter.owner(), owner);
        assert(!minter.paused());
        assertEq(address(minter.walletContract()), address(0));
    }
}
