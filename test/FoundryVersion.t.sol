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

import {Test} from "forge-std/src/Test.sol";

contract TestFoundryVersion is Test {
    string private constant EXPECTED_VERSION = "1.0.0";

    function test() external view {
        // Returns something like "1.0.0-v1.0.0+8692e92619.1739178359.maxperf"
        string memory fullVersion = vm.getFoundryVersion();
        bytes memory fullVersionBytes = bytes(fullVersion);

        uint256 versionPrefixLength;
        for (uint256 i = 0; i < fullVersionBytes.length; i++) {
            bytes1 char = fullVersionBytes[i];
            if (char == bytes1("+") || char == bytes1("-")) {
                versionPrefixLength = i;
                break;
            }
        }

        assertGt(versionPrefixLength, 0, "Unexpected version format");

        bytes memory versionPrefixBytes = new bytes(versionPrefixLength);
        for (uint256 i = 0; i < versionPrefixBytes.length; i++) {
            versionPrefixBytes[i] = fullVersionBytes[i];
        }

        string memory versionPrefix = string(versionPrefixBytes);

        assertEq(versionPrefix, EXPECTED_VERSION, "Wrong version of foundry, please install the right version");
    }
}
