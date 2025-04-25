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

import {Test} from "forge-std/Test.sol";

/// Ensures the correct version of Foundry is installed
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
