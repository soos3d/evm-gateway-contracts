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

import {Test} from "forge-std/Test.sol";
import {Domain} from "src/modules/common/Domain.sol";

contract DomainHarness is Domain {
    function initialize(uint32 domain) public initializer {
        __Domain_init(domain);
    }

    // Wraps the internal _isCurrentDomain function for testing
    function isCurrentDomain(uint32 domain) public view returns (bool) {
        return _isCurrentDomain(domain);
    }
}

contract DomainTest is Test {
    uint32 private testDomain = 99;

    DomainHarness private domainHarness;

    function setUp() public {
        domainHarness = new DomainHarness();
    }

    function test_initializeNonZeroDomain() public {
        assertEq(domainHarness.domain(), 0, "Domain should be 0 before initialization.");
        assertTrue(domainHarness.isCurrentDomain(0), "Domain should be 0 before initialization.");
        domainHarness.initialize(testDomain);
        assertEq(domainHarness.domain(), testDomain, "Domain should be set to the initialized domain.");
        assertTrue(domainHarness.isCurrentDomain(testDomain), "Domain should be set to the initialized domain.");
    }

    function test_initializeZeroDomain() public {
        assertEq(domainHarness.domain(), 0, "Domain should be 0 before initialization.");
        assertTrue(domainHarness.isCurrentDomain(0), "Domain should be 0 before initialization.");
        domainHarness.initialize(0);
        assertEq(domainHarness.domain(), 0, "Domain should still be 0 after initialization.");
        assertTrue(domainHarness.isCurrentDomain(0), "Domain should still be 0 after initialization.");
    }
}
