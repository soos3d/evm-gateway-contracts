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

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {SpendHashes} from "src/lib/common/SpendHashes.sol";
import {SpendSpec} from "src/lib/Authorizations.sol";

contract SpendHashesHarness is SpendHashes {
    function markSpendHashAsUsed(bytes32 spendHash) external {
        _markSpendHashAsUsed(spendHash);
    }

    function ensureSpendHashNotUsed(bytes32 spendHash) external view {
        _ensureSpendHashNotUsed(spendHash);
    }
}

contract UpgradeableSpendHashesHarness is SpendHashesHarness, UUPSUpgradeable {
    function _authorizeUpgrade(address) internal override {}
}

/// Tests the SpendHashes contract
contract SpendHashesTest is Test {
    SpendHashesHarness private spendHashes;

    function setUp() public {
        spendHashes = new SpendHashesHarness();
    }

    function _createFakeSpendSpec(uint256 seed) internal pure returns (SpendSpec memory) {
        return SpendSpec({
            version: 1,
            sourceDomain: 1,
            destinationDomain: 2,
            sourceToken: keccak256(abi.encode("sourceToken", seed)),
            destinationToken: keccak256(abi.encode("destinationToken", seed)),
            sourceSpender: keccak256(abi.encode("sourceSpender", seed)),
            sourceDepositor: keccak256(abi.encode("sourceDepositor", seed)),
            destinationRecipient: keccak256(abi.encode("destinationRecipient", seed)),
            destinationContract: keccak256(abi.encode("destinationContract", seed)),
            destinationCaller: keccak256(abi.encode("destinationCaller", seed)),
            value: seed,
            nonce: keccak256(abi.encode("nonce", seed)),
            metadata: abi.encode("metadata", seed)
        });
    }

    function _hashSpendSpec(SpendSpec memory spec) internal pure returns (bytes32) {
        return keccak256(abi.encode(spec));
    }

    function _deploySpendHashesProxy(address impl) internal returns (address) {
        ERC1967Proxy proxy = new ERC1967Proxy(impl, new bytes(0));
        return address(proxy);
    }

    function test_spendHashes_ensureSpendHashNotUsedSucceedsIfNewSpendHashFuzz(uint256 seed) public view {
        SpendSpec memory spec = _createFakeSpendSpec(seed);
        bytes32 spendHash = _hashSpendSpec(spec);
        spendHashes.ensureSpendHashNotUsed(spendHash);
    }

    function test_spendHashes_revertsIfSpendHashAlreadyUsedFuzz(uint256 seed) public {
        SpendSpec memory spec = _createFakeSpendSpec(seed);
        bytes32 spendHash = _hashSpendSpec(spec);

        spendHashes.markSpendHashAsUsed(spendHash);

        vm.expectRevert(abi.encodeWithSelector(SpendHashes.SpendHashUsed.selector, spendHash));
        spendHashes.ensureSpendHashNotUsed(spendHash);
    }

    function test_spendHashes_markSpendHashAsUsedIsIdempotentFuzz(uint256 seed) public {
        SpendSpec memory spec = _createFakeSpendSpec(seed);
        bytes32 spendHash = _hashSpendSpec(spec);

        spendHashes.markSpendHashAsUsed(spendHash);
        spendHashes.markSpendHashAsUsed(spendHash);

        vm.expectRevert(abi.encodeWithSelector(SpendHashes.SpendHashUsed.selector, spendHash));
        spendHashes.ensureSpendHashNotUsed(spendHash);
    }

    function test_spendHashes_markMultipleSpendHashesAsUsedFuzz(uint256 seed1, uint256 seed2) public {
        vm.assume(seed1 != seed2);
        SpendSpec memory spec1 = _createFakeSpendSpec(seed1);
        SpendSpec memory spec2 = _createFakeSpendSpec(seed2);
        bytes32 spendHash1 = _hashSpendSpec(spec1);
        bytes32 spendHash2 = _hashSpendSpec(spec2);

        spendHashes.markSpendHashAsUsed(spendHash1);
        spendHashes.markSpendHashAsUsed(spendHash2);

        vm.expectRevert(abi.encodeWithSelector(SpendHashes.SpendHashUsed.selector, spendHash1));
        spendHashes.ensureSpendHashNotUsed(spendHash1);

        vm.expectRevert(abi.encodeWithSelector(SpendHashes.SpendHashUsed.selector, spendHash2));
        spendHashes.ensureSpendHashNotUsed(spendHash2);
    }

    function test_spendHashes_persistsStorageAcrossUpgradesFuzz(uint256 seed) public {
        // Deploy implementation contracts
        UpgradeableSpendHashesHarness impl1 = new UpgradeableSpendHashesHarness();
        UpgradeableSpendHashesHarness impl2 = new UpgradeableSpendHashesHarness();

        // Deploy proxy directly with impl1 and initialize it
        address proxyAddr = _deploySpendHashesProxy(address(impl1));
        UpgradeableSpendHashesHarness proxyAsImpl = UpgradeableSpendHashesHarness(proxyAddr);

        SpendSpec memory spec = _createFakeSpendSpec(seed);
        bytes32 spendHash = _hashSpendSpec(spec);
        proxyAsImpl.markSpendHashAsUsed(spendHash);

        vm.expectRevert(abi.encodeWithSelector(SpendHashes.SpendHashUsed.selector, spendHash));
        proxyAsImpl.ensureSpendHashNotUsed(spendHash);

        // Upgrade to the second implementation
        proxyAsImpl.upgradeToAndCall(address(impl2), new bytes(0));

        // Check that the spend hash is still marked as used despite the upgrade
        vm.expectRevert(abi.encodeWithSelector(SpendHashes.SpendHashUsed.selector, spendHash));
        proxyAsImpl.ensureSpendHashNotUsed(spendHash);

        // Verify that implementation storage is not affected by the upgrade
        impl1.ensureSpendHashNotUsed(spendHash);
        impl2.ensureSpendHashNotUsed(spendHash);
    }
}
