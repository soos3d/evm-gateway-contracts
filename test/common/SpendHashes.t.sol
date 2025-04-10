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
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {SpendHashes} from "src/lib/common/SpendHashes.sol";
import {TransferSpec} from "src/lib/authorizations/TransferSpec.sol";

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

    function _createFakeTransferSpec(uint256 seed) internal pure returns (TransferSpec memory) {
        return TransferSpec({
            version: 1,
            sourceDomain: 1,
            destinationDomain: 2,
            sourceContract: keccak256(abi.encode("sourceContract", seed)),
            destinationContract: keccak256(abi.encode("destinationContract", seed)),
            sourceToken: keccak256(abi.encode("sourceToken", seed)),
            destinationToken: keccak256(abi.encode("destinationToken", seed)),
            sourceDepositor: keccak256(abi.encode("sourceDepositor", seed)),
            destinationRecipient: keccak256(abi.encode("destinationRecipient", seed)),
            sourceSigner: keccak256(abi.encode("sourceSigner", seed)),
            destinationCaller: keccak256(abi.encode("destinationCaller", seed)),
            value: seed,
            nonce: keccak256(abi.encode("nonce", seed)),
            metadata: abi.encode("metadata", seed)
        });
    }

    function _hashTransferSpec(TransferSpec memory spec) internal pure returns (bytes32) {
        return keccak256(abi.encode(spec));
    }

    function _deploySpendHashesProxy(address impl) internal returns (address) {
        ERC1967Proxy proxy = new ERC1967Proxy(impl, new bytes(0));
        return address(proxy);
    }

    function test_spendHashes_ensureSpendHashNotUsedSucceedsIfNewSpendHashFuzz(uint256 seed) public view {
        TransferSpec memory spec = _createFakeTransferSpec(seed);
        bytes32 spendHash = _hashTransferSpec(spec);
        spendHashes.ensureSpendHashNotUsed(spendHash);
    }

    function test_spendHashes_revertsIfSpendHashAlreadyUsedFuzz(uint256 seed) public {
        TransferSpec memory spec = _createFakeTransferSpec(seed);
        bytes32 spendHash = _hashTransferSpec(spec);

        spendHashes.markSpendHashAsUsed(spendHash);

        vm.expectRevert(abi.encodeWithSelector(SpendHashes.SpendHashUsed.selector, spendHash));
        spendHashes.ensureSpendHashNotUsed(spendHash);
    }

    function test_spendHashes_markSpendHashAsUsedIsIdempotentFuzz(uint256 seed) public {
        TransferSpec memory spec = _createFakeTransferSpec(seed);
        bytes32 spendHash = _hashTransferSpec(spec);

        spendHashes.markSpendHashAsUsed(spendHash);
        spendHashes.markSpendHashAsUsed(spendHash);

        vm.expectRevert(abi.encodeWithSelector(SpendHashes.SpendHashUsed.selector, spendHash));
        spendHashes.ensureSpendHashNotUsed(spendHash);
    }

    function test_spendHashes_markMultipleSpendHashesAsUsedFuzz(uint256 seed1, uint256 seed2) public {
        vm.assume(seed1 != seed2);
        TransferSpec memory spec1 = _createFakeTransferSpec(seed1);
        TransferSpec memory spec2 = _createFakeTransferSpec(seed2);
        bytes32 spendHash1 = _hashTransferSpec(spec1);
        bytes32 spendHash2 = _hashTransferSpec(spec2);

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

        TransferSpec memory spec = _createFakeTransferSpec(seed);
        bytes32 spendHash = _hashTransferSpec(spec);
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
