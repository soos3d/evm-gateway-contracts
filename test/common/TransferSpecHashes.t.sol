/**
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
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

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Test} from "forge-std/Test.sol";
import {TransferSpec} from "src/lib/TransferSpec.sol";
import {TransferSpecHashes} from "src/modules/common/TransferSpecHashes.sol";

contract TransferSpecHashesHarness is TransferSpecHashes {
    function markTransferSpecHashAsUsed(bytes32 transferSpecHash) external {
        _markTransferSpecHashAsUsed(transferSpecHash);
    }

    function ensureTransferSpecHashNotUsed(bytes32 transferSpecHash) external view {
        _ensureTransferSpecHashNotUsed(transferSpecHash);
    }
}

contract UpgradeableTransferSpecHashesHarness is TransferSpecHashesHarness, UUPSUpgradeable {
    function _authorizeUpgrade(address) internal override {}
}

/// Tests the TransferSpecHashes contract
contract TransferSpecHashesTest is Test {
    TransferSpecHashesHarness private transferSpecHashes;

    function setUp() public {
        transferSpecHashes = new TransferSpecHashesHarness();
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

    function _deployTransferSpecHashesProxy(address impl) internal returns (address) {
        ERC1967Proxy proxy = new ERC1967Proxy(impl, new bytes(0));
        return address(proxy);
    }

    function test_transferSpecHashes_marksAsUsed(uint256 seed) public {
        TransferSpec memory spec = _createFakeTransferSpec(seed);
        bytes32 transferSpecHash = _hashTransferSpec(spec);

        transferSpecHashes.markTransferSpecHashAsUsed(transferSpecHash);
        assertTrue(transferSpecHashes.isTransferSpecHashUsed(transferSpecHash));
    }

    function test_transferSpecHashes_ensureTransferSpecHashNotUsedSucceedsIfNewTransferSpecHashFuzz(uint256 seed)
        public
        view
    {
        TransferSpec memory spec = _createFakeTransferSpec(seed);
        bytes32 transferSpecHash = _hashTransferSpec(spec);
        transferSpecHashes.ensureTransferSpecHashNotUsed(transferSpecHash);
    }

    function test_transferSpecHashes_revertsIfTransferSpecHashAlreadyUsedFuzz(uint256 seed) public {
        TransferSpec memory spec = _createFakeTransferSpec(seed);
        bytes32 transferSpecHash = _hashTransferSpec(spec);

        transferSpecHashes.markTransferSpecHashAsUsed(transferSpecHash);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecHashes.TransferSpecHashUsed.selector, transferSpecHash));
        transferSpecHashes.ensureTransferSpecHashNotUsed(transferSpecHash);
    }

    function test_transferSpecHashes_markTransferSpecHashAsUsedIsIdempotentFuzz(uint256 seed) public {
        TransferSpec memory spec = _createFakeTransferSpec(seed);
        bytes32 transferSpecHash = _hashTransferSpec(spec);

        transferSpecHashes.markTransferSpecHashAsUsed(transferSpecHash);
        transferSpecHashes.markTransferSpecHashAsUsed(transferSpecHash);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecHashes.TransferSpecHashUsed.selector, transferSpecHash));
        transferSpecHashes.ensureTransferSpecHashNotUsed(transferSpecHash);
    }

    function test_transferSpecHashes_markMultipleTransferSpecHashesAsUsedFuzz(uint256 seed1, uint256 seed2) public {
        vm.assume(seed1 != seed2);
        TransferSpec memory spec1 = _createFakeTransferSpec(seed1);
        TransferSpec memory spec2 = _createFakeTransferSpec(seed2);
        bytes32 transferSpecHash1 = _hashTransferSpec(spec1);
        bytes32 transferSpecHash2 = _hashTransferSpec(spec2);

        transferSpecHashes.markTransferSpecHashAsUsed(transferSpecHash1);
        transferSpecHashes.markTransferSpecHashAsUsed(transferSpecHash2);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecHashes.TransferSpecHashUsed.selector, transferSpecHash1));
        transferSpecHashes.ensureTransferSpecHashNotUsed(transferSpecHash1);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecHashes.TransferSpecHashUsed.selector, transferSpecHash2));
        transferSpecHashes.ensureTransferSpecHashNotUsed(transferSpecHash2);
    }

    function test_transferSpecHashes_persistsStorageAcrossUpgradesFuzz(uint256 seed) public {
        // Deploy implementation contracts
        UpgradeableTransferSpecHashesHarness impl1 = new UpgradeableTransferSpecHashesHarness();
        UpgradeableTransferSpecHashesHarness impl2 = new UpgradeableTransferSpecHashesHarness();

        // Deploy proxy directly with impl1 and initialize it
        address proxyAddr = _deployTransferSpecHashesProxy(address(impl1));
        UpgradeableTransferSpecHashesHarness proxyAsImpl = UpgradeableTransferSpecHashesHarness(proxyAddr);

        TransferSpec memory spec = _createFakeTransferSpec(seed);
        bytes32 transferSpecHash = _hashTransferSpec(spec);
        proxyAsImpl.markTransferSpecHashAsUsed(transferSpecHash);

        vm.expectRevert(abi.encodeWithSelector(TransferSpecHashes.TransferSpecHashUsed.selector, transferSpecHash));
        proxyAsImpl.ensureTransferSpecHashNotUsed(transferSpecHash);

        // Upgrade to the second implementation
        proxyAsImpl.upgradeToAndCall(address(impl2), new bytes(0));

        // Check that the transfer spec hash is still marked as used despite the upgrade
        vm.expectRevert(abi.encodeWithSelector(TransferSpecHashes.TransferSpecHashUsed.selector, transferSpecHash));
        proxyAsImpl.ensureTransferSpecHashNotUsed(transferSpecHash);

        // Verify that implementation storage is not affected by the upgrade
        impl1.ensureTransferSpecHashNotUsed(transferSpecHash);
        impl2.ensureTransferSpecHashNotUsed(transferSpecHash);
    }
}
