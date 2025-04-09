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

import {SpendWallet} from "src/SpendWallet.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {Test} from "forge-std/Test.sol";

contract TestBurns is Test, DeployUtils {
    SpendWallet private wallet;
    address private owner = makeAddr("owner");
    address private burnSigner;
    uint256 private burnSignerKey;

    function setUp() public {
        wallet = deployWalletOnly(owner);
        (burnSigner, burnSignerKey) = makeAddrAndKey("burnSigner");
        vm.prank(owner);
        wallet.updateBurnSigner(burnSigner);
        vm.stopPrank();
    }

    function test_burnSpent_emptyArgs_correctSigner() external view {
        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _emptyArgs();
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_burnSpent_randomArgs_correctSigner() external view {
        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _randomArgs();
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_burnSpent_emptyArgs_wrongSigner() external {
        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _emptyArgs();
        (, uint256 wrongSignerKey) = makeAddrAndKey("wrongSigner");
        vm.expectRevert(SpendWallet.InvalidBurnSigner.selector);
        _callBurnSpentSignedBy(authorizations, signatures, fees, wrongSignerKey);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_burnSpent_randomArgs_wrongSigner() external {
        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _randomArgs();
        (, uint256 wrongSignerKey) = makeAddrAndKey("wrongSigner");
        vm.expectRevert(SpendWallet.InvalidBurnSigner.selector);
        _callBurnSpentSignedBy(authorizations, signatures, fees, wrongSignerKey);
    }

    function _emptyArgs()
        internal
        pure
        returns (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees)
    {
        authorizations = new bytes[](0);
        signatures = new bytes[](0);
        fees = new uint256[][](0);
    }

    function _randomArgs()
        internal
        pure
        returns (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees)
    {
        authorizations = new bytes[](3);
        authorizations[0] = hex"abcdef";
        authorizations[1] = hex"123456";
        authorizations[2] = hex"987654";
        signatures = new bytes[](3);
        signatures[0] = hex"aaaaaa";
        signatures[1] = hex"bbbbbb";
        signatures[2] = hex"cccccc";
        fees = new uint256[][](3);
        fees[0] = new uint256[](2);
        fees[0][0] = 1;
        fees[0][1] = 2;
        fees[1] = new uint256[](1);
        fees[1][0] = 3;
        fees[2] = new uint256[](1);
        fees[2][0] = 4;
    }

    function _callBurnSpentSignedBy(
        bytes[] memory authorizations,
        bytes[] memory signatures,
        uint256[][] memory fees,
        uint256 signerKey
    ) internal view {
        // Generate a random address and key for the burn signer
        bytes memory encodedCalldata = abi.encode(authorizations, signatures, fees);

        // Hash the calldata, this will be easier in JS but slices don't work for `bytes memory` so we need to drop to
        // assembly. This slices off the first 4 bytes (the argument offsets) and fixes an off-by-one error.
        bytes32 calldataHash;
        uint256 len = encodedCalldata.length - 0x80 + 0x20;
        assembly {
            calldataHash := keccak256(add(encodedCalldata, 0x80), len)
        }

        // Sign the calldata hash as the burn signer
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, calldataHash);
        bytes memory burnerSignature = abi.encodePacked(r, s, v);

        // Call burnSpent with the arguments and signature
        wallet.burnSpent(authorizations, signatures, fees, burnerSignature);
    }
}
