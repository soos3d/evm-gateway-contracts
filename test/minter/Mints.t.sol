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

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MintAuthorization} from "src/lib/authorizations/MintAuthorizations.sol";
import {MintAuthorizationLib} from "src/lib/authorizations/MintAuthorizationLib.sol";
import {SpendMinter} from "src/SpendMinter.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {Test} from "forge-std/Test.sol";

/// Tests minting functionality of SpendMinter
contract TestMints is Test, DeployUtils {
    using MessageHashUtils for bytes32;

    SpendMinter private minter;
    address private owner = makeAddr("owner");
    address private mintAuthorizationSigner;
    uint256 private mintAuthorizationSignerKey;
    bytes internal constant METADATA = "Test metadata";

    function setUp() public {
        minter = deployMinterOnly(owner);
        (mintAuthorizationSigner, mintAuthorizationSignerKey) = makeAddrAndKey("mintAuthorizationSigner");
        vm.startPrank(owner);
        minter.updateMintAuthorizationSigner(mintAuthorizationSigner);
        vm.stopPrank();
    }

    function test_spend_emptyAuth_correctSigner() public {
        _callSpendSignedBy(new bytes(0), mintAuthorizationSignerKey);
    }

    function test_spend_validAuth_correctSigner(MintAuthorization memory authorization) public {
        authorization.spec.metadata = METADATA;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(authorization);
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_emptyAuth_wrongSigner() public {
        (, uint256 wrongSignerKey) = makeAddrAndKey("wrongSigner");
        vm.expectRevert(SpendMinter.InvalidMintAuthorizationSigner.selector);
        _callSpendSignedBy(new bytes(0), wrongSignerKey);
    }

    function test_spend_validAuth_wrongSigner(MintAuthorization memory authorization) public {
        authorization.spec.metadata = METADATA;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(authorization);
        (, uint256 wrongSignerKey) = makeAddrAndKey("wrongSigner");
        vm.expectRevert(SpendMinter.InvalidMintAuthorizationSigner.selector);
        _callSpendSignedBy(encodedAuth, wrongSignerKey);
    }

    function test_spend_wrongSignatureLength() public {
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 2));
        minter.spend(new bytes(0), hex"aaaa");
    }

    function _callSpendSignedBy(bytes memory authorizations, uint256 signerKey) internal {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, keccak256(authorizations).toEthSignedMessageHash());
        bytes memory signature = abi.encodePacked(r, s, v);

        minter.spend(authorizations, signature);
    }
}
