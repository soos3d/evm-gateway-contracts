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

import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Test} from "forge-std/Test.sol";
import {GatewayWallet} from "src/GatewayWallet.sol";
import {BurnAuthorizationLib} from "src/lib/authorizations/BurnAuthorizationLib.sol";
import {BurnAuthorization} from "src/lib/authorizations/BurnAuthorizations.sol";
import {MintAuthorizationLib} from "src/lib/authorizations/MintAuthorizationLib.sol";
import {MintAuthorization, MintAuthorizationSet} from "src/lib/authorizations/MintAuthorizations.sol";
import {TransferSpec} from "src/lib/authorizations/TransferSpec.sol";

contract SignatureTestUtils is Test {
    using MessageHashUtils for bytes32;

    bytes32 private constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    bytes32 private constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 private constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    function _signPermit(address token, address spender, uint256 value, uint256 deadline, uint256 privateKey)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                vm.addr(privateKey),
                spender,
                value,
                IERC20Permit(token).nonces(vm.addr(privateKey)),
                deadline
            )
        );
        bytes32 domainSeparator = IERC20Permit(token).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (v, r, s) = vm.sign(privateKey, digest);
    }

    function _signReceiveWithAuthorization(
        address token,
        address to,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint256 value,
        uint256 privateKey
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(
            abi.encode(
                RECEIVE_WITH_AUTHORIZATION_TYPEHASH, vm.addr(privateKey), to, value, validAfter, validBefore, nonce
            )
        );
        bytes32 domainSeparator = IERC20Permit(token).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (v, r, s) = vm.sign(privateKey, digest);
    }

    function _signCancelAuthorization(address token, bytes32 nonce, uint256 privateKey)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 structHash = keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, vm.addr(privateKey), nonce));
        bytes32 domainSeparator = IERC20Permit(token).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (v, r, s) = vm.sign(privateKey, digest);
    }

    function _signBurnAuthWithTransferSpec(TransferSpec memory transferSpec, GatewayWallet wallet, uint256 signerKey)
        internal
        view
        returns (bytes memory encodedAuth, bytes memory signature)
    {
        BurnAuthorization[] memory auths = new BurnAuthorization[](1);
        auths[0] = _createBurnAuth(transferSpec);
        return _signBurnAuths(auths, wallet, signerKey);
    }

    function _signBurnAuthSetWithTransferSpec(
        TransferSpec[] memory transferSpecs,
        GatewayWallet wallet,
        uint256 signerKey
    ) internal view returns (bytes memory encodedAuth, bytes memory signature) {
        BurnAuthorization[] memory auths = new BurnAuthorization[](transferSpecs.length);
        for (uint256 i = 0; i < transferSpecs.length; i++) {
            auths[i] = _createBurnAuth(transferSpecs[i]);
        }
        return _signBurnAuths(auths, wallet, signerKey);
    }

    function _signMintAuthWithTransferSpec(TransferSpec memory transferSpec, uint256 signerKey)
        internal
        view
        returns (bytes memory encodedAuth, bytes memory signature)
    {
        MintAuthorization[] memory auths = new MintAuthorization[](1);
        auths[0] = _createMintAuth(transferSpec);
        return _signMintAuths(auths, signerKey);
    }

    function _signMintAuthSetWithTransferSpec(TransferSpec[] memory transferSpecs, uint256 signerKey)
        internal
        view
        returns (bytes memory encodedAuth, bytes memory signature)
    {
        MintAuthorization[] memory auths = new MintAuthorization[](transferSpecs.length);
        for (uint256 i = 0; i < transferSpecs.length; i++) {
            auths[i] = _createMintAuth(transferSpecs[i]);
        }
        return _signMintAuths(auths, signerKey);
    }

    function _signBurnAuthorizations(
        bytes[] memory authorizations,
        bytes[] memory signatures,
        uint256[][] memory fees,
        uint256 signerKey
    ) internal pure returns (bytes memory burnerSignature) {
        // Generate a random address and key for the burn signer
        bytes memory encodedCalldata = abi.encode(authorizations, signatures, fees);

        // Sign the calldata hash as the burn signer
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, keccak256(encodedCalldata).toEthSignedMessageHash());
        burnerSignature = abi.encodePacked(r, s, v);
    }

    function _createBurnAuth(TransferSpec memory spec) internal view returns (BurnAuthorization memory) {
        return BurnAuthorization({
            maxBlockHeight: block.number + 5, // ~1 minute expiry
            maxFee: 1e6, // 1 USDC max fee
            spec: spec
        });
    }

    function _createMintAuth(TransferSpec memory spec) private view returns (MintAuthorization memory) {
        return MintAuthorization({
            maxBlockHeight: block.number + 5, // ~1 minute expiry
            spec: spec
        });
    }

    function _signBurnAuths(BurnAuthorization[] memory auths, GatewayWallet wallet, uint256 signerKey)
        internal
        view
        returns (bytes memory encodedAuth, bytes memory signature)
    {
        encodedAuth =
            auths.length == 1 ? wallet.encodeBurnAuthorization(auths[0]) : wallet.encodeBurnAuthorizations(auths);
        bytes32 domainSeparator = wallet.domainSeparator();
        bytes32 digest =
            MessageHashUtils.toTypedDataHash(domainSeparator, BurnAuthorizationLib.getTypedDataHash(encodedAuth));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function _signMintAuths(MintAuthorization[] memory auths, uint256 signerKey)
        private
        pure
        returns (bytes memory encodedAuth, bytes memory signature)
    {
        if (auths.length == 1) {
            encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auths[0]);
        } else {
            MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: auths});
            encodedAuth = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);
        }
        signature = _sign(signerKey, encodedAuth);
    }

    function _sign(uint256 signerKey, bytes memory data) private pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, keccak256(data).toEthSignedMessageHash());
        signature = abi.encodePacked(r, s, v);
    }
}
