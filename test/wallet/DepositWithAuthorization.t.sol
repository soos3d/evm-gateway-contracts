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

import {Denylistable} from "src/lib/common/Denylistable.sol";
import {TokenSupport} from "src/lib/common/TokenSupport.sol";
import {Deposits} from "src/lib/wallet/Deposits.sol";
import {SpendWallet} from "src/SpendWallet.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";
import {MockERC1271Wallet} from "test/mock_fiattoken/contracts/test/MockERC1271Wallet.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IERC3009} from "src/interfaces/IERC3009.sol";
import {SignatureTestUtils} from "test/util/SignatureTestUtils.sol";

/// Tests ERC-3009 authorization deposit functionality of SpendWallet
contract SpendWalletDepositERC3009Test is DeployUtils, SignatureTestUtils {
    address private owner = makeAddr("owner");
    uint256 private depositorPrivateKey;
    address private depositor;
    address private usdc;

    uint256 private initialUsdcBalance = 1000 * 10 ** 6;
    uint256 private erc3009ValidAfter;
    uint256 private erc3009ValidBefore;
    uint256 private activeTimeOffset;
    uint256 private inactiveTimeOffset;

    bytes32 private erc3009Nonce = keccak256("erc3009TestNonce");

    // ERC-3009 typehashes
    bytes32 private constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    bytes32 private constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    // Revert error strings
    string private constant ECRECOVER_INVALID_SIGNATURE = "ECRecover: invalid signature";
    string private constant FIATTOKENV2_INVALID_SIGNATURE = "FiatTokenV2: invalid signature";
    string private constant FIATTOKENV2_AUTHORIZATION_USED_OR_CANCELED =
        "FiatTokenV2: authorization is used or canceled";
    string private constant FIATTOKENV2_AUTHORIZATION_IS_EXPIRED = "FiatTokenV2: authorization is expired";
    string private constant FIATTOKENV2_AUTHORIZATION_IS_NOT_YET_VALID = "FiatTokenV2: authorization is not yet valid";

    SpendWallet private wallet;
    MockERC1271Wallet private depositorWallet;

    function setUp() public {
        (depositor, depositorPrivateKey) = makeAddrAndKey("spendWalletDepositor");
        wallet = deployWalletOnly(owner, ForkTestUtils.forkVars().domain);

        usdc = ForkTestUtils.forkVars().usdc;
        vm.prank(owner);
        wallet.addSupportedToken(usdc);
        // Mint initial USDC balance to depositor
        deal(usdc, depositor, initialUsdcBalance);

        erc3009ValidAfter = block.timestamp;
        erc3009ValidBefore = block.timestamp + 1 days;
        activeTimeOffset = 1 minutes;
        inactiveTimeOffset = 2 days;

        // Create mock ERC1271 wallet for testing SCA signatures
        depositorWallet = new MockERC1271Wallet(depositor);
    }

    // Signature Generation Helpers

    function _create3009AuthorizationSignature(uint256 value) private view returns (uint8 v, bytes32 r, bytes32 s) {
        return _signReceiveWithAuthorization(
            usdc, address(wallet), erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, value, depositorPrivateKey
        );
    }

    function _create3009CancellationSignature() private view returns (uint8 v, bytes32 r, bytes32 s) {
        return _signCancelAuthorization(usdc, erc3009Nonce, depositorPrivateKey);
    }

    function _create7598AuthorizationSignatureBytes(uint256 value) private view returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(value);
        signature = abi.encodePacked(r, s, v);
    }

    /// EIP-3009 EOA signature interface tests

    function test_depositWithAuthorization_with3009Interface_revertWhenPaused() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        vm.prank(owner);
        wallet.pause();

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    function test_depositWithAuthorization_with3009Interface_revertWhenTokenNotSupported() public {
        address unsupportedToken = makeAddr("unsupportedToken");
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);

        vm.expectRevert(abi.encodeWithSelector(TokenSupport.UnsupportedToken.selector, unsupportedToken));
        wallet.depositWithAuthorization(
            unsupportedToken,
            depositor,
            initialUsdcBalance,
            erc3009ValidAfter,
            erc3009ValidBefore,
            erc3009Nonce,
            v,
            r,
            s
        );
    }

    function test_depositWithAuthorization_with3009Interface_revertWhenTxSenderDenylisted() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        address denylister = wallet.denylister();
        address denylistedSender = makeAddr("denylistedSender");
        vm.prank(denylister);
        wallet.denylist(denylistedSender);

        vm.prank(denylistedSender);
        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, denylistedSender));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    function test_depositWithAuthorization_with3009Interface_revertWhenTokenOwnerDenylisted() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        address denylister = wallet.denylister();
        vm.prank(denylister);
        wallet.denylist(depositor);

        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, depositor));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    function test_depositWithAuthorization_with3009Interface_revertIfSignatureInvalid() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        skip(activeTimeOffset);
        r = 0;
        vm.expectRevert(bytes(ECRECOVER_INVALID_SIGNATURE));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    function test_depositWithAuthorization_with3009Interface_revertIfAuthorizationIsNotYetValid() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        assert(block.timestamp == erc3009ValidAfter);
        vm.expectRevert(bytes(FIATTOKENV2_AUTHORIZATION_IS_NOT_YET_VALID));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    function test_depositWithAuthorization_with3009Interface_revertIfAuthorizationExpired() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        skip(inactiveTimeOffset);
        vm.expectRevert(bytes(FIATTOKENV2_AUTHORIZATION_IS_EXPIRED));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    function test_depositWithAuthorization_with3009Interface_revertIfValueExceedsAuthorized() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance / 2);
        skip(activeTimeOffset);
        vm.expectRevert(bytes(FIATTOKENV2_INVALID_SIGNATURE));
        // Attempt to deposit more than authorized
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    function test_depositWithAuthorization_with3009Interface_revertIfValueExceedsBalance() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(2 * initialUsdcBalance);
        skip(activeTimeOffset);
        vm.expectRevert(bytes("ERC20: transfer amount exceeds balance"));
        wallet.depositWithAuthorization(
            usdc, depositor, 2 * initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    function test_depositWithAuthorization_with3009Interface_revertIfAuthorizationCancelled() public {
        (uint8 authorizationV, bytes32 authorizationR, bytes32 authorizationS) =
            _create3009AuthorizationSignature(initialUsdcBalance);
        (uint8 cancellationV, bytes32 cancellationR, bytes32 cancellationS) = _create3009CancellationSignature();
        IERC3009(usdc).cancelAuthorization(depositor, erc3009Nonce, cancellationV, cancellationR, cancellationS);

        skip(activeTimeOffset);

        vm.expectRevert(bytes(FIATTOKENV2_AUTHORIZATION_USED_OR_CANCELED));
        wallet.depositWithAuthorization(
            usdc,
            depositor,
            initialUsdcBalance,
            erc3009ValidAfter,
            erc3009ValidBefore,
            erc3009Nonce,
            authorizationV,
            authorizationR,
            authorizationS
        );
    }

    function test_depositWithAuthorization_with3009Interface_spendableBalanceUpdatedAfterTransfer() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        skip(activeTimeOffset);
        vm.expectEmit(true, true, false, true);
        emit Deposits.Deposited(usdc, depositor, initialUsdcBalance);
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
        assertEq(wallet.spendableBalance(usdc, depositor), initialUsdcBalance);
    }

    function test_depositWithAuthorization_with3009Interface_revertIfAuthorizationReplayed() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance / 2);
        skip(activeTimeOffset);
        vm.expectEmit(true, true, false, true);
        emit Deposits.Deposited(usdc, depositor, initialUsdcBalance / 2);
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance / 2, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
        assertEq(wallet.spendableBalance(usdc, depositor), initialUsdcBalance / 2);

        // Attempt to replay the same authorization
        vm.expectRevert(bytes(FIATTOKENV2_AUTHORIZATION_USED_OR_CANCELED));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance / 2, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    // EIP-7598 byte signature interface tests

    function test_depositWithAuthorization_with7598Interface_revertWhenPaused() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);
        vm.prank(owner);
        wallet.pause();

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_with7598Interface_revertWhenTokenNotSupported() public {
        address unsupportedToken = makeAddr("unsupportedToken");
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);

        vm.expectRevert(abi.encodeWithSelector(TokenSupport.UnsupportedToken.selector, unsupportedToken));
        wallet.depositWithAuthorization(
            unsupportedToken,
            depositor,
            initialUsdcBalance,
            erc3009ValidAfter,
            erc3009ValidBefore,
            erc3009Nonce,
            signature
        );
    }

    function test_depositWithAuthorization_with7598Interface_revertWhenTxSenderDenylisted() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);
        address denylister = wallet.denylister();
        address denylistedSender = makeAddr("denylistedSender");
        vm.prank(denylister);
        wallet.denylist(denylistedSender);

        vm.prank(denylistedSender);
        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, denylistedSender));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_with7598Interface_revertWhenTokenOwnerDenylisted() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);
        address denylister = wallet.denylister();
        vm.prank(denylister);
        wallet.denylist(depositor);

        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, depositor));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_with7598Interface_withEOASignature_revertIfSignatureInvalid() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        skip(activeTimeOffset);
        r = 0;
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.expectRevert(bytes(ECRECOVER_INVALID_SIGNATURE));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_with7598Interface_withSCASignature_revertIfSCASignatureInvalid() public {
        depositorWallet.setSignatureValid(false);
        bytes memory signature = abi.encodePacked("random");
        skip(activeTimeOffset);

        vm.expectRevert(bytes(FIATTOKENV2_INVALID_SIGNATURE));
        wallet.depositWithAuthorization(
            usdc,
            address(depositorWallet),
            initialUsdcBalance,
            erc3009ValidAfter,
            erc3009ValidBefore,
            erc3009Nonce,
            signature
        );
    }

    function test_depositWithAuthorization_with7598Interface_revertIfAuthorizationIsNotYetValid() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);
        assert(block.timestamp == erc3009ValidAfter);
        vm.expectRevert(bytes(FIATTOKENV2_AUTHORIZATION_IS_NOT_YET_VALID));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_with7598Interface_revertIfAuthorizationExpired() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);
        skip(inactiveTimeOffset);
        vm.expectRevert(bytes(FIATTOKENV2_AUTHORIZATION_IS_EXPIRED));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_with7598Interface_revertIfValueExceedsAuthorized() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance / 2);
        skip(activeTimeOffset);
        vm.expectRevert(bytes(FIATTOKENV2_INVALID_SIGNATURE));
        // Attempt to deposit more than authorized
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_with7598Interface_revertIfValueExceedsBalance() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(2 * initialUsdcBalance);
        skip(activeTimeOffset);
        vm.expectRevert(bytes("ERC20: transfer amount exceeds balance"));
        wallet.depositWithAuthorization(
            usdc, depositor, 2 * initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_with7598Interface_revertIfAuthorizationCancelled() public {
        bytes memory authorizationSignature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);
        (uint8 cancellationV, bytes32 cancellationR, bytes32 cancellationS) = _create3009CancellationSignature();
        IERC3009(usdc).cancelAuthorization(depositor, erc3009Nonce, cancellationV, cancellationR, cancellationS);

        skip(activeTimeOffset);

        vm.expectRevert(bytes(FIATTOKENV2_AUTHORIZATION_USED_OR_CANCELED));
        wallet.depositWithAuthorization(
            usdc,
            depositor,
            initialUsdcBalance,
            erc3009ValidAfter,
            erc3009ValidBefore,
            erc3009Nonce,
            authorizationSignature
        );
    }

    function test_depositWithAuthorization_with7598Interface_withEOASignature_spendableBalanceUpdatedAfterTransfer()
        public
    {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);
        skip(activeTimeOffset);
        vm.expectEmit(true, true, false, true);
        emit Deposits.Deposited(usdc, depositor, initialUsdcBalance);
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
        assertEq(wallet.spendableBalance(usdc, depositor), initialUsdcBalance);
    }

    function test_depositWithAuthorization_with7598Interface_withSCASignature_spendableBalanceUpdatedAfterTransfer()
        public
    {
        address depositorWalletAddress = address(depositorWallet);
        deal(usdc, depositorWalletAddress, initialUsdcBalance);
        depositorWallet.setSignatureValid(true);
        bytes memory signature = abi.encodePacked("random");
        skip(activeTimeOffset);

        vm.expectEmit(true, true, false, true);
        emit Deposits.Deposited(usdc, depositorWalletAddress, initialUsdcBalance);
        wallet.depositWithAuthorization(
            usdc,
            depositorWalletAddress,
            initialUsdcBalance,
            erc3009ValidAfter,
            erc3009ValidBefore,
            erc3009Nonce,
            signature
        );
        assertEq(wallet.spendableBalance(usdc, depositorWalletAddress), initialUsdcBalance);
    }

    function test_depositWithAuthorization_with7598Interface_revertIfAuthorizationReplayed() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance / 2);
        skip(activeTimeOffset);
        vm.expectEmit(true, true, false, true);
        emit Deposits.Deposited(usdc, depositor, initialUsdcBalance / 2);
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance / 2, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
        assertEq(wallet.spendableBalance(usdc, depositor), initialUsdcBalance / 2);

        // Attempt to replay the same authorization
        vm.expectRevert(bytes(FIATTOKENV2_AUTHORIZATION_USED_OR_CANCELED));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance / 2, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }
}
