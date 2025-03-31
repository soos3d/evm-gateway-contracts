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
pragma solidity 0.8.28;

import {Rejection} from "src/lib/common/Rejection.sol";
import {TokenSupport} from "src/lib/common/TokenSupport.sol";
import {SpendWallet} from "src/SpendWallet.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IERC3009} from "src/interfaces/IERC3009.sol";
import {Test} from "forge-std/Test.sol";

/// Tests ERC-3009 authorization deposit functionality of SpendWallet
contract SpendWalletDepositERC3009Test is Test, DeployUtils {
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

    function setUp() public {
        (depositor, depositorPrivateKey) = makeAddrAndKey("spendWalletDepositor");
        wallet = deployWalletOnly(owner);

        usdc = ForkTestUtils.forkVars().usdc;
        vm.prank(owner);
        wallet.addSupportedToken(usdc);
        // Mint initial USDC balance to depositor
        deal(usdc, depositor, initialUsdcBalance);

        erc3009ValidAfter = block.timestamp;
        erc3009ValidBefore = block.timestamp + 1 days;
        activeTimeOffset = 1 minutes;
        inactiveTimeOffset = 2 days;
    }

    // Signature Generation Helpers

    function _create3009AuthorizationSignature(uint256 value) private view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(
            abi.encode(
                RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
                depositor,
                address(wallet),
                value,
                erc3009ValidAfter,
                erc3009ValidBefore,
                erc3009Nonce
            )
        );
        bytes32 domainSeparator = IERC20Permit(usdc).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (v, r, s) = vm.sign(depositorPrivateKey, digest);
    }

    function _create3009CancellationSignature() private view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, depositor, erc3009Nonce));
        bytes32 domainSeparator = IERC20Permit(usdc).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (v, r, s) = vm.sign(depositorPrivateKey, digest);
    }

    function _create7598AuthorizationSignatureBytes(uint256 value) private view returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(value);
        signature = abi.encodePacked(r, s, v);
    }

    function _create7598ancellationSignatureBytes() private view returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = _create3009CancellationSignature();
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
            unsupportedToken, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    function test_depositWithAuthorization_with3009Interface_revertWhenTxSenderRejected() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        address rejecter = wallet.rejecter();
        address rejectedSender = makeAddr("rejectedSender");
        vm.prank(rejecter);
        wallet.rejectAddress(rejectedSender);

        vm.prank(rejectedSender);
        vm.expectRevert(abi.encodeWithSelector(Rejection.NotAllowed.selector, rejectedSender));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    function test_depositWithAuthorization_with3009Interface_revertWhenTokenOwnerRejected() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        address rejecter = wallet.rejecter();
        vm.prank(rejecter);
        wallet.rejectAddress(depositor);

        vm.expectRevert(abi.encodeWithSelector(Rejection.NotAllowed.selector, depositor));
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
        emit SpendWallet.Deposited(usdc, depositor, initialUsdcBalance);
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
        assertEq(wallet.spendableBalance(usdc, depositor), initialUsdcBalance);
    }

    function test_depositWithAuthorization_with3009Interface_revertIfAuthorizationReplayed() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance / 2);
        skip(activeTimeOffset);
        vm.expectEmit(true, true, false, true);
        emit SpendWallet.Deposited(usdc, depositor, initialUsdcBalance / 2);
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

    function test_depositWithAuthorization_withEOASignatureBytes_revertWhenPaused() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);
        vm.prank(owner);
        wallet.pause();

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_withEOASignatureBytes_revertWhenTokenNotSupported() public {
        address unsupportedToken = makeAddr("unsupportedToken");
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);

        vm.expectRevert(abi.encodeWithSelector(TokenSupport.UnsupportedToken.selector, unsupportedToken));
        wallet.depositWithAuthorization(
            unsupportedToken, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_withEOASignatureBytes_revertWhenTxSenderRejected() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);
        address rejecter = wallet.rejecter();
        address rejectedSender = makeAddr("rejectedSender");
        vm.prank(rejecter);
        wallet.rejectAddress(rejectedSender);

        vm.prank(rejectedSender);
        vm.expectRevert(abi.encodeWithSelector(Rejection.NotAllowed.selector, rejectedSender));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_withEOASignatureBytes_revertWhenTokenOwnerRejected() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);
        address rejecter = wallet.rejecter();
        vm.prank(rejecter);
        wallet.rejectAddress(depositor);

        vm.expectRevert(abi.encodeWithSelector(Rejection.NotAllowed.selector, depositor));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_withEOASignatureBytes_revertIfSignatureInvalid() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        skip(activeTimeOffset);
        r = 0;
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.expectRevert(bytes(ECRECOVER_INVALID_SIGNATURE));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_withEOASignatureBytes_revertIfAuthorizationIsNotYetValid() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);
        assert(block.timestamp == erc3009ValidAfter);
        vm.expectRevert(bytes(FIATTOKENV2_AUTHORIZATION_IS_NOT_YET_VALID));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_withEOASignatureBytes_revertIfAuthorizationExpired() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);
        skip(inactiveTimeOffset);
        vm.expectRevert(bytes(FIATTOKENV2_AUTHORIZATION_IS_EXPIRED));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_withEOASignatureBytes_revertIfValueExceedsAuthorized() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance / 2);
        skip(activeTimeOffset);
        vm.expectRevert(bytes(FIATTOKENV2_INVALID_SIGNATURE));
        // Attempt to deposit more than authorized
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_withEOASignatureBytes_revertIfValueExceedsBalance() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(2 * initialUsdcBalance);
        skip(activeTimeOffset);
        vm.expectRevert(bytes("ERC20: transfer amount exceeds balance"));
        wallet.depositWithAuthorization(
            usdc, depositor, 2 * initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
    }

    function test_depositWithAuthorization_withEOASignatureBytes_revertIfAuthorizationCancelled() public {
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

    function test_depositWithAuthorization_withEOASignatureBytes_spendableBalanceUpdatedAfterTransfer() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance);
        skip(activeTimeOffset);
        vm.expectEmit(true, true, false, true);
        emit SpendWallet.Deposited(usdc, depositor, initialUsdcBalance);
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, signature
        );
        assertEq(wallet.spendableBalance(usdc, depositor), initialUsdcBalance);
    }

    function test_depositWithAuthorization_withEOASignatureBytes_revertIfAuthorizationReplayed() public {
        bytes memory signature = _create7598AuthorizationSignatureBytes(initialUsdcBalance / 2);
        skip(activeTimeOffset);
        vm.expectEmit(true, true, false, true);
        emit SpendWallet.Deposited(usdc, depositor, initialUsdcBalance / 2);
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