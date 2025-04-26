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

import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {Denylist} from "src/modules/common/Denylist.sol";
import {TokenSupport} from "src/modules/common/TokenSupport.sol";
import {Deposits} from "src/modules/wallet/Deposits.sol";
import {GatewayWallet} from "src/GatewayWallet.sol";
import {MockERC1271Wallet} from "test/mock_fiattoken/contracts/test/MockERC1271Wallet.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";
import {SignatureTestUtils} from "test/util/SignatureTestUtils.sol";

/// Tests EIP-2612 permit deposit functionality of GatewayWallet
contract GatewayWalletDepositWithPermitTest is DeployUtils, SignatureTestUtils {
    address private owner = makeAddr("owner");
    uint256 private depositorPrivateKey;
    address private depositor;
    address private usdc;

    uint256 private initialUsdcBalance = 1000 * 10 ** 6;
    uint256 private eip2612PermitDeadline;
    uint256 private activeTimeOffset;
    uint256 private inactiveTimeOffset;

    // EIP-2612 typehash
    bytes32 private constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    // Revert error strings
    string private constant ERC20_TRANSFER_AMOUNT_EXCEEDS_BALANCE = "ERC20: transfer amount exceeds balance";
    string private constant EIP2612_INVALID_SIGNATURE = "EIP2612: invalid signature";
    string private constant ECRECOVER_INVALID_SIGNATURE = "ECRecover: invalid signature";
    string private constant FIATTOKENV2_PERMIT_EXPIRED = "FiatTokenV2: permit is expired";

    GatewayWallet private wallet;
    MockERC1271Wallet private depositorWallet;

    function setUp() public {
        (depositor, depositorPrivateKey) = makeAddrAndKey("spendWalletDepositor");
        wallet = deployWalletOnly(owner, ForkTestUtils.forkVars().domain);

        usdc = ForkTestUtils.forkVars().usdc;
        vm.prank(owner);
        wallet.addSupportedToken(usdc);
        // Mint initial USDC balance to depositor
        deal(usdc, depositor, initialUsdcBalance);

        eip2612PermitDeadline = block.timestamp + 1 days;
        activeTimeOffset = 1 minutes;
        inactiveTimeOffset = 2 days;

        // Create mock ERC1271 wallet for testing SCA signatures
        depositorWallet = new MockERC1271Wallet(depositor);
    }

    // Signature Generation Helpers

    function _create2612PermitSignature(uint256 value) private view returns (uint8 v, bytes32 r, bytes32 s) {
        return _signPermit(usdc, address(wallet), value, eip2612PermitDeadline, depositorPrivateKey);
    }

    function _create7597PermitEOASignature(uint256 value) private view returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(value);
        signature = abi.encodePacked(r, s, v);
    }

    // EIP-2612 EOA signature interface tests

    function test_depositWithPermit_with2612Interface_revertWhenPaused() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance);
        vm.prank(owner);
        wallet.pause();

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWithPermit_with2612Interface_revertWhenTokenNotSupported() public {
        address unsupportedToken = makeAddr("unsupportedToken");
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance);
        vm.expectRevert(abi.encodeWithSelector(TokenSupport.UnsupportedToken.selector, unsupportedToken));
        wallet.depositWithPermit(unsupportedToken, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWithPermit_with2612Interface_revertWhenTxSenderDenylisted() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance);
        address denylister = wallet.denylister();
        address denylistedSender = makeAddr("denylistedSender");
        vm.prank(denylister);
        wallet.denylist(denylistedSender);

        vm.prank(denylistedSender);
        vm.expectRevert(abi.encodeWithSelector(Denylist.AccountDenylisted.selector, denylistedSender));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWithPermit_with2612Interface_revertWhenTokenOwnerDenylisted() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance);
        address denylister = wallet.denylister();
        vm.prank(denylister);
        wallet.denylist(depositor);

        vm.expectRevert(abi.encodeWithSelector(Denylist.AccountDenylisted.selector, depositor));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWithPermit_with2612Interface_revertIfSignatureInvalid() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance);
        r = 0;
        vm.expectRevert(bytes(ECRECOVER_INVALID_SIGNATURE));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWithPermit_with2612Interface_revertIfValueNonPositive() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(0);
        vm.expectRevert(Deposits.DepositValueMustBePositive.selector);
        wallet.depositWithPermit(usdc, depositor, 0, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWithPermit_with2612Interface_revertIfDeadlinePassed() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance);
        skip(inactiveTimeOffset);
        vm.expectRevert(bytes(FIATTOKENV2_PERMIT_EXPIRED));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWithPermit_with2612Interface_revertIfValueExceedsPermitted() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance / 2);
        vm.expectRevert(bytes(EIP2612_INVALID_SIGNATURE));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWithPermit_with2612Interface_revertIfValueExceedsBalance() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(2 * initialUsdcBalance);
        vm.expectRevert(bytes(ERC20_TRANSFER_AMOUNT_EXCEEDS_BALANCE));
        wallet.depositWithPermit(usdc, depositor, 2 * initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWithPermit_with2612Interface_availableBalanceUpdatedAfterTransfer() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance);
        vm.expectEmit(true, true, false, true);
        emit Deposits.Deposited(usdc, depositor, initialUsdcBalance);
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
        assertEq(wallet.availableBalance(usdc, depositor), initialUsdcBalance);
    }

    function test_depositWithPermit_with2612Interface_revertIfPermitReplayed() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance / 2);
        vm.expectEmit(true, true, false, true);
        emit Deposits.Deposited(usdc, depositor, initialUsdcBalance / 2);
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance / 2, eip2612PermitDeadline, v, r, s);
        assertEq(wallet.availableBalance(usdc, depositor), initialUsdcBalance / 2);

        // Attempt to replay the same permit signature
        vm.expectRevert(bytes(EIP2612_INVALID_SIGNATURE));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance / 2, eip2612PermitDeadline, v, r, s);
    }

    // EIP-7597 byte signature interface tests

    function test_depositWithPermit_with7597Interface_revertWhenPaused() public {
        bytes memory signature = _create7597PermitEOASignature(initialUsdcBalance);
        vm.prank(owner);
        wallet.pause();

        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, signature);
    }

    function test_depositWithPermit_with7597Interface_revertWhenTokenNotSupported() public {
        address unsupportedToken = makeAddr("unsupportedToken");
        bytes memory signature = _create7597PermitEOASignature(initialUsdcBalance);
        vm.expectRevert(abi.encodeWithSelector(TokenSupport.UnsupportedToken.selector, unsupportedToken));
        wallet.depositWithPermit(unsupportedToken, depositor, initialUsdcBalance, eip2612PermitDeadline, signature);
    }

    function test_depositWithPermit_with7597Interface_revertWhenTxSenderDenylisted() public {
        bytes memory signature = _create7597PermitEOASignature(initialUsdcBalance);
        address denylister = wallet.denylister();
        address denylistedSender = makeAddr("denylistedSender");
        vm.prank(denylister);
        wallet.denylist(denylistedSender);

        vm.prank(denylistedSender);
        vm.expectRevert(abi.encodeWithSelector(Denylist.AccountDenylisted.selector, denylistedSender));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, signature);
    }

    function test_depositWithPermit_with7597Interface_revertWhenTokenOwnerDenylisted() public {
        bytes memory signature = _create7597PermitEOASignature(initialUsdcBalance);
        address denylister = wallet.denylister();
        vm.prank(denylister);
        wallet.denylist(depositor);

        vm.expectRevert(abi.encodeWithSelector(Denylist.AccountDenylisted.selector, depositor));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, signature);
    }

    function test_depositWithPermit_with7597Interface_revertIfEOASignatureInvalid() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance);
        r = 0;
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(bytes(ECRECOVER_INVALID_SIGNATURE));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, signature);
    }

    function test_depositWithPermit_with7597Interface_revertIfSCASignatureInvalid() public {
        depositorWallet.setSignatureValid(false);
        bytes memory signature = abi.encodePacked("random");
        vm.expectRevert(bytes(EIP2612_INVALID_SIGNATURE));
        wallet.depositWithPermit(usdc, address(depositorWallet), initialUsdcBalance, eip2612PermitDeadline, signature);
    }

    function test_depositWithPermit_with7597Interface_revertIfValueNonPositive() public {
        bytes memory signature = _create7597PermitEOASignature(0);
        vm.expectRevert(Deposits.DepositValueMustBePositive.selector);
        wallet.depositWithPermit(usdc, depositor, 0, eip2612PermitDeadline, signature);
    }

    function test_depositWithPermit_with7597Interface_revertIfDeadlinePassed() public {
        bytes memory signature = _create7597PermitEOASignature(initialUsdcBalance);
        skip(inactiveTimeOffset);
        vm.expectRevert(bytes(FIATTOKENV2_PERMIT_EXPIRED));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, signature);
    }

    function test_depositWithPermit_with7597Interface_revertIfValueExceedsPermitted() public {
        bytes memory signature = _create7597PermitEOASignature(initialUsdcBalance / 2);
        vm.expectRevert(bytes(EIP2612_INVALID_SIGNATURE));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, signature);
    }

    function test_depositWithPermit_with7597Interface_revertIfValueExceedsBalance() public {
        bytes memory signature = _create7597PermitEOASignature(2 * initialUsdcBalance);
        vm.expectRevert(bytes(ERC20_TRANSFER_AMOUNT_EXCEEDS_BALANCE));
        wallet.depositWithPermit(usdc, depositor, 2 * initialUsdcBalance, eip2612PermitDeadline, signature);
    }

    function test_depositWithPermit_with7597Interface_withEOASignature_availableBalanceUpdatedAfterTransfer() public {
        bytes memory signature = _create7597PermitEOASignature(initialUsdcBalance);
        vm.expectEmit(true, true, false, true);
        emit Deposits.Deposited(usdc, depositor, initialUsdcBalance);

        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, signature);

        assertEq(wallet.availableBalance(usdc, depositor), initialUsdcBalance);
    }

    function test_depositWithPermit_with7597Interface_withSCASignature_availableBalanceUpdatedAfterTransfer() public {
        address depositorWalletAddress = address(depositorWallet);
        deal(usdc, depositorWalletAddress, initialUsdcBalance);
        depositorWallet.setSignatureValid(true);
        bytes memory signature = abi.encodePacked("random");
        vm.expectEmit(true, true, false, true);
        emit Deposits.Deposited(usdc, depositorWalletAddress, initialUsdcBalance);

        wallet.depositWithPermit(usdc, depositorWalletAddress, initialUsdcBalance, eip2612PermitDeadline, signature);

        assertEq(wallet.availableBalance(usdc, depositorWalletAddress), initialUsdcBalance);
    }

    function test_depositWithPermit_with7597Interface_revertIfPermitReplayed() public {
        bytes memory signature = _create7597PermitEOASignature(initialUsdcBalance / 2);
        vm.expectEmit(true, true, false, true);
        emit Deposits.Deposited(usdc, depositor, initialUsdcBalance / 2);
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance / 2, eip2612PermitDeadline, signature);
        assertEq(wallet.availableBalance(usdc, depositor), initialUsdcBalance / 2);

        // Attempt to replay the same permit signature
        vm.expectRevert(bytes(EIP2612_INVALID_SIGNATURE));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance / 2, eip2612PermitDeadline, signature);
    }
}
