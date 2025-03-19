/*
 * Copyright 2024 Circle Internet Group, Inc. All rights reserved.

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

import {SpendWallet} from "src/SpendWallet.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {IERC3009} from "src/interfaces/IERC3009.sol";
import {Test} from "forge-std/Test.sol";

/// Tests deposit functionality of SpendWallet
contract SpendWalletDepositTest is Test, DeployUtils {
    address private owner = makeAddr("owner");

    uint256 private depositorPrivateKey = 1;
    address private depositor = vm.addr(depositorPrivateKey);
    address private usdc;

    uint256 private initialUsdcBalance = 1000 * 10 ** 6;

    uint256 private eip2612PermitDeadline;
    uint256 private erc3009ValidAfter;
    uint256 private erc3009ValidBefore;

    bytes32 private erc3009Nonce = keccak256("erc3009TestNonce");

    // EIP-2612 typehash
    bytes32 private constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    // ERC-3009 typehashes
    bytes32 private constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    bytes32 private constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    // Revert error strings
    string private constant ERC20_TRANSFER_AMOUNT_EXCEEDS_ALLOWANCE = "ERC20: transfer amount exceeds allowance";
    string private constant ERC20_TRANSFER_AMOUNT_EXCEEDS_BALANCE = "ERC20: transfer amount exceeds balance";
    string private constant EIP2612_INVALID_SIGNATURE = "EIP2612: invalid signature";
    string private constant ECRECOVER_INVALID_SIGNATURE = "ECRecover: invalid signature";
    string private constant FIATTOKENV2_INVALID_SIGNATURE = "FiatTokenV2: invalid signature";
    string private constant FIATTOKENV2_AUTHORIZATION_USED_OR_CANCELED =
        "FiatTokenV2: authorization is used or canceled";
    string private constant FIATTOKENV2_AUTHORIZATION_IS_EXPIRED = "FiatTokenV2: authorization is expired";
    string private constant FIATTOKENV2_AUTHORIZATION_IS_NOT_YET_VALID = "FiatTokenV2: authorization is not yet valid";

    SpendWallet private wallet;

    function setUp() public {
        wallet = deployWalletOnly(owner);

        usdc = ForkTestUtils.forkVars().usdc;
        vm.prank(owner);
        wallet.addSupportedToken(usdc);
        // Mint initial USDC balance to depositor
        deal(usdc, depositor, initialUsdcBalance);

        eip2612PermitDeadline = block.timestamp + 1 days;
        erc3009ValidAfter = block.timestamp;
        erc3009ValidBefore = block.timestamp + 1 days;
    }

    function test_deposit_revertIfWalletNotApproved() public {
        vm.startPrank(depositor);
        vm.expectRevert(bytes(ERC20_TRANSFER_AMOUNT_EXCEEDS_ALLOWANCE));
        wallet.deposit(usdc, initialUsdcBalance);
        vm.stopPrank();
    }

    function test_deposit_revertIfValueNonPositive() public {
        vm.startPrank(depositor);
        vm.expectRevert(SpendWallet.DepositValueMustBePositive.selector);
        wallet.deposit(usdc, 0);
        vm.stopPrank();
    }

    function test_deposit_revertIfValueMoreThanApproved() public {
        vm.startPrank(depositor);
        IERC20(usdc).approve(address(wallet), initialUsdcBalance);
        vm.expectRevert(bytes(ERC20_TRANSFER_AMOUNT_EXCEEDS_ALLOWANCE));
        wallet.deposit(usdc, 2 * initialUsdcBalance);
        vm.stopPrank();
    }

    function test_deposit_spendableBalanceUpdatedAfterTransfer() public {
        vm.startPrank(depositor);
        IERC20(usdc).approve(address(wallet), initialUsdcBalance);

        // Deposit half of the allowance
        vm.expectEmit(true, true, true, true);
        emit SpendWallet.Deposited(usdc, depositor, initialUsdcBalance / 2);
        wallet.deposit(usdc, initialUsdcBalance / 2);
        assertEq(wallet.spendableBalance(usdc, address(depositor)), initialUsdcBalance / 2);

        // Deposit the other half
        vm.expectEmit(true, true, true, true);
        emit SpendWallet.Deposited(usdc, depositor, initialUsdcBalance / 2);
        wallet.deposit(usdc, initialUsdcBalance / 2);
        assertEq(wallet.spendableBalance(usdc, address(depositor)), initialUsdcBalance);

        vm.stopPrank();
    }

    function _create2612PermitSignature(uint256 value) private view returns (uint8 v, bytes32 r, bytes32 s) {
        uint256 nonce = IERC20Permit(usdc).nonces(depositor);
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, depositor, address(wallet), value, nonce, eip2612PermitDeadline));
        bytes32 domainSeparator = IERC20Permit(usdc).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (v, r, s) = vm.sign(depositorPrivateKey, digest);
    }

    function test_depositWith2612Permit_revertIfSignatureInvalid() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance);
        r = 0;
        vm.expectRevert(bytes(ECRECOVER_INVALID_SIGNATURE));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWith2612Permit_revertIfValueNonPositive() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(0);
        vm.expectRevert(SpendWallet.DepositValueMustBePositive.selector);
        wallet.depositWithPermit(usdc, depositor, 0, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWith2612Permit_revertIfDeadlinePassed() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance);
        vm.expectRevert(bytes(EIP2612_INVALID_SIGNATURE));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, block.timestamp, v, r, s);
    }

    function test_depositWith2612Permit_revertIfValueExceedsPermitted() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance / 2);
        vm.expectRevert(bytes(EIP2612_INVALID_SIGNATURE));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWith2612Permit_revertIfValueExceedsBalance() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(2 * initialUsdcBalance);
        vm.expectRevert(bytes(ERC20_TRANSFER_AMOUNT_EXCEEDS_BALANCE));
        wallet.depositWithPermit(usdc, depositor, 2 * initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWith2612Permit_spendableBalanceUpdatedAfterTransfer() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance);
        vm.expectEmit(true, true, true, true);
        emit SpendWallet.Deposited(usdc, depositor, initialUsdcBalance);
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
        assertEq(wallet.spendableBalance(usdc, address(depositor)), initialUsdcBalance);
    }

    function test_depositWith2612Permit_revertIfPermitReplayed() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance / 2);
        vm.expectEmit(true, true, true, true);
        emit SpendWallet.Deposited(usdc, depositor, initialUsdcBalance / 2);
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance / 2, eip2612PermitDeadline, v, r, s);
        assertEq(wallet.spendableBalance(usdc, address(depositor)), initialUsdcBalance / 2);

        // Attempt to replay the same permit signature
        vm.expectRevert(bytes(EIP2612_INVALID_SIGNATURE));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance / 2, eip2612PermitDeadline, v, r, s);
    }

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

    function test_depositWith3009Authorization_revertIfSignatureInvalid() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        skip(1 minutes);
        r = 0;
        vm.expectRevert(bytes(ECRECOVER_INVALID_SIGNATURE));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    function test_depositWith3009Authorization_revertIfAuthorizationIsNotYetValid() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        assert(block.timestamp == erc3009ValidAfter);
        vm.expectRevert(bytes(FIATTOKENV2_AUTHORIZATION_IS_NOT_YET_VALID));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    function test_depositWith3009Authorization_revertIfAuthorizationExpired() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        skip(erc3009ValidBefore + 1 minutes);
        vm.expectRevert(bytes(FIATTOKENV2_AUTHORIZATION_IS_EXPIRED));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    function test_depositWith3009Authorization_revertIfValueExceedsAuthorized() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance / 2);
        skip(1 minutes);
        vm.expectRevert(bytes(FIATTOKENV2_INVALID_SIGNATURE));
        // Attempt to deposit more than authorized
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    // TODO revisit
    function test_depositWith3009Authorization_revertIfValueExceedsBalance() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance * 2);
        skip(1 minutes);
        vm.expectRevert(bytes(ERC20_TRANSFER_AMOUNT_EXCEEDS_BALANCE));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance * 2, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }

    function _create3009CancellationSignature() private view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, depositor, erc3009Nonce));
        bytes32 domainSeparator = IERC20Permit(usdc).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (v, r, s) = vm.sign(depositorPrivateKey, digest);
    }

    function test_depositWith3009Authorization_revertIfAuthorizationCancelled() public {
        (uint8 authorizationV, bytes32 authorizationR, bytes32 authorizationS) =
            _create3009AuthorizationSignature(initialUsdcBalance);
        (uint8 cancellationV, bytes32 cancellationR, bytes32 cancellationS) = _create3009CancellationSignature();
        IERC3009(usdc).cancelAuthorization(depositor, erc3009Nonce, cancellationV, cancellationR, cancellationS);

        skip(1 minutes);

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

    function test_depositWith3009Authorization_spendableBalanceUpdatedAfterTransfer() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance);
        skip(1 minutes);
        vm.expectEmit(true, true, true, true);
        emit SpendWallet.Deposited(usdc, depositor, initialUsdcBalance);
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
        assertEq(wallet.spendableBalance(usdc, address(depositor)), initialUsdcBalance);
    }

    function test_depositWith3009Authorization_revertIfAuthorizationReplayed() public {
        (uint8 v, bytes32 r, bytes32 s) = _create3009AuthorizationSignature(initialUsdcBalance / 2);
        skip(1 minutes);
        vm.expectEmit(true, true, true, true);
        emit SpendWallet.Deposited(usdc, depositor, initialUsdcBalance / 2);
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance / 2, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
        assertEq(wallet.spendableBalance(usdc, address(depositor)), initialUsdcBalance / 2);

        // Attemp to replay the same authorization
        vm.expectRevert(bytes(FIATTOKENV2_AUTHORIZATION_USED_OR_CANCELED));
        wallet.depositWithAuthorization(
            usdc, depositor, initialUsdcBalance / 2, erc3009ValidAfter, erc3009ValidBefore, erc3009Nonce, v, r, s
        );
    }
}
