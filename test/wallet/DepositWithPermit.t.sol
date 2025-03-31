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

import {SpendWallet} from "src/SpendWallet.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {Test} from "forge-std/Test.sol";

/// Tests EIP-2612 permit deposit functionality of SpendWallet
contract SpendWalletDepositWithPermitTest is Test, DeployUtils {
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
    string private constant EIP2612_INVALID_SIGNATURE = "EIP2612: invalid signature";
    string private constant ECRECOVER_INVALID_SIGNATURE = "ECRecover: invalid signature";
    string private constant FIATTOKENV2_PERMIT_EXPIRED = "FiatTokenV2: permit is expired";

    SpendWallet private wallet;

    function setUp() public {
        (depositor, depositorPrivateKey) = makeAddrAndKey("spendWalletDepositor");
        wallet = deployWalletOnly(owner);

        usdc = ForkTestUtils.forkVars().usdc;
        vm.prank(owner);
        wallet.addSupportedToken(usdc);
        // Mint initial USDC balance to depositor
        deal(usdc, depositor, initialUsdcBalance);

        eip2612PermitDeadline = block.timestamp + 1 days;
        activeTimeOffset = 1 minutes;
        inactiveTimeOffset = 2 days;
    }

    function _create2612PermitSignature(uint256 value) private view returns (uint8 v, bytes32 r, bytes32 s) {
        uint256 nonce = IERC20Permit(usdc).nonces(depositor);
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, depositor, address(wallet), value, nonce, eip2612PermitDeadline));
        bytes32 domainSeparator = IERC20Permit(usdc).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (v, r, s) = vm.sign(depositorPrivateKey, digest);
    }

    function test_depositWithPermit_revertIfSignatureInvalid() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance);
        r = 0;
        vm.expectRevert(bytes(ECRECOVER_INVALID_SIGNATURE));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWithPermit_revertIfValueNonPositive() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(0);
        vm.expectRevert(SpendWallet.DepositValueMustBePositive.selector);
        wallet.depositWithPermit(usdc, depositor, 0, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWithPermit_revertIfDeadlinePassed() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance);
        skip(inactiveTimeOffset);
        vm.expectRevert(bytes(FIATTOKENV2_PERMIT_EXPIRED));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWithPermit_revertIfValueExceedsPermitted() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance / 2);
        vm.expectRevert(bytes(EIP2612_INVALID_SIGNATURE));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWithPermit_revertIfValueExceedsBalance() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(2 * initialUsdcBalance);
        vm.expectRevert(bytes("ERC20: transfer amount exceeds balance"));
        wallet.depositWithPermit(usdc, depositor, 2 * initialUsdcBalance, eip2612PermitDeadline, v, r, s);
    }

    function test_depositWithPermit_spendableBalanceUpdatedAfterTransfer() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance);
        vm.expectEmit(true, true, false, true);
        emit SpendWallet.Deposited(usdc, depositor, initialUsdcBalance);
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance, eip2612PermitDeadline, v, r, s);
        assertEq(wallet.spendableBalance(usdc, depositor), initialUsdcBalance);
    }

    function test_depositWithPermit_revertIfPermitReplayed() public {
        (uint8 v, bytes32 r, bytes32 s) = _create2612PermitSignature(initialUsdcBalance / 2);
        vm.expectEmit(true, true, false, true);
        emit SpendWallet.Deposited(usdc, depositor, initialUsdcBalance / 2);
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance / 2, eip2612PermitDeadline, v, r, s);
        assertEq(wallet.spendableBalance(usdc, depositor), initialUsdcBalance / 2);

        // Attempt to replay the same permit signature
        vm.expectRevert(bytes(EIP2612_INVALID_SIGNATURE));
        wallet.depositWithPermit(usdc, depositor, initialUsdcBalance / 2, eip2612PermitDeadline, v, r, s);
    }
}