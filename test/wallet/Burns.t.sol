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
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {SpendWallet} from "src/SpendWallet.sol";
import {DelegationStorage} from "src/lib/wallet/Delegation.sol";
import {BurnAuthorization, BurnAuthorizationSet} from "src/lib/authorizations/BurnAuthorizations.sol";
import {BurnAuthorizationLib} from "src/lib/authorizations/BurnAuthorizationLib.sol";
import {TransferSpec, TRANSFER_SPEC_VERSION} from "src/lib/authorizations/TransferSpec.sol";
import {TransferSpecLib} from "src/lib/authorizations/TransferSpecLib.sol";
import {BurnLib} from "src/lib/wallet/BurnLib.sol";
import {_addressToBytes32} from "src/lib/util/addresses.sol";
import {MasterMinter} from "../mock_fiattoken/contracts/minting/MasterMinter.sol";
import {FiatTokenV2_2} from "../mock_fiattoken/contracts/v2/FiatTokenV2_2.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";
import {SignatureTestUtils} from "test/util/SignatureTestUtils.sol";
import {console} from "forge-std/console.sol";

contract TestBurns is SignatureTestUtils, DeployUtils {
    using MessageHashUtils for bytes32;

    uint32 private domain;
    address private owner = makeAddr("owner");
    address private feeRecipient = makeAddr("feeRecipient");
    uint256 private depositorKey;
    address private depositor;
    uint256 private delegateKey;
    address private delegate;
    address private recipient = makeAddr("recipient");
    address private destinationContract = makeAddr("destinationContract");
    address private burnSigner;
    uint256 private burnSignerKey;
    uint256 private defaultMaxBlockHeightOffset = 100;
    uint256 private defaultMaxFee = 10 ** 6;
    uint256 private depositorInitialBalance = 5 * 1000 * 10 ** 6;
    bytes internal constant METADATA = "Test metadata";

    struct ExpectedBurnEventParams {
        address token;
        address depositor;
        bytes32 spendHash;
        uint32 destinationDomain;
        bytes32 recipient;
        address authorizer;
        uint256 value;
        uint256 fee;
        uint256 fromSpendable;
        uint256 fromWithdrawing;
    }

    struct ExpectedBalances {
        uint256 depositorExternalUsdc;
        uint256 depositorSpendable;
        uint256 depositorWithdrawing;
        uint256 feeRecipientExternalUsdc;
        uint256 walletExternalUsdc;
        uint256 usdcTotalSupply;
    }

    FiatTokenV2_2 private usdc;

    BurnAuthorization private baseAuth;

    SpendWallet private wallet;

    function setUp() public {
        domain = ForkTestUtils.forkVars().domain;
        usdc = FiatTokenV2_2(ForkTestUtils.forkVars().usdc);
        wallet = deployWalletOnly(owner, domain);

        (depositor, depositorKey) = makeAddrAndKey("depositor");
        (delegate, delegateKey) = makeAddrAndKey("delegate");
        (burnSigner, burnSignerKey) = makeAddrAndKey("burnSigner");

        vm.startPrank(owner);
        {
            wallet.addSupportedToken(address(usdc));
            wallet.updateDenylister(owner);
            wallet.updateBurnSigner(burnSigner);
            wallet.updateFeeRecipient(feeRecipient);
        }
        vm.stopPrank();

        // Setup wallet as USDC burner
        address masterMinterAddr = usdc.masterMinter();
        if (masterMinterAddr.code.length > 0) {
            MasterMinter masterMinter = MasterMinter(masterMinterAddr);
            address masterMinterOwner = masterMinter.owner();
            vm.startPrank(masterMinterOwner);
            masterMinter.configureController(masterMinterOwner, address(wallet));
            masterMinter.configureMinter(0); // zero allowance, burn only
            vm.stopPrank();
        } else {
            // On testnet MasterMinter can be an EOA
            vm.startPrank(masterMinterAddr);
            usdc.configureMinter(address(wallet), 0); // zero allowance, burn only
            vm.stopPrank();
        }   

        // Setup initial depositor balance
        deal(address(usdc), depositor, depositorInitialBalance, true);
        vm.startPrank(depositor);
        {
            usdc.approve(address(wallet), type(uint256).max);
            wallet.deposit(address(usdc), depositorInitialBalance);
        }
        vm.stopPrank();

        baseAuth = BurnAuthorization({
            maxBlockHeight: block.number + defaultMaxBlockHeightOffset,
            maxFee: defaultMaxFee,
            spec: TransferSpec({
                version: TRANSFER_SPEC_VERSION,
                sourceDomain: domain,
                destinationDomain: domain + 1, // A different destination domain
                sourceContract: _addressToBytes32(address(wallet)),
                destinationContract: _addressToBytes32(destinationContract),
                sourceToken: _addressToBytes32(address(usdc)),
                destinationToken: _addressToBytes32(address(usdc)),
                sourceDepositor: _addressToBytes32(depositor),
                destinationRecipient: _addressToBytes32(recipient),
                sourceSigner: bytes32(0),
                destinationCaller: bytes32(0),
                value: depositorInitialBalance / 2,
                nonce: keccak256("nonce"),
                metadata: METADATA
            })
        });

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
    ) internal {
        bytes memory burnerSignature = _signBurnAuthorizations(authorizations, signatures, fees, signerKey);

        // Call burnSpent with the arguments and signature
        wallet.burnSpent(authorizations, signatures, fees, burnerSignature);
    }

    function _signAuthOrAuthSet(bytes memory authOrAuthSet, uint256 signerKey) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, keccak256(authOrAuthSet).toEthSignedMessageHash());
        signature = abi.encodePacked(r, s, v);
    }

    function _expectBurnEvent(ExpectedBurnEventParams memory params) internal {
        vm.expectEmit(true, true, true, true);
        emit BurnLib.BurnedSpent(
            params.token,
            params.depositor,
            params.spendHash,
            params.destinationDomain,
            params.recipient,
            params.authorizer,
            params.value,
            params.fee,
            params.fromSpendable,
            params.fromWithdrawing
        );
    }

    // ===== Entry Checks / Modifier Tests =====

    function test_burnSpent_revertIfPaused() public {
        vm.startPrank(owner);
        wallet.pause();
        vm.stopPrank();

        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _emptyArgs();
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        wallet.burnSpent(authorizations, signatures, fees, new bytes(0));
    }

    // ===== BurnSigner Signature Tests =====

    // TODO: add this test back after burns are implemented
    // function test_burnSpent_randomArgs_correctSigner() public {
    //     (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _randomArgs();
    //     _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    // }

    function test_burnSpent_randomArgs_wrongSigner() public {
        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _randomArgs();
        (, uint256 wrongSignerKey) = makeAddrAndKey("wrongSigner");
        vm.expectRevert(BurnLib.InvalidBurnSigner.selector);
        _callBurnSpentSignedBy(authorizations, signatures, fees, wrongSignerKey);
    }

    function test_burnSpent_randomArgs_wrongSignatureLength() public {
        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _randomArgs();
        vm.expectRevert(BurnLib.InvalidBurnSigner.selector);
        wallet.burnSpent(authorizations, signatures, fees, bytes(hex"aaaa"));
    }

    // ===== Authorization Structural Validation Tests =====

    function test_burnSpent_revertIfNoAuthorizations() public {
        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _emptyArgs();
        vm.expectRevert(BurnLib.MustHaveAtLeastOneBurnAuthorization.selector);
        wallet.burnSpent(authorizations, signatures, fees, new bytes(0));
    }

    function test_burnSpent_revertIfAuthSetIsEmpty() public {
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: new BurnAuthorization[](0)});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = new bytes(0);
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](0);
        vm.expectRevert(BurnLib.MustHaveAtLeastOneBurnAuthorization.selector);
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_burnSpent_revertIfFeesLengthMismatch() public {
        BurnAuthorization[] memory auths = new BurnAuthorization[](1);
        auths[0] = baseAuth;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: auths});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = new bytes(0);
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](0); // empty, but should have length 1 to match authorizations and signatures
        vm.expectRevert(BurnLib.MismatchedBurn.selector);
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_burnSpent_revertIfInputLengthsMismatched() public {
        vm.expectRevert(BurnLib.MismatchedBurn.selector);
        wallet.burnSpent(new bytes[](2), new bytes[](1), new uint256[][](2), new bytes(0));
    }

    // ===== Authorization Content Validation Tests =====

    function test_burnSpent_revertIfNotAllSameToken() external {
        address notUsdc = makeAddr("notUsdc");
        vm.startPrank(owner);
        wallet.addSupportedToken(notUsdc);
        vm.stopPrank();

        BurnAuthorization memory nonUsdcAuth = baseAuth;
        nonUsdcAuth.spec.sourceToken = _addressToBytes32(notUsdc);

        BurnAuthorization[] memory auths = new BurnAuthorization[](2);
        auths[0] = baseAuth;
        auths[1] = nonUsdcAuth;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: auths});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuthSet, depositorKey);
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](2);

        vm.expectRevert(BurnLib.NotAllSameToken.selector);
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_burnSpent_revertIfZeroValueAuth() public {
        baseAuth.spec.value = 0;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(baseAuth);
        
        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuth, depositorKey);
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);

        vm.expectRevert(abi.encodeWithSelector(BurnLib.BurnValueMustBePositive.selector, 0));
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_burnSpent_revertIfZeroValueAuthSet() public {
        BurnAuthorization memory zeroValueAuth = baseAuth;
        zeroValueAuth.spec.value = 0;

        BurnAuthorization[] memory auths = new BurnAuthorization[](2);
        auths[0] = baseAuth;
        auths[1] = zeroValueAuth;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: auths});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        // Prepare arguments for burnSpent
        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuthSet, depositorKey);

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](2);

        vm.expectRevert(abi.encodeWithSelector(BurnLib.BurnValueMustBePositive.selector, 1));
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_burnSpent_revertIfExpiredAuth() public {
        // Set maxBlockHeight to a past block
        baseAuth.maxBlockHeight = block.number - 1;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(baseAuth);
        
        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuth, depositorKey);
        
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);

        vm.expectRevert(abi.encodeWithSelector(BurnLib.AuthorizationExpired.selector, 0, baseAuth.maxBlockHeight, block.number));
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_burnSpent_revertIfExpiredAuthSet() public {
        BurnAuthorization memory expiredAuth = baseAuth;
        expiredAuth.maxBlockHeight = block.number - 1;

        BurnAuthorization[] memory auths = new BurnAuthorization[](2);
        auths[0] = baseAuth;
        auths[1] = expiredAuth;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: auths});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuthSet, depositorKey);

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](2); 

        vm.expectRevert(abi.encodeWithSelector(BurnLib.AuthorizationExpired.selector, 1, expiredAuth.maxBlockHeight, block.number));
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_burnSpent_revertIfFeeTooHighAuth() public {
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(baseAuth);
        
        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuth, depositorKey);
        
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        uint256 highFee = baseAuth.maxFee + 1;
        fees[0][0] = highFee;

        vm.expectRevert(abi.encodeWithSelector(BurnLib.BurnFeeTooHigh.selector, 0, baseAuth.maxFee, highFee));
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_burnSpent_revertIfFeeTooHighAuthSet() public {
        BurnAuthorization memory highFeeAuth = baseAuth;

        BurnAuthorization[] memory auths = new BurnAuthorization[](2);
        auths[0] = baseAuth;
        auths[1] = highFeeAuth;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: auths});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuthSet, depositorKey);

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](2);
        fees[0][0] = highFeeAuth.maxFee;
        uint256 highFee = highFeeAuth.maxFee + 1;
        fees[0][1] = highFee;

        vm.expectRevert(abi.encodeWithSelector(BurnLib.BurnFeeTooHigh.selector, 1, highFeeAuth.maxFee, highFee));
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_burnSpend_revertIfInvalidSourceContractAuth() public {
        BurnAuthorization memory invalidSourceContractAuth = baseAuth;
        address invalidSourceContract = makeAddr("invalidSourceContract");
        invalidSourceContractAuth.spec.sourceContract = _addressToBytes32(invalidSourceContract);
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(invalidSourceContractAuth);
        
        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuth, depositorKey);
        
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);

        vm.expectRevert(abi.encodeWithSelector(BurnLib.InvalidAuthorizationSourceContract.selector, 0, invalidSourceContract));
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_burnSpend_revertIfInvalidSourceContractAuthSet() public {
        BurnAuthorization memory invalidSourceContractAuth = baseAuth;
        address invalidSourceContract = makeAddr("invalidSourceContract");
        invalidSourceContractAuth.spec.sourceContract = _addressToBytes32(invalidSourceContract);

        BurnAuthorization[] memory auths = new BurnAuthorization[](2);
        auths[0] = baseAuth;
        auths[1] = invalidSourceContractAuth;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: auths});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuthSet, depositorKey);

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](2); 

        vm.expectRevert(abi.encodeWithSelector(BurnLib.InvalidAuthorizationSourceContract.selector, 1, invalidSourceContract));
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_burnSpend_revertIfUnsupportedTokenAuth() public {
        address unsupportedToken = makeAddr("unsupportedToken");
        baseAuth.spec.sourceToken = _addressToBytes32(unsupportedToken);
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(baseAuth);
        
        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuth, depositorKey);
        
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);

        vm.expectRevert(abi.encodeWithSelector(BurnLib.UnsupportedToken.selector, 0, unsupportedToken));
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_burnSpend_revertIfUnsupportedTokenAuthSet() public {
        BurnAuthorization memory unsupportedTokenAuth = baseAuth;
        address unsupportedToken = makeAddr("unsupportedToken");
        unsupportedTokenAuth.spec.sourceToken = _addressToBytes32(unsupportedToken);

        BurnAuthorization[] memory auths = new BurnAuthorization[](2);
        auths[0] = baseAuth;
        auths[1] = unsupportedTokenAuth;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: auths});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuthSet, depositorKey);

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](2); 

        vm.expectRevert(abi.encodeWithSelector(BurnLib.UnsupportedToken.selector, 1, unsupportedToken));
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }
    
    function test_burnSpend_revertIfWasNeverAuthorizedForBalanceAuth() public {
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(baseAuth);
        
        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        
        // Sign with a wrong key
        (, uint256 wrongDepositorKey) = makeAddrAndKey("wrongDepositor");
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuth, wrongDepositorKey);
        
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);

        vm.expectRevert(DelegationStorage.NotAuthorized.selector);
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_burnSpend_revertIfWasNeverAuthorizedForBalanceAuthSet() public {
        BurnAuthorization[] memory auths = new BurnAuthorization[](2);
        auths[0] = baseAuth;
        auths[1] = baseAuth;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: auths});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;

        // Sign with a wrong key
        (, uint256 wrongDepositorKey) = makeAddrAndKey("wrongDepositor");
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuthSet, wrongDepositorKey);

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](2);

        vm.expectRevert(DelegationStorage.NotAuthorized.selector);
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    // ===== Burn Failure Scenarios =====

    function test_burnSpent_singleAuth_revertIfOtherDomain() public {
        BurnAuthorization memory otherDomainAuth = baseAuth;
        otherDomainAuth.spec.sourceDomain = domain + 1; // A different domain

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(otherDomainAuth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, depositorKey);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        fees[0][0] = baseAuth.maxFee;


        vm.expectRevert(BurnLib.NoRelevantBurnAuthorizations.selector);
        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    /*
     * Test Matrix for Successful Burns:
     *
     * This section tests successful `burnSpent` calls by varying several parameters:
     * 1. Input Structure: How authorizations are grouped (single vs. multiple sets, single vs. multiple auths per set).
     * 2. Domain Relevance: Whether authorizations are for the current domain (processed) or another (skipped).
     * 3. Balance Source: Where funds are drawn from (spendable only, withdrawing only, or both).
     * 4. Authorization Signer: Who signed the authorization (the depositor, an authorized delegate, or a now revoked delegate).
     *
     */

    // ===== Burn Success Scenarios - Single Authorization, Single Authorization Set =====

    // General purpose state assertion helper
    function _assertBalances(
        string memory context, // e.g., "Initial State", "After Burn"
        address depositorAddr,
        address feeRecipientAddr,
        ExpectedBalances memory expected
    ) internal view {
        // Fetch actual balances
        uint256 actualDepositorExternalUsdc = usdc.balanceOf(depositorAddr);
        uint256 actualDepositorSpendable = wallet.spendableBalance(address(usdc), depositorAddr);
        uint256 actualDepositorWithdrawing = wallet.withdrawingBalance(address(usdc), depositorAddr);
        uint256 actualFeeRecipientExternalUsdc = usdc.balanceOf(feeRecipientAddr);
        uint256 actualWalletExternalUsdc = usdc.balanceOf(address(wallet));
        uint256 actualUsdcTotalSupply = usdc.totalSupply();

        // Assertions
        assertEq(actualDepositorExternalUsdc, expected.depositorExternalUsdc, string.concat(context, ": Depositor External USDC mismatch"));
        assertEq(actualDepositorSpendable, expected.depositorSpendable, string.concat(context, ": Depositor Spendable mismatch"));
        assertEq(actualDepositorWithdrawing, expected.depositorWithdrawing, string.concat(context, ": Depositor Withdrawing mismatch"));
        assertEq(actualFeeRecipientExternalUsdc, expected.feeRecipientExternalUsdc, string.concat(context, ": Fee Recipient External USDC mismatch"));
        assertEq(actualWalletExternalUsdc, expected.walletExternalUsdc, string.concat(context, ": Wallet External USDC mismatch"));
        assertEq(actualUsdcTotalSupply, expected.usdcTotalSupply, string.concat(context, ": USDC Total Supply mismatch"));
    }

    /// Tests a simple burn scenario: single authorization, signed by the depositor, burning from spendable balance.
    /// 
    /// Steps:
    /// 1. Initial State Check: Use `_assertBalances` to verify initial balances:
    ///    - Depositor: External USDC (0), Internal Spendable (`depositorInitialBalance`), Internal Withdrawing (0).
    ///    - Fee Recipient: External USDC (0).
    ///    - SpendWallet Contract: External USDC (`depositorInitialBalance`).
    ///    - USDC Token: `totalSupply`.
    /// 2. Authorization Setup: Create `BurnAuthorization` for `value` + `fee` and sign it using the depositor's key.
    /// 3. Event Expectation: Set up `_expectBurnEvent` with expected parameters.
    /// 4. Call `burnSpent`: Execute the function via `_callBurnSpentSignedBy` with the authorization, depositor signature, fee, and a valid burner signature.
    /// 5. Final State Check: Use `_assertBalances` to verify final balances.
    ///    - Depositor: External USDC (0), Internal Spendable (`depositorInitialBalance - value - fee`), Internal Withdrawing (0).
    ///    - Fee Recipient: External USDC (`fee`).
    ///    - SpendWallet Contract: External USDC (`depositorInitialBalance - value - fee`).
    ///    - USDC Token: `totalSupply` (should be `initialTotalSupply - value`).
    function test_burnSpent_singleAuth_currentDomain_fromSpendableBalance_depositorSigner() public {
        BurnAuthorization memory auth = baseAuth;
        uint256 burnValue = auth.spec.value;
        uint256 fee = defaultMaxFee / 2;

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, depositorKey);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        fees[0][0] = fee;

        // Assert initial state
        uint256 initialTotalSupply = usdc.totalSupply();
        ExpectedBalances memory initialExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: depositorInitialBalance,
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });
        _assertBalances("Initial State", depositor, feeRecipient, initialExpectedBalances);

        ExpectedBurnEventParams memory expectedParams;
        expectedParams.token = address(usdc);
        expectedParams.depositor = depositor;
        expectedParams.spendHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));
        expectedParams.destinationDomain = auth.spec.destinationDomain;
        expectedParams.recipient = auth.spec.destinationRecipient;
        expectedParams.authorizer = depositor;
        expectedParams.value = burnValue;
        expectedParams.fee = fee;
        expectedParams.fromSpendable = burnValue + fee;
        expectedParams.fromWithdrawing = 0;
        _expectBurnEvent(expectedParams);

        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);

        // Assert final state
        ExpectedBalances memory finalExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: depositorInitialBalance - (burnValue + fee),
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: depositorInitialBalance - (burnValue + fee),
            usdcTotalSupply: initialTotalSupply - burnValue
        });
        _assertBalances("Final State", depositor, feeRecipient, finalExpectedBalances);
    }

    function test_burnSpent_singleAuth_currentDomain_fromSpendableBalance_delegateSigner() public {
        // Setup delegate
        vm.startPrank(depositor);
        wallet.addDelegate(address(usdc), delegate);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        uint256 burnValue = auth.spec.value;
        uint256 fee = defaultMaxFee / 2;

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, delegateKey);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        fees[0][0] = fee;

        // Assert initial state
        uint256 initialTotalSupply = usdc.totalSupply();
        ExpectedBalances memory initialExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: depositorInitialBalance,
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });
        _assertBalances("Initial State (Delegate)", depositor, feeRecipient, initialExpectedBalances);

        ExpectedBurnEventParams memory expectedParams;
        expectedParams.token = address(usdc);
        expectedParams.depositor = depositor;
        expectedParams.spendHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));
        expectedParams.destinationDomain = auth.spec.destinationDomain;
        expectedParams.recipient = auth.spec.destinationRecipient;
        expectedParams.authorizer = delegate; // Authorizer is the delegate
        expectedParams.value = burnValue;
        expectedParams.fee = fee;
        expectedParams.fromSpendable = burnValue + fee;
        expectedParams.fromWithdrawing = 0;
        _expectBurnEvent(expectedParams);

        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);

        // Assert final state
        ExpectedBalances memory finalExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: depositorInitialBalance - (burnValue + fee),
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: depositorInitialBalance - (burnValue + fee),
            usdcTotalSupply: initialTotalSupply - burnValue
        });
        _assertBalances("Final State (Delegate)", depositor, feeRecipient, finalExpectedBalances);
    }

    function test_burnSpent_singleAuth_currentDomain_fromSpendableBalance_revokedDelegateSigner() public {
        // Setup and revoke delegate
        vm.startPrank(depositor);
        wallet.addDelegate(address(usdc), delegate);
        wallet.removeDelegate(address(usdc), delegate);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        uint256 burnValue = auth.spec.value;
        uint256 fee = defaultMaxFee / 2;

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, delegateKey);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        fees[0][0] = fee;

        // Assert initial state
        uint256 initialTotalSupply = usdc.totalSupply();
        ExpectedBalances memory initialExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: depositorInitialBalance,
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });
        _assertBalances("Initial State (Revoked Delegate)", depositor, feeRecipient, initialExpectedBalances);

        ExpectedBurnEventParams memory expectedParams;
        expectedParams.token = address(usdc);
        expectedParams.depositor = depositor;
        expectedParams.spendHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));
        expectedParams.destinationDomain = auth.spec.destinationDomain;
        expectedParams.recipient = auth.spec.destinationRecipient;
        expectedParams.authorizer = delegate; // Revoked delegate
        expectedParams.value = burnValue;
        expectedParams.fee = fee;
        expectedParams.fromSpendable = burnValue + fee;
        expectedParams.fromWithdrawing = 0;
        _expectBurnEvent(expectedParams);

        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);

        // Assert final state
        ExpectedBalances memory finalExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: depositorInitialBalance - (burnValue + fee),
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: depositorInitialBalance - (burnValue + fee),
            usdcTotalSupply: initialTotalSupply - burnValue
        });
        _assertBalances("Final State (Revoked Delegate)", depositor, feeRecipient, finalExpectedBalances);
    }

    function test_burnSpent_singleAuth_currentDomain_fromWithdrawingBalance_depositorSigner() public {
        // Move all depositor funds to withdrawing balance
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(address(usdc), depositorInitialBalance);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        uint256 burnValue = auth.spec.value;
        uint256 fee = defaultMaxFee / 2;

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, depositorKey);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        fees[0][0] = fee;

        // Assert initial state
        uint256 initialTotalSupply = usdc.totalSupply();
        ExpectedBalances memory initialExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: 0,
            depositorWithdrawing: depositorInitialBalance,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });
        _assertBalances("Initial State (Withdrawing)", depositor, feeRecipient, initialExpectedBalances);

        ExpectedBurnEventParams memory expectedParams;
        expectedParams.token = address(usdc);
        expectedParams.depositor = depositor;
        expectedParams.spendHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));
        expectedParams.destinationDomain = auth.spec.destinationDomain;
        expectedParams.recipient = auth.spec.destinationRecipient;
        expectedParams.authorizer = depositor;
        expectedParams.value = burnValue;
        expectedParams.fee = fee;
        expectedParams.fromSpendable = 0;
        expectedParams.fromWithdrawing = burnValue + fee;
        _expectBurnEvent(expectedParams);

        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);

        // Assert final state
        ExpectedBalances memory finalExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: 0,
            depositorWithdrawing: depositorInitialBalance - (burnValue + fee),
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: depositorInitialBalance - (burnValue + fee),
            usdcTotalSupply: initialTotalSupply - burnValue
        });
        _assertBalances("Final State (Withdrawing)", depositor, feeRecipient, finalExpectedBalances);
    }

    function test_burnSpent_singleAuth_currentDomain_fromWithdrawingBalance_delegateSigner() public {
        // Move all depositor funds to withdrawing balance
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(address(usdc), depositorInitialBalance);
        vm.stopPrank();

        // Setup delegate
        vm.startPrank(depositor);
        wallet.addDelegate(address(usdc), delegate);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        uint256 burnValue = auth.spec.value;
        uint256 fee = defaultMaxFee / 2;

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, delegateKey); // Signed by delegate

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        fees[0][0] = fee;

        // Assert initial state
        uint256 initialTotalSupply = usdc.totalSupply();
        ExpectedBalances memory initialExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: 0,
            depositorWithdrawing: depositorInitialBalance,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });
        _assertBalances("Initial State (Withdrawing, Delegate)", depositor, feeRecipient, initialExpectedBalances);

        ExpectedBurnEventParams memory expectedParams;
        expectedParams.token = address(usdc);
        expectedParams.depositor = depositor;
        expectedParams.spendHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));
        expectedParams.destinationDomain = auth.spec.destinationDomain;
        expectedParams.recipient = auth.spec.destinationRecipient;
        expectedParams.authorizer = delegate; // Delegate
        expectedParams.value = burnValue;
        expectedParams.fee = fee;
        expectedParams.fromSpendable = 0;
        expectedParams.fromWithdrawing = burnValue + fee;
        _expectBurnEvent(expectedParams);

        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);

        // Assert final state
        ExpectedBalances memory finalExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: 0,
            depositorWithdrawing: depositorInitialBalance - (burnValue + fee),
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: depositorInitialBalance - (burnValue + fee),
            usdcTotalSupply: initialTotalSupply - burnValue
        });
        _assertBalances("Final State (Withdrawing, Delegate)", depositor, feeRecipient, finalExpectedBalances);
    }

    function test_burnSpent_singleAuth_currentDomain_fromWithdrawingBalance_revokedDelegateSigner() public {
        // Move all depositor funds to withdrawing balance
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(address(usdc), depositorInitialBalance);
        vm.stopPrank();

        // Setup and revoke delegate
        vm.startPrank(depositor);
        wallet.addDelegate(address(usdc), delegate);
        wallet.removeDelegate(address(usdc), delegate);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        uint256 burnValue = auth.spec.value;
        uint256 fee = defaultMaxFee / 2;

        // Encode and sign auth with delegate key *before* revocation
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, delegateKey);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature; // Use signature from before revocation
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        fees[0][0] = fee;

        // Assert initial state
        uint256 initialTotalSupply = usdc.totalSupply();
        ExpectedBalances memory initialExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: 0,
            depositorWithdrawing: depositorInitialBalance,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });
        _assertBalances("Initial State (Withdrawing, Revoked Delegate)", depositor, feeRecipient, initialExpectedBalances);

        ExpectedBurnEventParams memory expectedParams;
        expectedParams.token = address(usdc);
        expectedParams.depositor = depositor;
        expectedParams.spendHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));
        expectedParams.destinationDomain = auth.spec.destinationDomain;
        expectedParams.recipient = auth.spec.destinationRecipient;
        expectedParams.authorizer = delegate;
        expectedParams.value = burnValue;
        expectedParams.fee = fee;
        expectedParams.fromSpendable = 0;
        expectedParams.fromWithdrawing = burnValue + fee;
        _expectBurnEvent(expectedParams);

        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);

        uint256 finalDepositorWithdrawing = depositorInitialBalance - (burnValue + fee);
        uint256 finalWalletExternalUsdc = depositorInitialBalance - (burnValue + fee);
        uint256 finalUsdcTotalSupply = initialTotalSupply - burnValue;

        // Assert final state
        ExpectedBalances memory finalExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: 0,
            depositorWithdrawing: finalDepositorWithdrawing,
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: finalWalletExternalUsdc,
            usdcTotalSupply: finalUsdcTotalSupply
        });
        _assertBalances("Final State (Withdrawing, Revoked Delegate)", depositor, feeRecipient, finalExpectedBalances);
    }

    function test_burnSpent_singleAuth_currentDomain_fromBothBalances_depositorSigner() public {
        // Move some funds to withdrawing balance
        uint256 withdrawAmount = depositorInitialBalance * 3 / 4;
        uint256 remainingSpendable = depositorInitialBalance - withdrawAmount;
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(address(usdc), withdrawAmount);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        uint256 burnValue = auth.spec.value;
        uint256 fee = defaultMaxFee / 2;

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, depositorKey);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        fees[0][0] = fee;

        // Assert initial state
        uint256 initialTotalSupply = usdc.totalSupply();
        ExpectedBalances memory initialExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: remainingSpendable,
            depositorWithdrawing: withdrawAmount,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });
        _assertBalances("Initial State (Both Balances)", depositor, feeRecipient, initialExpectedBalances);

        // Expect event with inlined calculations
        ExpectedBurnEventParams memory expectedParams;
        expectedParams.token = address(usdc);
        expectedParams.depositor = depositor;
        expectedParams.spendHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));
        expectedParams.destinationDomain = auth.spec.destinationDomain;
        expectedParams.recipient = auth.spec.destinationRecipient;
        expectedParams.authorizer = depositor;
        expectedParams.value = burnValue;
        expectedParams.fee = fee;
        expectedParams.fromSpendable = remainingSpendable;
        expectedParams.fromWithdrawing = (burnValue + fee) - remainingSpendable;
        _expectBurnEvent(expectedParams);

        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);

        uint256 finalDepositorWithdrawing = withdrawAmount - ((burnValue + fee) - remainingSpendable);
        uint256 finalWalletExternalUsdc = depositorInitialBalance - (burnValue + fee);
        uint256 finalUsdcTotalSupply = initialTotalSupply - burnValue;

        // Assert final state
        ExpectedBalances memory finalExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: 0, // Spendable used up
            depositorWithdrawing: finalDepositorWithdrawing,
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: finalWalletExternalUsdc,
            usdcTotalSupply: finalUsdcTotalSupply
        });
        _assertBalances("Final State (Both Balances)", depositor, feeRecipient, finalExpectedBalances);
    }

    function test_burnSpent_singleAuth_currentDomain_fromBothBalances_delegateSigner() public {
        // Move some funds to withdrawing balance
        uint256 withdrawAmount = depositorInitialBalance * 3 / 4;
        uint256 remainingSpendable = depositorInitialBalance - withdrawAmount;
        
        // Setup delegate
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(address(usdc), withdrawAmount);
        wallet.addDelegate(address(usdc), delegate);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        uint256 burnValue = auth.spec.value;
        uint256 fee = defaultMaxFee / 2;

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, delegateKey);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        fees[0][0] = fee;

        // Assert initial state
        uint256 initialTotalSupply = usdc.totalSupply();
        ExpectedBalances memory initialExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: remainingSpendable,
            depositorWithdrawing: withdrawAmount,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });
        _assertBalances("Initial State (Both Balances)", depositor, feeRecipient, initialExpectedBalances);

        // Expect event with inlined calculations
        ExpectedBurnEventParams memory expectedParams;
        expectedParams.token = address(usdc);
        expectedParams.depositor = depositor;
        expectedParams.spendHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));
        expectedParams.destinationDomain = auth.spec.destinationDomain;
        expectedParams.recipient = auth.spec.destinationRecipient;
        expectedParams.authorizer = delegate;
        expectedParams.value = burnValue;
        expectedParams.fee = fee;
        expectedParams.fromSpendable = remainingSpendable;
        expectedParams.fromWithdrawing = (burnValue + fee) - remainingSpendable;
        _expectBurnEvent(expectedParams);

        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);

        uint256 finalDepositorWithdrawing = withdrawAmount - ((burnValue + fee) - remainingSpendable);
        uint256 finalWalletExternalUsdc = depositorInitialBalance - (burnValue + fee);
        uint256 finalUsdcTotalSupply = initialTotalSupply - burnValue;

        // Assert final state
        ExpectedBalances memory finalExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: 0, // Spendable used up
            depositorWithdrawing: finalDepositorWithdrawing,
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: finalWalletExternalUsdc,
            usdcTotalSupply: finalUsdcTotalSupply
        });
        _assertBalances("Final State (Both Balances)", depositor, feeRecipient, finalExpectedBalances);
    }

    function test_burnSpent_singleAuth_currentDomain_fromBothBalances_revokedDelegateSigner() public {
        // Move some funds to withdrawing balance
        uint256 withdrawAmount = depositorInitialBalance * 3 / 4;
        uint256 remainingSpendable = depositorInitialBalance - withdrawAmount;
        
        // Setup and revoke delegate
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(address(usdc), withdrawAmount);
        wallet.addDelegate(address(usdc), delegate);
        wallet.removeDelegate(address(usdc), delegate);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        uint256 burnValue = auth.spec.value;
        uint256 fee = defaultMaxFee / 2;

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, delegateKey);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        fees[0][0] = fee;

        // Assert initial state
        uint256 initialTotalSupply = usdc.totalSupply();
        ExpectedBalances memory initialExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: remainingSpendable,
            depositorWithdrawing: withdrawAmount,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });
        _assertBalances("Initial State (Both Balances)", depositor, feeRecipient, initialExpectedBalances);

        // Expect event with inlined calculations
        ExpectedBurnEventParams memory expectedParams;
        expectedParams.token = address(usdc);
        expectedParams.depositor = depositor;
        expectedParams.spendHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));
        expectedParams.destinationDomain = auth.spec.destinationDomain;
        expectedParams.recipient = auth.spec.destinationRecipient;
        expectedParams.authorizer = delegate;
        expectedParams.value = burnValue;
        expectedParams.fee = fee;
        expectedParams.fromSpendable = remainingSpendable;
        expectedParams.fromWithdrawing = (burnValue + fee) - remainingSpendable;
        _expectBurnEvent(expectedParams);

        _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);

        uint256 finalDepositorWithdrawing = withdrawAmount - ((burnValue + fee) - remainingSpendable);
        uint256 finalWalletExternalUsdc = depositorInitialBalance - (burnValue + fee);
        uint256 finalUsdcTotalSupply = initialTotalSupply - burnValue;

        // Assert final state
        ExpectedBalances memory finalExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorSpendable: 0, // Spendable used up
            depositorWithdrawing: finalDepositorWithdrawing,
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: finalWalletExternalUsdc,
            usdcTotalSupply: finalUsdcTotalSupply
        });
        _assertBalances("Final State (Both Balances)", depositor, feeRecipient, finalExpectedBalances);
    }

}
