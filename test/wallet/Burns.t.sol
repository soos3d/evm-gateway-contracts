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
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {GatewayWallet} from "src/GatewayWallet.sol";
import {BurnAuthorizationLib} from "src/lib/authorizations/BurnAuthorizationLib.sol";
import {BurnAuthorization, BurnAuthorizationSet} from "src/lib/authorizations/BurnAuthorizations.sol";
import {TransferSpec, TRANSFER_SPEC_VERSION} from "src/lib/authorizations/TransferSpec.sol";
import {TransferSpecLib} from "src/lib/authorizations/TransferSpecLib.sol";
import {AddressLib} from "src/lib/util/AddressLib.sol";
import {TransferSpecHashes} from "src/modules/common/TransferSpecHashes.sol";
import {Burns} from "src/modules/wallet/Burns.sol";
import {Delegation} from "src/modules/wallet/Delegation.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";
import {SignatureTestUtils} from "test/util/SignatureTestUtils.sol";
import {MasterMinter} from "./../mock_fiattoken/contracts/minting/MasterMinter.sol";
import {FiatTokenV2_2} from "./../mock_fiattoken/contracts/v2/FiatTokenV2_2.sol";

// solhint-disable max-states-count
contract TestBurns is SignatureTestUtils, DeployUtils {
    using MessageHashUtils for bytes32;

    uint32 private domain;
    address private owner = makeAddr("owner");
    address private feeRecipient = makeAddr("feeRecipient");
    uint256 private depositorKey;
    address private depositor;
    uint256 private depositor2Key;
    address private depositor2;
    uint256 private underFundedDepositorKey;
    address private underFundedDepositor;
    uint256 private delegateKey;
    address private delegate;
    address private recipient = makeAddr("recipient");
    address private otherToken = makeAddr("otherToken");
    address private destinationContract = makeAddr("destinationContract");
    address private destinationToken = makeAddr("destinationToken");
    address private burnSigner;
    uint256 private burnSignerKey;
    uint256 private defaultMaxBlockHeightOffset = 100;
    uint256 private defaultMaxFee = 10 ** 6;
    uint256 private depositorInitialBalance = 5 * 1000 * 10 ** 6;
    uint256 private depositor2InitialBalance = 3 * 1000 * 10 ** 6;
    bytes internal constant METADATA = "Test metadata";

    struct ExpectedBurnEventParams {
        address token;
        address depositor;
        bytes32 transferSpecHash;
        uint32 destinationDomain;
        bytes32 recipient;
        address authorizer;
        uint256 value;
        uint256 fee;
        uint256 fromAvailable;
        uint256 fromWithdrawing;
    }

    struct ExpectedBalances {
        uint256 depositorExternalUsdc;
        uint256 depositorAvailable;
        uint256 depositorWithdrawing;
        uint256 feeRecipientExternalUsdc;
        uint256 walletExternalUsdc;
        uint256 usdcTotalSupply;
    }

    FiatTokenV2_2 private usdc;

    BurnAuthorization private baseAuth;

    GatewayWallet private wallet;

    function setUp() public {
        domain = ForkTestUtils.forkVars().domain;
        usdc = FiatTokenV2_2(ForkTestUtils.forkVars().usdc);
        wallet = deployWalletOnly(owner, domain);

        (depositor, depositorKey) = makeAddrAndKey("depositor");
        (depositor2, depositor2Key) = makeAddrAndKey("depositor2");
        (underFundedDepositor, underFundedDepositorKey) = makeAddrAndKey("underFundedDepositor");
        (delegate, delegateKey) = makeAddrAndKey("delegate");
        (burnSigner, burnSignerKey) = makeAddrAndKey("burnSigner");

        vm.startPrank(owner);
        {
            wallet.addSupportedToken(address(usdc));
            wallet.addSupportedToken(otherToken);
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
                sourceContract: AddressLib._addressToBytes32(address(wallet)),
                destinationContract: AddressLib._addressToBytes32(destinationContract),
                sourceToken: AddressLib._addressToBytes32(address(usdc)),
                destinationToken: AddressLib._addressToBytes32(destinationToken),
                sourceDepositor: AddressLib._addressToBytes32(depositor),
                destinationRecipient: AddressLib._addressToBytes32(recipient),
                sourceSigner: AddressLib._addressToBytes32(depositor),
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

    function _callGatewayBurnSignedBy(
        bytes[] memory authorizations,
        bytes[] memory signatures,
        uint256[][] memory fees,
        uint256 signerKey
    ) internal {
        bytes memory burnerSignature = _signBurnAuthorizations(authorizations, signatures, fees, signerKey);

        // Call gatewayBurn with the arguments and signature
        wallet.gatewayBurn(authorizations, signatures, fees, burnerSignature);
    }

    function _signAuthOrAuthSet(bytes memory authOrAuthSet, uint256 signerKey)
        internal
        pure
        returns (bytes memory signature)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, keccak256(authOrAuthSet).toEthSignedMessageHash());
        signature = abi.encodePacked(r, s, v);
    }

    function _expectBurnEvent(ExpectedBurnEventParams memory params) internal {
        vm.expectEmit(true, true, true, true);
        emit Burns.GatewayBurned(
            params.token,
            params.depositor,
            params.transferSpecHash,
            params.destinationDomain,
            params.recipient,
            params.authorizer,
            params.value,
            params.fee,
            params.fromAvailable,
            params.fromWithdrawing
        );
    }

    // ===== Entry Checks / Modifier Tests =====

    function test_gatewayBurn_revertIfPaused() public {
        vm.startPrank(owner);
        wallet.pause();
        vm.stopPrank();

        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _emptyArgs();
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        wallet.gatewayBurn(authorizations, signatures, fees, new bytes(0));
    }

    // ===== BurnSigner Signature Tests =====

    function test_gatewayBurn_randomArgs_wrongSigner() public {
        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _randomArgs();
        (, uint256 wrongSignerKey) = makeAddrAndKey("wrongSigner");
        vm.expectRevert(Burns.InvalidBurnSigner.selector);
        _callGatewayBurnSignedBy(authorizations, signatures, fees, wrongSignerKey);
    }

    function test_gatewayBurn_randomArgs_wrongSignatureLength() public {
        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _randomArgs();
        vm.expectRevert(Burns.InvalidBurnSigner.selector);
        wallet.gatewayBurn(authorizations, signatures, fees, bytes(hex"aaaa"));
    }

    // ===== Authorization Structural Validation Tests =====

    function test_gatewayBurn_revertIfNoAuthorizations() public {
        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _emptyArgs();
        vm.expectRevert(Burns.MustHaveAtLeastOneBurnAuthorization.selector);
        wallet.gatewayBurn(authorizations, signatures, fees, new bytes(0));
    }

    function test_gatewayBurn_revertIfAuthSetIsEmpty() public {
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: new BurnAuthorization[](0)});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = new bytes(0);
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](0);
        vm.expectRevert(Burns.MustHaveAtLeastOneBurnAuthorization.selector);
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfFeesLengthMismatch() public {
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
        vm.expectRevert(Burns.MismatchedBurn.selector);
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfInputLengthsMismatched() public {
        vm.expectRevert(Burns.MismatchedBurn.selector);
        wallet.gatewayBurn(new bytes[](2), new bytes[](1), new uint256[][](2), new bytes(0));
    }

    // ===== Authorization Content Validation Tests =====

    function test_gatewayBurn_revertIfZeroValueAuth() public {
        baseAuth.spec.value = 0;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(baseAuth);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuth, depositorKey);
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);

        vm.expectRevert(abi.encodeWithSelector(Burns.AuthorizationValueMustBePositiveAtIndex.selector, 0));
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfZeroValueAuthSet() public {
        BurnAuthorization memory zeroValueAuth = baseAuth;
        zeroValueAuth.spec.value = 0;

        BurnAuthorization[] memory auths = new BurnAuthorization[](2);
        auths[0] = baseAuth;
        auths[1] = zeroValueAuth;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: auths});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        // Prepare arguments for gatewayBurn
        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuthSet, depositorKey);

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](2);

        vm.expectRevert(abi.encodeWithSelector(Burns.AuthorizationValueMustBePositiveAtIndex.selector, 1));
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfExpiredAuth() public {
        // Set maxBlockHeight to a past block
        baseAuth.maxBlockHeight = block.number - 1;
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(baseAuth);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuth, depositorKey);

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);

        vm.expectRevert(
            abi.encodeWithSelector(Burns.AuthorizationExpiredAtIndex.selector, 0, baseAuth.maxBlockHeight, block.number)
        );
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfExpiredAuthSet() public {
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

        vm.expectRevert(
            abi.encodeWithSelector(
                Burns.AuthorizationExpiredAtIndex.selector, 1, expiredAuth.maxBlockHeight, block.number
            )
        );
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfFeeTooHighAuth() public {
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(baseAuth);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuth, depositorKey);

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        uint256 highFee = baseAuth.maxFee + 1;
        fees[0][0] = highFee;

        vm.expectRevert(abi.encodeWithSelector(Burns.BurnFeeTooHighAtIndex.selector, 0, baseAuth.maxFee, highFee));
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfFeeTooHighAuthSet() public {
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

        vm.expectRevert(abi.encodeWithSelector(Burns.BurnFeeTooHighAtIndex.selector, 1, highFeeAuth.maxFee, highFee));
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfInvalidSourceContractAuth() public {
        BurnAuthorization memory invalidSourceContractAuth = baseAuth;
        address invalidSourceContract = makeAddr("invalidSourceContract");
        invalidSourceContractAuth.spec.sourceContract = AddressLib._addressToBytes32(invalidSourceContract);
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(invalidSourceContractAuth);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuth, depositorKey);

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);

        vm.expectRevert(
            abi.encodeWithSelector(
                Burns.InvalidAuthorizationSourceContractAtIndex.selector, 0, invalidSourceContract, address(wallet)
            )
        );
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfInvalidSourceContractAuthSet() public {
        BurnAuthorization memory invalidSourceContractAuth = baseAuth;
        address invalidSourceContract = makeAddr("invalidSourceContract");
        invalidSourceContractAuth.spec.sourceContract = AddressLib._addressToBytes32(invalidSourceContract);

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

        vm.expectRevert(
            abi.encodeWithSelector(
                Burns.InvalidAuthorizationSourceContractAtIndex.selector, 1, invalidSourceContract, address(wallet)
            )
        );
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfUnsupportedTokenAuth() public {
        address unsupportedToken = makeAddr("unsupportedToken");
        baseAuth.spec.sourceToken = AddressLib._addressToBytes32(unsupportedToken);
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(baseAuth);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuth, depositorKey);

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);

        vm.expectRevert(abi.encodeWithSelector(Burns.UnsupportedTokenAtIndex.selector, 0, unsupportedToken));
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfUnsupportedTokenAuthSet() public {
        BurnAuthorization memory unsupportedTokenAuth = baseAuth;
        address unsupportedToken = makeAddr("unsupportedToken");
        unsupportedTokenAuth.spec.sourceToken = AddressLib._addressToBytes32(unsupportedToken);

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

        vm.expectRevert(abi.encodeWithSelector(Burns.UnsupportedTokenAtIndex.selector, 1, unsupportedToken));
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfWasNeverAuthorizedForBalanceAuth() public {
        BurnAuthorization memory neverAuthorizedAuth = baseAuth;
        (address neverAuthorizedSigner, uint256 neverAuthorizedSignerKey) = makeAddrAndKey("neverAuthorizedSigner");
        neverAuthorizedAuth.spec.sourceSigner = AddressLib._addressToBytes32(neverAuthorizedSigner);
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(neverAuthorizedAuth);
        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;

        // Sign with a wrong key
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuth, neverAuthorizedSignerKey);

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);

        vm.expectRevert(Delegation.NotAuthorized.selector);
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfWasNeverAuthorizedForBalanceAuthSet() public {
        BurnAuthorization[] memory auths = new BurnAuthorization[](2);
        (address neverAuthorizedSigner, uint256 neverAuthorizedSignerKey) = makeAddrAndKey("neverAuthorizedSigner");
        auths[0] = baseAuth;
        auths[0].spec.sourceSigner = AddressLib._addressToBytes32(neverAuthorizedSigner);
        auths[1] = baseAuth;
        auths[1].spec.sourceSigner = AddressLib._addressToBytes32(neverAuthorizedSigner);
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: auths});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuthSet, neverAuthorizedSignerKey);

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](2);

        vm.expectRevert(Delegation.NotAuthorized.selector);
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfInvalidSourceSignerAuth() public {
        BurnAuthorization memory mismatchedSignerAuth = baseAuth;
        address anotherAddress = makeAddr("anotherAddress");
        mismatchedSignerAuth.spec.sourceSigner = AddressLib._addressToBytes32(anotherAddress);
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(mismatchedSignerAuth);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuth, depositorKey); // Signed by depositor but sourceSigner is anotherAddress

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);

        vm.expectRevert(
            abi.encodeWithSelector(Burns.InvalidAuthorizationSourceSignerAtIndex.selector, 0, anotherAddress, depositor)
        );
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfInvalidSourceSignerAuthSet() public {
        BurnAuthorization memory auth1 = baseAuth;
        BurnAuthorization memory auth2MismatchedSigner = baseAuth;
        address anotherAddress = makeAddr("anotherAddress");
        auth2MismatchedSigner.spec.sourceSigner = AddressLib._addressToBytes32(anotherAddress);

        BurnAuthorization[] memory auths = new BurnAuthorization[](2);
        auths[0] = auth1;
        auths[1] = auth2MismatchedSigner;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: auths});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuthSet, depositorKey); // Signed by depositor

        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](2);

        vm.expectRevert(
            abi.encodeWithSelector(Burns.InvalidAuthorizationSourceSignerAtIndex.selector, 1, anotherAddress, depositor)
        );
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    // ===== Burn Failure Scenarios =====

    function test_gatewayBurn_revertIfReplayed() public {
        BurnAuthorization memory auth = baseAuth;

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, depositorKey);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        fees[0][0] = 0;

        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);

        // Replay the same authorization
        bytes32 specHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));
        vm.expectRevert(abi.encodeWithSelector(TransferSpecHashes.TransferSpecHashUsed.selector, specHash));
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_revertIfNotAllSameToken() external {
        address notUsdc = makeAddr("notUsdc");
        vm.startPrank(owner);
        wallet.addSupportedToken(notUsdc);
        vm.stopPrank();

        BurnAuthorization memory nonUsdcAuth = baseAuth;
        nonUsdcAuth.spec.sourceToken = AddressLib._addressToBytes32(notUsdc);

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

        vm.expectRevert(Burns.NotAllSameToken.selector);
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_singleAuth_revertIfOtherSourceDomain() public {
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

        vm.expectRevert(Burns.NoRelevantBurnAuthorizations.selector);
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_singleAuthSet_revertIfOtherSourceDomain() public {
        BurnAuthorization memory otherDomainAuth = baseAuth;
        otherDomainAuth.spec.sourceDomain = domain + 1; // A different domain

        BurnAuthorization[] memory auths = new BurnAuthorization[](2);
        auths[0] = otherDomainAuth;
        auths[1] = otherDomainAuth;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: auths});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuthSet, depositorKey);
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](2);
        fees[0][0] = baseAuth.maxFee;
        fees[0][1] = baseAuth.maxFee;

        vm.expectRevert(Burns.NoRelevantBurnAuthorizations.selector);
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_singleAuth_revertIfSameDestinationDomain() public {
        BurnAuthorization memory sameDestDomainAuth = baseAuth;
        sameDestDomainAuth.spec.destinationDomain = domain; // The same domain as source

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(sameDestDomainAuth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, depositorKey);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        fees[0][0] = baseAuth.maxFee;

        vm.expectRevert(Burns.NoRelevantBurnAuthorizations.selector);
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    function test_gatewayBurn_singleAuthSet_revertIfSameDestinationDomain() public {
        BurnAuthorization memory sameDestDomainAuth = baseAuth;
        sameDestDomainAuth.spec.destinationDomain = domain; // The same domain as source

        BurnAuthorization[] memory auths = new BurnAuthorization[](2);
        auths[0] = sameDestDomainAuth;
        auths[1] = sameDestDomainAuth;
        BurnAuthorizationSet memory authSet = BurnAuthorizationSet({authorizations: auths});
        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuthSet;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signAuthOrAuthSet(encodedAuthSet, depositorKey);
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](2);
        fees[0][0] = baseAuth.maxFee;
        fees[0][1] = baseAuth.maxFee;

        vm.expectRevert(Burns.NoRelevantBurnAuthorizations.selector);
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);
    }

    // ===== Insufficient Balance Tests =====

    struct AuthSetInsufficientBalanceTestData {
        uint256 initialDeposit;
        uint256 depositorKey;
        address depositorAddr;
        uint256 fee1;
        uint256 fee2;
        uint256 value1;
        uint256 value2;
        BurnAuthorization auth1;
        BurnAuthorization auth2;
        BurnAuthorization[] authsForSet;
        BurnAuthorizationSet authSet;
        bytes encodedAuthSet;
        bytes signature;
        bytes[] authorizations;
        bytes[] signatures;
        uint256[][] fees;
        uint256 initialTotalSupply;
        uint256 initialWalletBalance;
        uint256 initialFeeRecipientBalance;
        ExpectedBalances initialBalances;
        ExpectedBalances finalBalances;
        ExpectedBurnEventParams eventParams1;
        uint256 insufficientEventValueNeeded;
        uint256 insufficientEventAvailableAvailable;
        uint256 insufficientEventWithdrawingAvailable;
        ExpectedBurnEventParams eventParams2;
    }

    function test_gatewayBurn_singleAuth_insufficientBalanceForBurnValue() public {
        // Setup the under funded depositor
        deal(address(usdc), underFundedDepositor, depositorInitialBalance, true); // Fund externally with initial $5000
        vm.startPrank(underFundedDepositor);
        usdc.approve(address(wallet), type(uint256).max);
        wallet.deposit(address(usdc), depositorInitialBalance / 4); // Deposit $1250 (1/4 of initial)
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        auth.spec.value = 2500 * 10 ** 6; // $2500
        auth.spec.sourceDepositor = AddressLib._addressToBytes32(underFundedDepositor);
        auth.spec.sourceSigner = AddressLib._addressToBytes32(underFundedDepositor);
        uint256 fee = defaultMaxFee / 2; // $0.50

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, underFundedDepositorKey);

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
            depositorExternalUsdc: depositorInitialBalance * 3 / 4, // $3750 external
            depositorAvailable: depositorInitialBalance / 4, // $1250 available
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance + depositorInitialBalance / 4, // $5000 (original depositor) + $1250 (underFundedDepositor) = $6250 total in wallet
            usdcTotalSupply: initialTotalSupply
        });
        _assertBalances("Initial State", underFundedDepositor, feeRecipient, initialExpectedBalances);

        vm.expectEmit(true, true, true, true);
        emit Burns.InsufficientBalance(
            address(usdc),
            underFundedDepositor,
            auth.spec.value + fee, // Total needed: $2500 + $0.50 = $2500.50
            depositorInitialBalance / 4, // Available available: $1250
            0 // Withdrawing available: $0
        );

        ExpectedBurnEventParams memory expectedParams;
        expectedParams.token = address(usdc);
        expectedParams.depositor = underFundedDepositor;
        expectedParams.transferSpecHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));
        expectedParams.destinationDomain = auth.spec.destinationDomain;
        expectedParams.recipient = auth.spec.destinationRecipient;
        expectedParams.authorizer = underFundedDepositor;
        expectedParams.value = depositorInitialBalance / 4; // fromAvailable - fee
        expectedParams.fee = 0; // Actual fee charged: $0 (waived)
        expectedParams.fromAvailable = depositorInitialBalance / 4; // Actual amount deducted from available: $1250
        expectedParams.fromWithdrawing = 0;
        _expectBurnEvent(expectedParams);

        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);

        // Assert final state
        ExpectedBalances memory finalExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: depositorInitialBalance * 3 / 4, // $3750
            depositorAvailable: 0, // Available becomes $0
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: 0, // Fee recipient gets $0
            walletExternalUsdc: depositorInitialBalance, // Wallet balance: $6250 - $1250 = $5000
            usdcTotalSupply: initialTotalSupply - depositorInitialBalance / 4 // Total supply reduced by $1250
        });
        _assertBalances("Final State", underFundedDepositor, feeRecipient, finalExpectedBalances);
    }

    /// Tests gatewayBurn with an authorization set containing two auths for the same depositor.
    /// The first auth succeeds, but depletes the balance such that the second auth
    /// triggers the InsufficientBalance event and results in a partial burn value and zero fee.
    function test_gatewayBurn_singleAuthSet_secondAuthHasInsufficientBalanceForBurnValue() public {
        AuthSetInsufficientBalanceTestData memory testData;

        (testData.depositorAddr, testData.depositorKey) = makeAddrAndKey("partiallyFundedDepositor");
        testData.initialDeposit = 1000 * 10 ** 6; // $1000.00
        testData.value1 = 600 * 10 ** 6; // $600.00
        testData.fee1 = defaultMaxFee / 5; // $0.20
        testData.value2 = 500 * 10 ** 6; // $500.00 (Needs $500.10 total)
        testData.fee2 = defaultMaxFee / 10; // $0.10

        // Setup the depositor's balance
        deal(address(usdc), testData.depositorAddr, testData.initialDeposit, true);
        vm.startPrank(testData.depositorAddr);
        usdc.approve(address(wallet), type(uint256).max);
        wallet.deposit(address(usdc), testData.initialDeposit);
        vm.stopPrank();

        // Auth 1 (should succeed)
        testData.auth1 = baseAuth;
        testData.auth1.spec.sourceDepositor = AddressLib._addressToBytes32(testData.depositorAddr);
        testData.auth1.spec.sourceSigner = AddressLib._addressToBytes32(testData.depositorAddr);
        testData.auth1.spec.value = testData.value1;
        testData.auth1.maxFee = defaultMaxFee;

        // Auth 2 (should have insufficient funds after Auth 1)
        testData.auth2 = baseAuth;
        testData.auth2.spec.sourceDepositor = AddressLib._addressToBytes32(testData.depositorAddr);
        testData.auth2.spec.sourceSigner = AddressLib._addressToBytes32(testData.depositorAddr);
        testData.auth2.spec.value = testData.value2;
        testData.auth2.maxFee = defaultMaxFee;

        testData.authsForSet = new BurnAuthorization[](2);
        testData.authsForSet[0] = testData.auth1;
        testData.authsForSet[1] = testData.auth2;
        testData.authSet = BurnAuthorizationSet({authorizations: testData.authsForSet});
        testData.encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(testData.authSet);

        testData.signature = _signAuthOrAuthSet(testData.encodedAuthSet, testData.depositorKey);

        testData.authorizations = new bytes[](1);
        testData.authorizations[0] = testData.encodedAuthSet;
        testData.signatures = new bytes[](1);
        testData.signatures[0] = testData.signature;
        testData.fees = new uint256[][](1);
        testData.fees[0] = new uint256[](2);
        testData.fees[0][0] = testData.fee1;
        testData.fees[0][1] = testData.fee2;

        testData.initialTotalSupply = usdc.totalSupply();
        testData.initialWalletBalance = usdc.balanceOf(address(wallet));
        testData.initialFeeRecipientBalance = usdc.balanceOf(feeRecipient);

        uint256 balanceAfterAuth1 = testData.initialDeposit - (testData.value1 + testData.fee1); // $1000 - ($600 + $0.20) = $399.80
        uint256 neededForAuth2 = testData.value2 + testData.fee2; // $500 + $0.10 = $500.10
        uint256 deductedForAuth2 = balanceAfterAuth1; // $399.80 (since $399.80 < $500.10)
        uint256 actualFeeAuth2 = 0; // Since deductedForAuth2 ($399.80) <= value2 ($500)
        uint256 actualValueBurnedAuth2 = deductedForAuth2 - actualFeeAuth2; // $399.80 - $0 = $399.80

        // Initial Balances
        testData.initialBalances = ExpectedBalances({
            depositorExternalUsdc: 0, // Depositor transferred all funds in
            depositorAvailable: testData.initialDeposit,
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: testData.initialFeeRecipientBalance, // May have balance from other tests
            walletExternalUsdc: testData.initialWalletBalance, // Wallet holds initial depositor + this new one
            usdcTotalSupply: testData.initialTotalSupply
        });

        // Final Balances
        uint256 finalTotalValueBurned = testData.value1 + actualValueBurnedAuth2; // $600 + $399.80 = $999.80
        uint256 finalTotalFeeCharged = testData.fee1 + actualFeeAuth2; // $0.20 + $0 = $0.20
        uint256 finalTotalDeducted = (testData.value1 + testData.fee1) + deductedForAuth2; // $600.20 + $399.80 = $1000.00

        testData.finalBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: 0, // Fully depleted
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: testData.initialFeeRecipientBalance + finalTotalFeeCharged, // Initial + $0.20
            walletExternalUsdc: testData.initialWalletBalance - finalTotalDeducted, // Initial wallet bal - $1000
            usdcTotalSupply: testData.initialTotalSupply - finalTotalValueBurned // Initial supply - $999.80
        });

        // Event 1 (Auth 1)
        testData.eventParams1 = ExpectedBurnEventParams({
            token: address(usdc),
            depositor: testData.depositorAddr,
            transferSpecHash: keccak256(TransferSpecLib.encodeTransferSpec(testData.auth1.spec)),
            destinationDomain: testData.auth1.spec.destinationDomain,
            recipient: testData.auth1.spec.destinationRecipient,
            authorizer: testData.depositorAddr,
            value: testData.value1, // fromAvailable - fee
            fee: testData.fee1,
            fromAvailable: testData.value1 + testData.fee1,
            fromWithdrawing: 0
        });

        // Insufficient Balance Event (Auth 2)
        testData.insufficientEventValueNeeded = neededForAuth2; // $500.10
        testData.insufficientEventAvailableAvailable = balanceAfterAuth1; // $399.80
        testData.insufficientEventWithdrawingAvailable = 0;

        // Event 2 (Auth 2)
        testData.eventParams2 = ExpectedBurnEventParams({
            token: address(usdc),
            depositor: testData.depositorAddr,
            transferSpecHash: keccak256(TransferSpecLib.encodeTransferSpec(testData.auth2.spec)),
            destinationDomain: testData.auth2.spec.destinationDomain,
            recipient: testData.auth2.spec.destinationRecipient,
            authorizer: testData.depositorAddr,
            value: deductedForAuth2 - actualFeeAuth2, // fromAvailable - fee
            fee: actualFeeAuth2, // Actual fee $0
            fromAvailable: deductedForAuth2, // Amount actually deducted $399.80
            fromWithdrawing: 0
        });

        // Assert initial state
        _assertBalances(
            "Initial State (AuthSet Insufficient)", testData.depositorAddr, feeRecipient, testData.initialBalances
        );

        _expectBurnEvent(testData.eventParams1); // Event for successful auth1
        vm.expectEmit(true, true, true, true);
        emit Burns.InsufficientBalance(
            address(usdc),
            testData.depositorAddr,
            testData.insufficientEventValueNeeded,
            testData.insufficientEventAvailableAvailable,
            testData.insufficientEventWithdrawingAvailable
        );
        _expectBurnEvent(testData.eventParams2); // Event for partially successful auth2

        _callGatewayBurnSignedBy(testData.authorizations, testData.signatures, testData.fees, burnSignerKey);

        // Assert final state
        _assertBalances(
            "Final State (AuthSet Insufficient)", testData.depositorAddr, feeRecipient, testData.finalBalances
        );
    }

    function test_gatewayBurn_singleAuth_insufficientBalanceForBurnFee() public {
        uint256 fee = defaultMaxFee / 2; // $0.50

        // Setup the under funded depositor
        deal(address(usdc), underFundedDepositor, depositorInitialBalance, true); // Fund externally with initial $5000
        vm.startPrank(underFundedDepositor);
        usdc.approve(address(wallet), type(uint256).max);
        wallet.deposit(address(usdc), depositorInitialBalance / 4 + fee / 2); // Deposit $1250 (1/4 of initial) + $0.25 (half of fee)
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        auth.spec.value = depositorInitialBalance / 4; // $1250
        auth.spec.sourceDepositor = AddressLib._addressToBytes32(underFundedDepositor);
        auth.spec.sourceSigner = AddressLib._addressToBytes32(underFundedDepositor);
        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, underFundedDepositorKey);

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
            depositorExternalUsdc: depositorInitialBalance * 3 / 4 - fee / 2, // $3750 external - $0.25 (half of fee)
            depositorAvailable: depositorInitialBalance / 4 + fee / 2, // $1250 available + $0.25 (half of fee)
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance + depositorInitialBalance / 4 + fee / 2, // $5000 (original depositor) + $1250 (underFundedDepositor) + $0.25 (half of fee) = $6250.25 total in wallet
            usdcTotalSupply: initialTotalSupply
        });
        _assertBalances("Initial State", underFundedDepositor, feeRecipient, initialExpectedBalances);

        vm.expectEmit(true, true, true, true);
        emit Burns.InsufficientBalance(
            address(usdc),
            underFundedDepositor,
            auth.spec.value + fee, // Total needed: $1250 + $0.50 = $1250.50
            depositorInitialBalance / 4 + fee / 2, // Available available: $1250 + $0.25 (half of fee)
            0 // Withdrawing available: $0
        );

        ExpectedBurnEventParams memory expectedParams;
        expectedParams.token = address(usdc);
        expectedParams.depositor = underFundedDepositor;
        expectedParams.transferSpecHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));
        expectedParams.destinationDomain = auth.spec.destinationDomain;
        expectedParams.recipient = auth.spec.destinationRecipient;
        expectedParams.authorizer = underFundedDepositor;
        expectedParams.fee = fee / 2; // Actual fee charged: $0.25 (half of fee)
        expectedParams.fromAvailable = depositorInitialBalance / 4 + fee / 2; // Actual amount deducted from available: $1250.25
        expectedParams.value = expectedParams.fromAvailable - expectedParams.fee;
        expectedParams.fromWithdrawing = 0;
        _expectBurnEvent(expectedParams);

        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);

        // Assert final state
        ExpectedBalances memory finalExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: depositorInitialBalance * 3 / 4 - fee / 2, // $3750 external - $0.25 (half of fee)
            depositorAvailable: 0, // Available becomes $0
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: fee / 2, // Fee recipient gets $0.25 (half of fee)
            walletExternalUsdc: depositorInitialBalance, // Wallet balance: $6250 - $1250 = $5000
            usdcTotalSupply: initialTotalSupply - depositorInitialBalance / 4 // Total supply reduced by $1250
        });
        _assertBalances("Final State", underFundedDepositor, feeRecipient, finalExpectedBalances);
    }

    /// Tests gatewayBurn with an authorization set containing two auths for the same depositor.
    /// The first auth succeeds, but depletes the balance such that the second auth
    /// can cover its value but only a portion of its fee.
    function test_gatewayBurn_singleAuthSet_secondAuthPartialFee() public {
        AuthSetInsufficientBalanceTestData memory testData;

        (testData.depositorAddr, testData.depositorKey) = makeAddrAndKey("partialFeeDepositor");
        testData.initialDeposit = 1000 * 10 ** 6; // $1000.00
        testData.value1 = 800 * 10 ** 6; // $800.00
        testData.fee1 = defaultMaxFee / 10; // $0.10
        testData.value2 = 1995 * 10 ** 5; // $199.50
        testData.fee2 = defaultMaxFee / 2; // $0.50 (Needs $199.50 + $0.50 = $200.00 total)

        // Setup the depositor's balance
        deal(address(usdc), testData.depositorAddr, testData.initialDeposit, true);
        vm.startPrank(testData.depositorAddr);
        usdc.approve(address(wallet), type(uint256).max);
        wallet.deposit(address(usdc), testData.initialDeposit);
        vm.stopPrank();

        // Auth 1 (designed to succeed)
        testData.auth1 = baseAuth;
        testData.auth1.spec.sourceDepositor = AddressLib._addressToBytes32(testData.depositorAddr);
        testData.auth1.spec.sourceSigner = AddressLib._addressToBytes32(testData.depositorAddr);
        testData.auth1.spec.value = testData.value1;
        testData.auth1.maxFee = defaultMaxFee;

        // Auth 2 (designed to have insufficient funds for full fee after Auth 1)
        testData.auth2 = baseAuth;
        testData.auth2.spec.sourceDepositor = AddressLib._addressToBytes32(testData.depositorAddr);
        testData.auth2.spec.sourceSigner = AddressLib._addressToBytes32(testData.depositorAddr);
        testData.auth2.spec.value = testData.value2;
        testData.auth2.maxFee = defaultMaxFee;

        testData.authsForSet = new BurnAuthorization[](2);
        testData.authsForSet[0] = testData.auth1;
        testData.authsForSet[1] = testData.auth2;
        testData.authSet = BurnAuthorizationSet({authorizations: testData.authsForSet});
        testData.encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(testData.authSet);

        testData.signature = _signAuthOrAuthSet(testData.encodedAuthSet, testData.depositorKey);

        testData.authorizations = new bytes[](1);
        testData.authorizations[0] = testData.encodedAuthSet;
        testData.signatures = new bytes[](1);
        testData.signatures[0] = testData.signature;
        testData.fees = new uint256[][](1);
        testData.fees[0] = new uint256[](2);
        testData.fees[0][0] = testData.fee1;
        testData.fees[0][1] = testData.fee2;

        testData.initialTotalSupply = usdc.totalSupply();
        testData.initialWalletBalance = usdc.balanceOf(address(wallet));
        testData.initialFeeRecipientBalance = usdc.balanceOf(feeRecipient);

        uint256 balanceAfterAuth1 = testData.initialDeposit - (testData.value1 + testData.fee1); // $1000 - ($800 + $0.10) = $199.90
        uint256 neededForAuth2 = testData.value2 + testData.fee2; // $199.50 + $0.50 = $200.00
        uint256 deductedForAuth2 = balanceAfterAuth1; // $199.90 (since $199.90 < $200.00)
        // Since deductedAmount ($199.90) > value2 ($199.50), potential fee is deductedAmount - value2
        uint256 potentialFeeAuth2 = deductedForAuth2 - testData.value2; // $199.90 - $199.50 = $0.40
        uint256 actualFeeAuth2 = potentialFeeAuth2 < testData.fee2 ? potentialFeeAuth2 : testData.fee2; // min($0.40, $0.50) = $0.40
        uint256 actualValueBurnedAuth2 = deductedForAuth2 - actualFeeAuth2; // $199.90 - $0.40 = $199.50

        // Initial Balances
        testData.initialBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: testData.initialDeposit,
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: testData.initialFeeRecipientBalance,
            walletExternalUsdc: testData.initialWalletBalance,
            usdcTotalSupply: testData.initialTotalSupply
        });

        // Final Balances
        uint256 finalTotalValueBurned = testData.value1 + actualValueBurnedAuth2; // $800 + $199.50 = $999.50
        uint256 finalTotalFeeCharged = testData.fee1 + actualFeeAuth2; // $0.10 + $0.40 = $0.50
        uint256 finalTotalDeducted = (testData.value1 + testData.fee1) + deductedForAuth2; // $800.10 + $199.90 = $1000.00

        testData.finalBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: 0, // Fully depleted
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: testData.initialFeeRecipientBalance + finalTotalFeeCharged, // Initial + $0.50
            walletExternalUsdc: testData.initialWalletBalance - finalTotalDeducted, // Initial wallet bal - $1000
            usdcTotalSupply: testData.initialTotalSupply - finalTotalValueBurned // Initial supply - $999.50
        });

        // Event 1 (Auth 1)
        testData.eventParams1 = ExpectedBurnEventParams({
            token: address(usdc),
            depositor: testData.depositorAddr,
            transferSpecHash: keccak256(TransferSpecLib.encodeTransferSpec(testData.auth1.spec)),
            destinationDomain: testData.auth1.spec.destinationDomain,
            recipient: testData.auth1.spec.destinationRecipient,
            authorizer: testData.depositorAddr,
            value: testData.value1,
            fee: testData.fee1,
            fromAvailable: testData.value1 + testData.fee1,
            fromWithdrawing: 0
        });

        // Insufficient Balance Event (Auth 2)
        testData.insufficientEventValueNeeded = neededForAuth2; // $200.00
        testData.insufficientEventAvailableAvailable = balanceAfterAuth1; // $199.90
        testData.insufficientEventWithdrawingAvailable = 0;

        // Event 2 (Auth 2)
        testData.eventParams2 = ExpectedBurnEventParams({
            token: address(usdc),
            depositor: testData.depositorAddr,
            transferSpecHash: keccak256(TransferSpecLib.encodeTransferSpec(testData.auth2.spec)),
            destinationDomain: testData.auth2.spec.destinationDomain,
            recipient: testData.auth2.spec.destinationRecipient,
            authorizer: testData.depositorAddr,
            value: deductedForAuth2 - actualFeeAuth2, // Requested value $199.50
            fee: actualFeeAuth2, // Actual fee $0.40
            fromAvailable: deductedForAuth2, // Amount actually deducted $199.90
            fromWithdrawing: 0
        });

        // Assert initial state
        _assertBalances(
            "Initial State (AuthSet Partial Fee)", testData.depositorAddr, feeRecipient, testData.initialBalances
        );

        _expectBurnEvent(testData.eventParams1); // Event for successful auth1
        vm.expectEmit(true, true, true, true);
        emit Burns.InsufficientBalance(
            address(usdc),
            testData.depositorAddr,
            testData.insufficientEventValueNeeded,
            testData.insufficientEventAvailableAvailable,
            testData.insufficientEventWithdrawingAvailable
        );
        _expectBurnEvent(testData.eventParams2); // Event for successful value burn, partial fee

        _callGatewayBurnSignedBy(testData.authorizations, testData.signatures, testData.fees, burnSignerKey);

        // Assert final state
        _assertBalances(
            "Final State (AuthSet Partial Fee)", testData.depositorAddr, feeRecipient, testData.finalBalances
        );
    }

    // ===== Burn Success Scenarios - Single Authorization, Single Authorization Set =====
    //
    // Test Matrix for Successful Burns:
    //
    // This section tests successful `gatewayBurn` calls by varying several parameters:
    // 1. Input Structure: How authorizations are grouped (single vs. multiple sets, single vs. multiple auths per set).
    // 2. Domain Relevance: Whether authorizations are for the current domain (processed) or another (skipped).
    // 3. Balance Source: Where funds are drawn from (available only, withdrawing only, or both).
    // 4. Authorization Signer: Who signed the authorization (the depositor, an authorized delegate, or a now revoked delegate).

    struct SingleBurnTestConfig {
        string contextSuffix; // Short description (e.g., "(Available, Depositor)")
        BurnAuthorization auth; // The specific authorization to test
        uint256 fee; // The fee for this specific burn
        uint256 signerKey; // Private key of the authorizer (depositor or delegate)
        ExpectedBalances initialBalances; // Expected state before the burn
        ExpectedBalances finalBalances; // Expected state after the burn
        ExpectedBurnEventParams eventParams; // Expected event details
    }

    function _assertBalances(
        string memory context, // e.g., "Initial State", "After Burn"
        address depositorAddr,
        address feeRecipientAddr,
        ExpectedBalances memory expected
    ) internal view {
        // Fetch actual balances
        uint256 actualDepositorExternalUsdc = usdc.balanceOf(depositorAddr);
        uint256 actualDepositorAvailable = wallet.availableBalance(address(usdc), depositorAddr);
        uint256 actualDepositorWithdrawing = wallet.withdrawingBalance(address(usdc), depositorAddr);
        uint256 actualFeeRecipientExternalUsdc = usdc.balanceOf(feeRecipientAddr);
        uint256 actualWalletExternalUsdc = usdc.balanceOf(address(wallet));
        uint256 actualUsdcTotalSupply = usdc.totalSupply();

        assertEq(
            actualDepositorExternalUsdc,
            expected.depositorExternalUsdc,
            string.concat(context, ": Depositor External USDC mismatch")
        );
        assertEq(
            actualDepositorAvailable,
            expected.depositorAvailable,
            string.concat(context, ": Depositor Available mismatch")
        );
        assertEq(
            actualDepositorWithdrawing,
            expected.depositorWithdrawing,
            string.concat(context, ": Depositor Withdrawing mismatch")
        );
        assertEq(
            actualFeeRecipientExternalUsdc,
            expected.feeRecipientExternalUsdc,
            string.concat(context, ": Fee Recipient External USDC mismatch")
        );
        assertEq(
            actualWalletExternalUsdc,
            expected.walletExternalUsdc,
            string.concat(context, ": Wallet External USDC mismatch")
        );
        assertEq(
            actualUsdcTotalSupply, expected.usdcTotalSupply, string.concat(context, ": USDC Total Supply mismatch")
        );
    }

    function _executeAndAssertSingleBurn(SingleBurnTestConfig memory config) internal {
        // Assert initial state
        _assertBalances(
            string.concat("Initial State ", config.contextSuffix),
            config.eventParams.depositor, // Get depositor from event params
            feeRecipient, // Global fee recipient
            config.initialBalances
        );

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(config.auth);
        bytes memory signature = _signAuthOrAuthSet(encodedAuth, config.signerKey);

        bytes[] memory authorizations = new bytes[](1);
        authorizations[0] = encodedAuth;
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = signature;
        uint256[][] memory fees = new uint256[][](1);
        fees[0] = new uint256[](1);
        fees[0][0] = config.fee;

        _expectBurnEvent(config.eventParams);
        _callGatewayBurnSignedBy(authorizations, signatures, fees, burnSignerKey);

        // Assert final state
        _assertBalances(
            string.concat("Final State ", config.contextSuffix),
            config.eventParams.depositor,
            feeRecipient,
            config.finalBalances
        );
    }

    function test_gatewayBurn_singleAuth_currentDomain_fromAvailableBalance_depositorSigner() public {
        BurnAuthorization memory auth = baseAuth;
        uint256 burnValue = depositorInitialBalance / 2;
        uint256 fee = defaultMaxFee / 2;
        uint256 signerKey = depositorKey;
        address expectedAuthorizer = depositor;
        string memory contextSuffix = "(Available, Depositor)";
        uint256 expectedTotalDeducted = burnValue + fee;

        SingleBurnTestConfig memory config;
        config.contextSuffix = contextSuffix;
        config.auth = auth;
        config.fee = fee;
        config.signerKey = signerKey;

        uint256 initialTotalSupply = usdc.totalSupply();
        config.initialBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: depositorInitialBalance,
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });

        config.finalBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: depositorInitialBalance - expectedTotalDeducted,
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: depositorInitialBalance - expectedTotalDeducted,
            usdcTotalSupply: initialTotalSupply - burnValue
        });

        config.eventParams = ExpectedBurnEventParams({
            token: address(usdc),
            depositor: depositor,
            transferSpecHash: keccak256(TransferSpecLib.encodeTransferSpec(auth.spec)),
            destinationDomain: auth.spec.destinationDomain,
            recipient: auth.spec.destinationRecipient,
            authorizer: expectedAuthorizer,
            value: burnValue,
            fee: fee,
            fromAvailable: expectedTotalDeducted,
            fromWithdrawing: 0
        });

        _executeAndAssertSingleBurn(config);
    }

    function test_gatewayBurn_singleAuth_currentDomain_fromAvailableBalance_delegateSigner() public {
        // Setup delegate
        vm.startPrank(depositor);
        wallet.addDelegate(address(usdc), delegate);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        auth.spec.sourceSigner = AddressLib._addressToBytes32(delegate);

        uint256 burnValue = depositorInitialBalance / 2;
        uint256 fee = defaultMaxFee / 2;
        uint256 signerKey = delegateKey; // Signed by delegate
        address expectedAuthorizer = delegate; // Authorizer is delegate
        string memory contextSuffix = "(Available, Delegate)";
        uint256 expectedTotalDeducted = burnValue + fee;

        SingleBurnTestConfig memory config;
        config.contextSuffix = contextSuffix;
        config.auth = auth;
        config.fee = fee;
        config.signerKey = signerKey;

        uint256 initialTotalSupply = usdc.totalSupply();
        config.initialBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: depositorInitialBalance,
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });

        config.finalBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: depositorInitialBalance - expectedTotalDeducted,
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: depositorInitialBalance - expectedTotalDeducted,
            usdcTotalSupply: initialTotalSupply - burnValue
        });

        config.eventParams = ExpectedBurnEventParams({
            token: address(usdc),
            depositor: depositor,
            transferSpecHash: keccak256(TransferSpecLib.encodeTransferSpec(auth.spec)),
            destinationDomain: auth.spec.destinationDomain,
            recipient: auth.spec.destinationRecipient,
            authorizer: expectedAuthorizer,
            value: burnValue,
            fee: fee,
            fromAvailable: expectedTotalDeducted,
            fromWithdrawing: 0
        });

        _executeAndAssertSingleBurn(config);
    }

    function test_gatewayBurn_singleAuth_currentDomain_fromAvailableBalance_revokedDelegateSigner() public {
        // Setup and revoke delegate
        vm.startPrank(depositor);
        wallet.addDelegate(address(usdc), delegate);
        wallet.removeDelegate(address(usdc), delegate);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        auth.spec.sourceSigner = AddressLib._addressToBytes32(delegate);

        uint256 burnValue = depositorInitialBalance / 2;
        uint256 fee = defaultMaxFee / 2;
        uint256 signerKey = delegateKey; // Signed by delegate (before revocation)
        address expectedAuthorizer = delegate; // Authorizer is revoked delegate
        string memory contextSuffix = "(Available, Revoked Delegate)";
        uint256 expectedTotalDeducted = burnValue + fee;

        SingleBurnTestConfig memory config;
        config.contextSuffix = contextSuffix;
        config.auth = auth;
        config.fee = fee;
        config.signerKey = signerKey;

        uint256 initialTotalSupply = usdc.totalSupply();
        config.initialBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: depositorInitialBalance,
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });

        config.finalBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: depositorInitialBalance - expectedTotalDeducted,
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: depositorInitialBalance - expectedTotalDeducted,
            usdcTotalSupply: initialTotalSupply - burnValue
        });

        config.eventParams = ExpectedBurnEventParams({
            token: address(usdc),
            depositor: depositor,
            transferSpecHash: keccak256(TransferSpecLib.encodeTransferSpec(auth.spec)),
            destinationDomain: auth.spec.destinationDomain,
            recipient: auth.spec.destinationRecipient,
            authorizer: expectedAuthorizer,
            value: burnValue,
            fee: fee,
            fromAvailable: expectedTotalDeducted,
            fromWithdrawing: 0
        });

        _executeAndAssertSingleBurn(config);
    }

    function test_gatewayBurn_singleAuth_currentDomain_fromWithdrawingBalance_depositorSigner() public {
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(address(usdc), depositorInitialBalance);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        uint256 burnValue = depositorInitialBalance / 2;
        uint256 fee = defaultMaxFee / 2;
        uint256 signerKey = depositorKey;
        address expectedAuthorizer = depositor;
        string memory contextSuffix = "(Withdrawing, Depositor)";
        uint256 expectedTotalDeducted = burnValue + fee;

        SingleBurnTestConfig memory config;
        config.contextSuffix = contextSuffix;
        config.auth = auth;
        config.fee = fee;
        config.signerKey = signerKey;

        uint256 initialTotalSupply = usdc.totalSupply();
        config.initialBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: 0,
            depositorWithdrawing: depositorInitialBalance,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });

        config.finalBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: 0,
            depositorWithdrawing: depositorInitialBalance - expectedTotalDeducted,
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: depositorInitialBalance - expectedTotalDeducted,
            usdcTotalSupply: initialTotalSupply - burnValue
        });

        config.eventParams = ExpectedBurnEventParams({
            token: address(usdc),
            depositor: depositor,
            transferSpecHash: keccak256(TransferSpecLib.encodeTransferSpec(auth.spec)),
            destinationDomain: auth.spec.destinationDomain,
            recipient: auth.spec.destinationRecipient,
            authorizer: expectedAuthorizer,
            value: burnValue,
            fee: fee,
            fromAvailable: 0,
            fromWithdrawing: expectedTotalDeducted
        });

        _executeAndAssertSingleBurn(config);
    }

    function test_gatewayBurn_singleAuth_currentDomain_fromWithdrawingBalance_delegateSigner() public {
        // Move all depositor funds to withdrawing balance
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(address(usdc), depositorInitialBalance);

        // Setup delegate
        wallet.addDelegate(address(usdc), delegate);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        auth.spec.sourceSigner = AddressLib._addressToBytes32(delegate);

        uint256 burnValue = depositorInitialBalance / 2;
        uint256 fee = defaultMaxFee / 2;
        uint256 signerKey = delegateKey; // Signed by delegate
        address expectedAuthorizer = delegate;
        string memory contextSuffix = "(Withdrawing, Delegate)";
        uint256 expectedTotalDeducted = burnValue + fee;

        SingleBurnTestConfig memory config;
        config.contextSuffix = contextSuffix;
        config.auth = auth;
        config.fee = fee;
        config.signerKey = signerKey;

        uint256 initialTotalSupply = usdc.totalSupply();
        config.initialBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: 0,
            depositorWithdrawing: depositorInitialBalance,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });

        config.finalBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: 0,
            depositorWithdrawing: depositorInitialBalance - expectedTotalDeducted,
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: depositorInitialBalance - expectedTotalDeducted,
            usdcTotalSupply: initialTotalSupply - burnValue
        });

        config.eventParams = ExpectedBurnEventParams({
            token: address(usdc),
            depositor: depositor,
            transferSpecHash: keccak256(TransferSpecLib.encodeTransferSpec(auth.spec)),
            destinationDomain: auth.spec.destinationDomain,
            recipient: auth.spec.destinationRecipient,
            authorizer: expectedAuthorizer,
            value: burnValue,
            fee: fee,
            fromAvailable: 0,
            fromWithdrawing: expectedTotalDeducted
        });

        _executeAndAssertSingleBurn(config);
    }

    function test_gatewayBurn_singleAuth_currentDomain_fromWithdrawingBalance_revokedDelegateSigner() public {
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(address(usdc), depositorInitialBalance);
        wallet.addDelegate(address(usdc), delegate);
        wallet.removeDelegate(address(usdc), delegate);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        auth.spec.sourceSigner = AddressLib._addressToBytes32(delegate);

        uint256 burnValue = depositorInitialBalance / 2;
        uint256 fee = defaultMaxFee / 2;
        uint256 signerKey = delegateKey; // Signed by delegate
        address expectedAuthorizer = delegate;
        string memory contextSuffix = "(Withdrawing, Revoked Delegate)";
        uint256 expectedTotalDeducted = burnValue + fee;

        SingleBurnTestConfig memory config;
        config.contextSuffix = contextSuffix;
        config.auth = auth;
        config.fee = fee;
        config.signerKey = signerKey;

        uint256 initialTotalSupply = usdc.totalSupply();
        config.initialBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: 0,
            depositorWithdrawing: depositorInitialBalance,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });

        config.finalBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: 0,
            depositorWithdrawing: depositorInitialBalance - expectedTotalDeducted,
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: depositorInitialBalance - expectedTotalDeducted,
            usdcTotalSupply: initialTotalSupply - burnValue
        });

        config.eventParams = ExpectedBurnEventParams({
            token: address(usdc),
            depositor: depositor,
            transferSpecHash: keccak256(TransferSpecLib.encodeTransferSpec(auth.spec)),
            destinationDomain: auth.spec.destinationDomain,
            recipient: auth.spec.destinationRecipient,
            authorizer: expectedAuthorizer,
            value: burnValue,
            fee: fee,
            fromAvailable: 0,
            fromWithdrawing: expectedTotalDeducted
        });

        _executeAndAssertSingleBurn(config);
    }

    function test_gatewayBurn_singleAuth_currentDomain_fromBothBalances_depositorSigner() public {
        // Move some funds to withdrawing balance
        uint256 withdrawAmount = depositorInitialBalance * 3 / 4;
        uint256 remainingAvailable = depositorInitialBalance / 4;

        vm.startPrank(depositor);
        wallet.initiateWithdrawal(address(usdc), withdrawAmount);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        uint256 burnValue = depositorInitialBalance / 2;
        uint256 fee = defaultMaxFee / 2;
        uint256 signerKey = depositorKey;
        address expectedAuthorizer = depositor;
        string memory contextSuffix = "(Both, Depositor)";
        uint256 expectedTotalDeducted = burnValue + fee;

        SingleBurnTestConfig memory config;
        config.contextSuffix = contextSuffix;
        config.auth = auth;
        config.fee = fee;
        config.signerKey = signerKey;

        uint256 initialTotalSupply = usdc.totalSupply();
        config.initialBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: remainingAvailable,
            depositorWithdrawing: withdrawAmount,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });

        config.finalBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: 0,
            depositorWithdrawing: withdrawAmount - (expectedTotalDeducted - remainingAvailable),
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: depositorInitialBalance - expectedTotalDeducted,
            usdcTotalSupply: initialTotalSupply - burnValue
        });

        config.eventParams = ExpectedBurnEventParams({
            token: address(usdc),
            depositor: depositor,
            transferSpecHash: keccak256(TransferSpecLib.encodeTransferSpec(auth.spec)),
            destinationDomain: auth.spec.destinationDomain,
            recipient: auth.spec.destinationRecipient,
            authorizer: expectedAuthorizer,
            value: burnValue,
            fee: fee,
            fromAvailable: remainingAvailable,
            fromWithdrawing: expectedTotalDeducted - remainingAvailable
        });

        _executeAndAssertSingleBurn(config);
    }

    function test_gatewayBurn_singleAuth_currentDomain_fromBothBalances_delegateSigner() public {
        // Move some funds to withdrawing balance
        uint256 withdrawAmount = depositorInitialBalance * 3 / 4;
        uint256 remainingAvailable = depositorInitialBalance - withdrawAmount;

        // Setup delegate
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(address(usdc), withdrawAmount);
        wallet.addDelegate(address(usdc), delegate);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        auth.spec.sourceSigner = AddressLib._addressToBytes32(delegate);

        uint256 burnValue = depositorInitialBalance / 2;
        uint256 fee = defaultMaxFee / 2;
        uint256 signerKey = delegateKey; // Signed by delegate
        address expectedAuthorizer = delegate;
        string memory contextSuffix = "(Both, Delegate)";
        uint256 expectedTotalDeducted = burnValue + fee;

        SingleBurnTestConfig memory config;
        config.contextSuffix = contextSuffix;
        config.auth = auth;
        config.fee = fee;
        config.signerKey = signerKey;

        uint256 initialTotalSupply = usdc.totalSupply();
        config.initialBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: remainingAvailable,
            depositorWithdrawing: withdrawAmount,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });

        config.finalBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: 0, // Available used up
            depositorWithdrawing: withdrawAmount - (expectedTotalDeducted - remainingAvailable),
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: depositorInitialBalance - expectedTotalDeducted,
            usdcTotalSupply: initialTotalSupply - burnValue
        });

        config.eventParams = ExpectedBurnEventParams({
            token: address(usdc),
            depositor: depositor,
            transferSpecHash: keccak256(TransferSpecLib.encodeTransferSpec(auth.spec)),
            destinationDomain: auth.spec.destinationDomain,
            recipient: auth.spec.destinationRecipient,
            authorizer: expectedAuthorizer,
            value: burnValue,
            fee: fee,
            fromAvailable: remainingAvailable,
            fromWithdrawing: expectedTotalDeducted - remainingAvailable
        });

        _executeAndAssertSingleBurn(config);
    }

    function test_gatewayBurn_singleAuth_currentDomain_fromBothBalances_revokedDelegateSigner() public {
        // Move some funds to withdrawing balance
        uint256 withdrawAmount = depositorInitialBalance * 3 / 4;
        uint256 remainingAvailable = depositorInitialBalance - withdrawAmount;

        // Setup and revoke delegate
        vm.startPrank(depositor);
        wallet.initiateWithdrawal(address(usdc), withdrawAmount);
        wallet.addDelegate(address(usdc), delegate);
        wallet.removeDelegate(address(usdc), delegate);
        vm.stopPrank();

        BurnAuthorization memory auth = baseAuth;
        auth.spec.sourceSigner = AddressLib._addressToBytes32(delegate);

        uint256 burnValue = depositorInitialBalance / 2;
        uint256 fee = defaultMaxFee / 2;
        uint256 signerKey = delegateKey; // Signed by delegate
        address expectedAuthorizer = delegate;
        string memory contextSuffix = "(Both, Revoked Delegate)";
        uint256 expectedTotalDeducted = burnValue + fee;

        SingleBurnTestConfig memory config;
        config.contextSuffix = contextSuffix;
        config.auth = auth;
        config.fee = fee;
        config.signerKey = signerKey;

        uint256 initialTotalSupply = usdc.totalSupply();
        config.initialBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: remainingAvailable,
            depositorWithdrawing: withdrawAmount,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: initialTotalSupply
        });

        config.finalBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: 0,
            depositorWithdrawing: withdrawAmount - (expectedTotalDeducted - remainingAvailable),
            feeRecipientExternalUsdc: fee,
            walletExternalUsdc: depositorInitialBalance - expectedTotalDeducted,
            usdcTotalSupply: initialTotalSupply - burnValue
        });

        config.eventParams = ExpectedBurnEventParams({
            token: address(usdc),
            depositor: depositor,
            transferSpecHash: keccak256(TransferSpecLib.encodeTransferSpec(auth.spec)),
            destinationDomain: auth.spec.destinationDomain,
            recipient: auth.spec.destinationRecipient,
            authorizer: expectedAuthorizer,
            value: burnValue,
            fee: fee,
            fromAvailable: remainingAvailable,
            fromWithdrawing: expectedTotalDeducted - remainingAvailable
        });

        _executeAndAssertSingleBurn(config);
    }

    // Struct to hold test data for the multi-set mixed domain test to avoid stack too deep errors
    struct MultiSetMixedDomainTestData {
        uint256 fee1;
        uint256 fee2;
        uint256 fee3Irrelevant;
        uint256 fee4;
        uint256 value1;
        uint256 value2;
        uint256 value3Irrelevant;
        uint256 value4;
        BurnAuthorization auth1;
        BurnAuthorization auth2;
        BurnAuthorization auth3Irrelevant;
        BurnAuthorization auth4;
        BurnAuthorization[] authsForSet;
        BurnAuthorizationSet authSet;
        bytes encodedAuth1;
        bytes encodedAuthSet;
        bytes sig1;
        bytes sigSet;
        bytes[] authorizations;
        bytes[] signatures;
        uint256[][] fees;
        uint256 initialTotalSupply;
        uint256 expectedTotalValueBurned;
        uint256 expectedTotalFeeCharged;
        uint256 expectedTotalDeducted;
        ExpectedBalances initialExpectedBalances;
        ExpectedBalances finalExpectedBalances;
        ExpectedBurnEventParams eventParams1;
        ExpectedBurnEventParams eventParams2;
        ExpectedBurnEventParams eventParams4;
    }

    /// Tests gatewayBurn with multiple independent authorization inputs, including a set with mixed domain relevance.
    /// - authorizations[0]: Single auth, current domain.
    /// - authorizations[1]: Set of 3 auths (current, other, current).
    /// Expects burns for the 3 current-domain auths to succeed and the other-domain auth to be skipped.
    function test_gatewayBurn_multipleSets_mixedDomains_fromAvailable_depositorSigner() public {
        MultiSetMixedDomainTestData memory testData;

        testData.fee1 = defaultMaxFee / 10;
        testData.fee2 = defaultMaxFee / 20;
        testData.fee3Irrelevant = defaultMaxFee / 30; // Fee for the irrelevant auth (won't be charged)
        testData.fee4 = defaultMaxFee / 40;

        testData.value1 = depositorInitialBalance / 10;
        testData.value2 = depositorInitialBalance / 20;
        testData.value3Irrelevant = depositorInitialBalance / 30; // Value for irrelevant auth
        testData.value4 = depositorInitialBalance / 40;

        // Auth 1: Single, current domain
        testData.auth1 = baseAuth;
        testData.auth1.spec.value = testData.value1;
        testData.auth1.maxFee = testData.fee1 * 2; // Ensure fee is allowed

        // Auth 2: Part of set, current domain
        testData.auth2 = baseAuth;
        testData.auth2.spec.value = testData.value2;
        testData.auth2.maxFee = testData.fee2 * 2;

        // Auth 3: Part of set, a different domain (should be skipped)
        testData.auth3Irrelevant = baseAuth;
        testData.auth3Irrelevant.spec.value = testData.value3Irrelevant;
        testData.auth3Irrelevant.spec.sourceDomain = domain + 1; // Different domain
        testData.auth3Irrelevant.maxFee = testData.fee3Irrelevant * 2;

        // Auth 4: Part of set, current domain
        testData.auth4 = baseAuth;
        testData.auth4.spec.value = testData.value4;
        testData.auth4.maxFee = testData.fee4 * 2;

        // Create auth set (containing auths 2, 3, 4)
        testData.authsForSet = new BurnAuthorization[](3);
        testData.authsForSet[0] = testData.auth2;
        testData.authsForSet[1] = testData.auth3Irrelevant; // The irrelevant one
        testData.authsForSet[2] = testData.auth4;
        testData.authSet = BurnAuthorizationSet({authorizations: testData.authsForSet});

        // Encode auths
        testData.encodedAuth1 = BurnAuthorizationLib.encodeBurnAuthorization(testData.auth1);
        testData.encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(testData.authSet);

        // Sign auths
        testData.sig1 = _signAuthOrAuthSet(testData.encodedAuth1, depositorKey);
        testData.sigSet = _signAuthOrAuthSet(testData.encodedAuthSet, depositorKey);

        testData.authorizations = new bytes[](2);
        testData.authorizations[0] = testData.encodedAuth1;
        testData.authorizations[1] = testData.encodedAuthSet;

        testData.signatures = new bytes[](2);
        testData.signatures[0] = testData.sig1;
        testData.signatures[1] = testData.sigSet;

        testData.fees = new uint256[][](2);
        testData.fees[0] = new uint256[](1); // Fees for authorizations[0] (auth1)
        testData.fees[0][0] = testData.fee1;
        testData.fees[1] = new uint256[](3); // Fees for authorizations[1] (authSet: auth2, auth3, auth4)
        testData.fees[1][0] = testData.fee2;
        testData.fees[1][1] = testData.fee3Irrelevant; // Provide fee, though it shouldn't be used
        testData.fees[1][2] = testData.fee4;

        // Expected initial state
        testData.initialTotalSupply = usdc.totalSupply();
        testData.expectedTotalValueBurned = testData.value1 + testData.value2 + testData.value4; // value3 is skipped
        testData.expectedTotalFeeCharged = testData.fee1 + testData.fee2 + testData.fee4; // fee3 is skipped
        testData.expectedTotalDeducted = testData.expectedTotalValueBurned + testData.expectedTotalFeeCharged;
        testData.initialExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: depositorInitialBalance,
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: 0,
            walletExternalUsdc: depositorInitialBalance,
            usdcTotalSupply: testData.initialTotalSupply
        });
        _assertBalances("Initial State (MultiSet Mixed)", depositor, feeRecipient, testData.initialExpectedBalances);

        // Event for auth1
        testData.eventParams1.token = address(usdc);
        testData.eventParams1.depositor = depositor;
        testData.eventParams1.transferSpecHash = keccak256(TransferSpecLib.encodeTransferSpec(testData.auth1.spec));
        testData.eventParams1.destinationDomain = testData.auth1.spec.destinationDomain;
        testData.eventParams1.recipient = testData.auth1.spec.destinationRecipient;
        testData.eventParams1.authorizer = depositor;
        testData.eventParams1.value = testData.value1;
        testData.eventParams1.fee = testData.fee1;
        testData.eventParams1.fromAvailable = testData.value1 + testData.fee1; // Assuming drawn from available first
        testData.eventParams1.fromWithdrawing = 0;
        _expectBurnEvent(testData.eventParams1);

        // Event for auth2
        testData.eventParams2.token = address(usdc);
        testData.eventParams2.depositor = depositor;
        testData.eventParams2.transferSpecHash = keccak256(TransferSpecLib.encodeTransferSpec(testData.auth2.spec));
        testData.eventParams2.destinationDomain = testData.auth2.spec.destinationDomain;
        testData.eventParams2.recipient = testData.auth2.spec.destinationRecipient;
        testData.eventParams2.authorizer = depositor;
        testData.eventParams2.value = testData.value2;
        testData.eventParams2.fee = testData.fee2;
        testData.eventParams2.fromAvailable = testData.value2 + testData.fee2;
        testData.eventParams2.fromWithdrawing = 0;
        _expectBurnEvent(testData.eventParams2);

        // Event for auth4 (auth3 is skipped)
        testData.eventParams4.token = address(usdc);
        testData.eventParams4.depositor = depositor;
        testData.eventParams4.transferSpecHash = keccak256(TransferSpecLib.encodeTransferSpec(testData.auth4.spec));
        testData.eventParams4.destinationDomain = testData.auth4.spec.destinationDomain;
        testData.eventParams4.recipient = testData.auth4.spec.destinationRecipient;
        testData.eventParams4.authorizer = depositor;
        testData.eventParams4.value = testData.value4;
        testData.eventParams4.fee = testData.fee4;
        testData.eventParams4.fromAvailable = testData.value4 + testData.fee4;
        testData.eventParams4.fromWithdrawing = 0;
        _expectBurnEvent(testData.eventParams4);

        _callGatewayBurnSignedBy(testData.authorizations, testData.signatures, testData.fees, burnSignerKey);

        testData.finalExpectedBalances = ExpectedBalances({
            depositorExternalUsdc: 0,
            depositorAvailable: depositorInitialBalance - testData.expectedTotalDeducted,
            depositorWithdrawing: 0,
            feeRecipientExternalUsdc: testData.expectedTotalFeeCharged,
            walletExternalUsdc: depositorInitialBalance - testData.expectedTotalDeducted,
            usdcTotalSupply: testData.initialTotalSupply - testData.expectedTotalValueBurned
        });
        _assertBalances("Final State (MultiSet Mixed)", depositor, feeRecipient, testData.finalExpectedBalances);
    }

    struct MultiDepositorTestData {
        uint256 burnValue1;
        uint256 fee1;
        uint256 burnValue2;
        uint256 fee2;
        BurnAuthorization auth1;
        BurnAuthorization auth2;
        bytes encodedAuth1;
        bytes encodedAuth2;
        bytes sig1;
        bytes sig2;
        bytes[] authorizations;
        bytes[] signatures;
        uint256[][] fees;
        uint256 initialTotalSupply;
        uint256 initialFeeRecipientBalance;
        uint256 initialWalletBalance;
        uint256 expectedTotalFee;
        uint256 expectedTotalValueBurned;
        uint256 expectedTotalDeducted;
        ExpectedBurnEventParams eventParams1;
        ExpectedBurnEventParams eventParams2;
    }

    function test_gatewayBurn_multipleDepositors_currentDomain_fromAvailable_depositorSigners() public {
        // Setup second depositor balance
        deal(address(usdc), depositor2, depositor2InitialBalance, true);
        vm.startPrank(depositor2);
        {
            usdc.approve(address(wallet), type(uint256).max);
            wallet.deposit(address(usdc), depositor2InitialBalance);
        }
        vm.stopPrank();

        MultiDepositorTestData memory testData;

        testData.burnValue1 = depositorInitialBalance / 5; // $1000 from depositor1
        testData.fee1 = defaultMaxFee / 10; // $0.10 fee for depositor1
        testData.burnValue2 = depositor2InitialBalance / 3; // $1000 from depositor2
        testData.fee2 = defaultMaxFee / 20; // $0.05 fee for depositor2

        // Authorization for depositor 1
        testData.auth1 = baseAuth;
        testData.auth1.spec.sourceDepositor = AddressLib._addressToBytes32(depositor);
        testData.auth1.spec.value = testData.burnValue1;
        testData.auth1.maxFee = defaultMaxFee; // Ensure provided fee1 is allowed

        // Authorization for depositor 2
        testData.auth2 = baseAuth;
        testData.auth2.spec.sourceDepositor = AddressLib._addressToBytes32(depositor2);
        testData.auth2.spec.sourceSigner = AddressLib._addressToBytes32(depositor2);
        testData.auth2.spec.value = testData.burnValue2;
        testData.auth2.maxFee = defaultMaxFee;

        testData.encodedAuth1 = BurnAuthorizationLib.encodeBurnAuthorization(testData.auth1);
        testData.sig1 = _signAuthOrAuthSet(testData.encodedAuth1, depositorKey);

        testData.encodedAuth2 = BurnAuthorizationLib.encodeBurnAuthorization(testData.auth2);
        testData.sig2 = _signAuthOrAuthSet(testData.encodedAuth2, depositor2Key);

        testData.authorizations = new bytes[](2);
        testData.authorizations[0] = testData.encodedAuth1;
        testData.authorizations[1] = testData.encodedAuth2;

        testData.signatures = new bytes[](2);
        testData.signatures[0] = testData.sig1;
        testData.signatures[1] = testData.sig2;

        testData.fees = new uint256[][](2);
        testData.fees[0] = new uint256[](1);
        testData.fees[0][0] = testData.fee1;
        testData.fees[1] = new uint256[](1);
        testData.fees[1][0] = testData.fee2;

        testData.initialTotalSupply = usdc.totalSupply();
        testData.initialFeeRecipientBalance = usdc.balanceOf(feeRecipient);
        testData.initialWalletBalance = usdc.balanceOf(address(wallet));

        // Depositor 1 Initial State
        assertEq(wallet.availableBalance(address(usdc), depositor), depositorInitialBalance, "Initial D1 Available");
        assertEq(wallet.withdrawingBalance(address(usdc), depositor), 0, "Initial D1 Withdrawing");

        // Depositor 2 Initial State
        assertEq(wallet.availableBalance(address(usdc), depositor2), depositor2InitialBalance, "Initial D2 Available");
        assertEq(wallet.withdrawingBalance(address(usdc), depositor2), 0, "Initial D2 Withdrawing");

        // Event for Depositor 1's burn
        testData.eventParams1.token = address(usdc);
        testData.eventParams1.depositor = depositor;
        testData.eventParams1.transferSpecHash = keccak256(TransferSpecLib.encodeTransferSpec(testData.auth1.spec));
        testData.eventParams1.destinationDomain = testData.auth1.spec.destinationDomain;
        testData.eventParams1.recipient = testData.auth1.spec.destinationRecipient;
        testData.eventParams1.authorizer = depositor;
        testData.eventParams1.value = testData.burnValue1;
        testData.eventParams1.fee = testData.fee1;
        testData.eventParams1.fromAvailable = testData.burnValue1 + testData.fee1;
        testData.eventParams1.fromWithdrawing = 0;
        _expectBurnEvent(testData.eventParams1);

        // Event for Depositor 2's burn
        testData.eventParams2.token = address(usdc);
        testData.eventParams2.depositor = depositor2;
        testData.eventParams2.transferSpecHash = keccak256(TransferSpecLib.encodeTransferSpec(testData.auth2.spec));
        testData.eventParams2.destinationDomain = testData.auth2.spec.destinationDomain;
        testData.eventParams2.recipient = testData.auth2.spec.destinationRecipient;
        testData.eventParams2.authorizer = depositor2;
        testData.eventParams2.value = testData.burnValue2;
        testData.eventParams2.fee = testData.fee2;
        testData.eventParams2.fromAvailable = testData.burnValue2 + testData.fee2;
        testData.eventParams2.fromWithdrawing = 0;
        _expectBurnEvent(testData.eventParams2);

        _callGatewayBurnSignedBy(testData.authorizations, testData.signatures, testData.fees, burnSignerKey);

        testData.expectedTotalFee = testData.fee1 + testData.fee2;
        testData.expectedTotalValueBurned = testData.burnValue1 + testData.burnValue2;
        testData.expectedTotalDeducted = (testData.burnValue1 + testData.fee1) + (testData.burnValue2 + testData.fee2);

        // Check Depositor 1 Final State
        assertEq(
            wallet.availableBalance(address(usdc), depositor),
            depositorInitialBalance - (testData.burnValue1 + testData.fee1),
            "Final D1 Available"
        );
        assertEq(wallet.withdrawingBalance(address(usdc), depositor), 0, "Final D1 Withdrawing");
        assertEq(usdc.balanceOf(depositor), 0, "Final D1 External");

        // Check Depositor 2 Final State
        assertEq(
            wallet.availableBalance(address(usdc), depositor2),
            depositor2InitialBalance - (testData.burnValue2 + testData.fee2),
            "Final D2 Available"
        );
        assertEq(wallet.withdrawingBalance(address(usdc), depositor2), 0, "Final D2 Withdrawing");
        assertEq(usdc.balanceOf(depositor2), 0, "Final D2 External");

        assertEq(
            usdc.balanceOf(feeRecipient),
            testData.initialFeeRecipientBalance + testData.expectedTotalFee,
            "Final Fee Recipient Balance"
        );
        assertEq(
            usdc.balanceOf(address(wallet)),
            testData.initialWalletBalance - testData.expectedTotalDeducted,
            "Final Wallet Balance"
        );
        assertEq(
            usdc.totalSupply(), testData.initialTotalSupply - testData.expectedTotalValueBurned, "Final Total Supply"
        );
    }

    // ===== Burn Authorization Encoding Tests =====

    function test_encodeBurnAuthorization() public view {
        bytes memory walletEncoded = wallet.encodeBurnAuthorization(baseAuth);
        bytes memory libEncoded = BurnAuthorizationLib.encodeBurnAuthorization(baseAuth);
        assertEq(walletEncoded, libEncoded);
    }

    function test_encodeBurnAuthorizations() public view {
        BurnAuthorization memory auth1 = baseAuth;
        BurnAuthorization memory auth2 = baseAuth;

        BurnAuthorization[] memory authArray = new BurnAuthorization[](2);
        authArray[0] = auth1;
        authArray[1] = auth2;

        bytes memory walletEncoded = wallet.encodeBurnAuthorizations(authArray);

        BurnAuthorizationSet memory authSet;
        authSet.authorizations = authArray;
        bytes memory libEncoded = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        assertEq(walletEncoded, libEncoded);
    }

    function test_validateBurnAuthorizations_success_singleAuth() public view {
        BurnAuthorization memory auth = baseAuth;
        auth.spec.sourceSigner = bytes32(uint256(uint160(depositor)));

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);

        assertTrue(wallet.validateBurnAuthorizations(encodedAuth, depositor));
    }

    function test_validateBurnAuthorizations_success_setOfAuths() public view {
        BurnAuthorization memory auth1 = baseAuth;
        BurnAuthorization memory auth2 = baseAuth;
        auth1.spec.sourceSigner = bytes32(uint256(uint160(depositor)));
        auth2.spec.sourceSigner = bytes32(uint256(uint160(depositor)));

        BurnAuthorization[] memory authArray = new BurnAuthorization[](2);
        authArray[0] = auth1;
        authArray[1] = auth2;

        BurnAuthorizationSet memory authSet;
        authSet.authorizations = authArray;

        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        assertTrue(wallet.validateBurnAuthorizations(encodedAuthSet, depositor));
    }

    function test_validateBurnAuthorizations_failure_mismatchedSigner_singleAuth() public {
        BurnAuthorization memory auth = baseAuth;
        auth.spec.sourceSigner = bytes32(uint256(uint160(depositor)));

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);

        // Sign with a different key (attacker)
        address attacker = makeAddr("attacker");

        // Expect revert because the signer (attacker) is not authorized for the depositor's balance
        vm.expectRevert(
            abi.encodeWithSelector(
                Burns.InvalidAuthorizationSourceSignerAtIndex.selector, uint32(0), depositor, attacker
            )
        );
        wallet.validateBurnAuthorizations(encodedAuth, attacker);
    }

    function test_validateBurnAuthorizations_failure_mismatchedSigner_SetOfAuths() public {
        address otherSignerAddr = makeAddr("otherSigner");

        BurnAuthorization memory auth1 = baseAuth;
        BurnAuthorization memory auth2 = baseAuth;

        // Set one auth with the depositor, one with a different signer
        auth1.spec.sourceSigner = bytes32(uint256(uint160(depositor)));
        auth2.spec.sourceSigner = bytes32(uint256(uint160(otherSignerAddr)));

        BurnAuthorization[] memory authArray = new BurnAuthorization[](2);
        authArray[0] = auth1;
        authArray[1] = auth2;

        BurnAuthorizationSet memory authSet;
        authSet.authorizations = authArray;

        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        // Expect revert because the recovered signer (depositor) won't match auth2's sourceSigner (otherSignerAddr)
        vm.expectRevert(
            abi.encodeWithSelector(
                Burns.InvalidAuthorizationSourceSignerAtIndex.selector, uint32(1), otherSignerAddr, depositor
            )
        );
        wallet.validateBurnAuthorizations(encodedAuthSet, depositor);
    }

    function test_validateBurnAuthorizations_success_irrelevantDomain_singleAuth() public view {
        BurnAuthorization memory auth = baseAuth;
        auth.spec.sourceDomain = domain + 1; // Irrelevant domain

        bytes memory encodedAuth = BurnAuthorizationLib.encodeBurnAuthorization(auth);

        // Validation should succeed even if the data isn't relevant to the current domain
        assertTrue(wallet.validateBurnAuthorizations(encodedAuth, depositor));
    }

    function test_validateBurnAuthorizations_success_irrelevantDomain_setOfAuths() public view {
        BurnAuthorization memory relevantAuth = baseAuth;
        BurnAuthorization memory irrelevantAuth = baseAuth;
        irrelevantAuth.spec.sourceDomain = domain + 1; // Irrelevant domain

        BurnAuthorization[] memory authArray = new BurnAuthorization[](2);
        authArray[0] = relevantAuth;
        authArray[1] = irrelevantAuth;

        BurnAuthorizationSet memory authSet;
        authSet.authorizations = authArray;

        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        // Validation should succeed even if there are irrelevant domains
        assertTrue(wallet.validateBurnAuthorizations(encodedAuthSet, depositor));
    }

    function test_validateBurnAuthorizations_revert_notAllSameToken_setOfAuths() public {
        BurnAuthorization memory usdcAuth = baseAuth; // Auth for USDC
        BurnAuthorization memory otherTokenAuth = baseAuth;
        otherTokenAuth.spec.sourceToken = AddressLib._addressToBytes32(otherToken); // Auth for the other token

        BurnAuthorization[] memory authArray = new BurnAuthorization[](2);
        authArray[0] = usdcAuth;
        authArray[1] = otherTokenAuth;

        BurnAuthorizationSet memory authSet;
        authSet.authorizations = authArray;

        bytes memory encodedAuthSet = BurnAuthorizationLib.encodeBurnAuthorizationSet(authSet);

        // Should revert because the relevant auths are for different tokens
        vm.expectRevert(Burns.NotAllSameToken.selector);
        wallet.validateBurnAuthorizations(encodedAuthSet, depositor);
    }
}
