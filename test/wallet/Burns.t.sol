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
import {BurnAuthorization, BurnAuthorizationSet} from "src/lib/authorizations/BurnAuthorizations.sol";
import {BurnAuthorizationLib} from "src/lib/authorizations/BurnAuthorizationLib.sol";
import {TransferSpec, TRANSFER_SPEC_VERSION} from "src/lib/authorizations/TransferSpec.sol";
import {BurnLib} from "src/lib/wallet/BurnLib.sol";
import {_addressToBytes32} from "src/lib/util/addresses.sol";
import {MasterMinter} from "../mock_fiattoken/contracts/minting/MasterMinter.sol";
import {FiatTokenV2_2} from "../mock_fiattoken/contracts/v2/FiatTokenV2_2.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";
import {SignatureTestUtils} from "test/util/SignatureTestUtils.sol";

contract TestBurns is SignatureTestUtils, DeployUtils {
    using MessageHashUtils for bytes32;

    uint32 private domain;
    address private owner = makeAddr("owner");
    uint256 private depositorKey;
    address private depositor;
    address private recipient = makeAddr("recipient");
    address private destinationContract = makeAddr("destinationContract");
    address private burnSigner;
    uint256 private burnSignerKey;
    uint256 private defaultMaxBlockHeightOffset = 100;
    uint256 private defaultMaxFee = 10 ** 6;
    uint256 private spendValue = 1000 * 10 ** 6;
    bytes internal constant METADATA = "Test metadata";

    FiatTokenV2_2 private usdc;

    BurnAuthorization private baseAuth;

    SpendWallet private wallet;

    function setUp() public {
        domain = ForkTestUtils.forkVars().domain;
        usdc = FiatTokenV2_2(ForkTestUtils.forkVars().usdc);
        wallet = deployWalletOnly(owner, domain);

        (depositor, depositorKey) = makeAddrAndKey("depositor");
        (burnSigner, burnSignerKey) = makeAddrAndKey("burnSigner");

        vm.startPrank(owner);
        {
            wallet.addSupportedToken(address(usdc));
            wallet.updateDenylister(owner);
            wallet.updateBurnSigner(burnSigner);
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
                value: spendValue,
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

    function _signAuthOrAuthSet(bytes memory authOrAuthSet, uint256 signerKey) internal returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, keccak256(authOrAuthSet).toEthSignedMessageHash());
        signature = abi.encodePacked(r, s, v);
    }

    // ===== Entry Checks / Modifier Tests =====

    function test_burnSpent_revertIfPaused() external {
        vm.startPrank(owner);
        wallet.pause();
        vm.stopPrank();

        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _emptyArgs();
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        wallet.burnSpent(authorizations, signatures, fees, new bytes(0));
    }

    // ===== BurnSigner Signature Tests =====

    // TODO: add this test back after burns are implemented
    // function test_burnSpent_randomArgs_correctSigner() external {
    //     (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _randomArgs();
    //     _callBurnSpentSignedBy(authorizations, signatures, fees, burnSignerKey);
    // }

    function test_burnSpent_randomArgs_wrongSigner() external {
        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _randomArgs();
        (, uint256 wrongSignerKey) = makeAddrAndKey("wrongSigner");
        vm.expectRevert(BurnLib.InvalidBurnSigner.selector);
        _callBurnSpentSignedBy(authorizations, signatures, fees, wrongSignerKey);
    }

    function test_burnSpent_randomArgs_wrongSignatureLength() external {
        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _randomArgs();
        vm.expectRevert(BurnLib.InvalidBurnSigner.selector);
        wallet.burnSpent(authorizations, signatures, fees, bytes(hex"aaaa"));
    }

    // ===== Authorization Structural Validation Tests =====

    function test_burnSpent_revertIfNoAuthorizations() external {
        (bytes[] memory authorizations, bytes[] memory signatures, uint256[][] memory fees) = _emptyArgs();
        vm.expectRevert(BurnLib.MustHaveAtLeastOneBurnAuthorization.selector);
        wallet.burnSpent(authorizations, signatures, fees, new bytes(0));
    }

    function test_burnSpent_revertIfAuthSetIsEmpty() external {
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

    function test_burnSpent_revertIfFeesLengthMismatch() external {
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

    function test_burnSpent_revertIfInputLengthsMismatched() external {
        vm.expectRevert(BurnLib.MismatchedBurn.selector);
        wallet.burnSpent(new bytes[](2), new bytes[](1), new uint256[][](2), new bytes(0));
    }

    // ===== Authorization Content Validation Tests =====

    function test_burnSpent_revertIfAuthContainsZeroValue() external {
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

}
