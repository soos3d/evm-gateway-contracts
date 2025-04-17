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

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {SpendMinter} from "src/SpendMinter.sol";
import {SpendWallet} from "src/SpendWallet.sol";
import {MintAuthorization, MintAuthorizationSet} from "src/lib/authorizations/MintAuthorizations.sol";
import {MintAuthorizationLib} from "src/lib/authorizations/MintAuthorizationLib.sol";
import {TransferSpec, TRANSFER_SPEC_VERSION} from "src/lib/authorizations/TransferSpec.sol";
import {TransferSpecLib, BYTES4_BYTES} from "src/lib/authorizations/TransferSpecLib.sol";
import {Denylistable} from "src/lib/common/Denylistable.sol";
import {SpendHashes} from "src/lib/common/SpendHashes.sol";
import {_addressToBytes32} from "src/lib/util/addresses.sol";
import {MasterMinter} from "../mock_fiattoken/contracts/minting/MasterMinter.sol";
import {FiatTokenV2_2} from "../mock_fiattoken/contracts/v2/FiatTokenV2_2.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";
import {Test} from "forge-std/Test.sol";

contract MockMintableToken is ERC20 {
    constructor() ERC20("Mock Spend Token", "MOCK") {}

    function mint(address to, uint256 amount) external returns (bool) {
        _mint(to, amount);
        return true;
    }
}

/// Tests minting functionality of SpendMinter
// solhint-disable max-states-count
contract TestMints is Test, DeployUtils {
    using MessageHashUtils for bytes32;

    uint32 private domain;
    address private owner = makeAddr("owner");
    address private mintAuthorizationSigner;
    uint256 private mintAuthorizationSignerKey;
    address private sourceContract = makeAddr("sourceContract");
    address private sourceToken = makeAddr("sourceToken");
    address private destinationToken = makeAddr("destinationToken");
    address private recipient = makeAddr("recipient");
    address private depositor = makeAddr("depositor");
    uint256 private spendValue = 1000 * 10 ** 6;
    uint256 private defaultMaxBlockHeightOffset = 100;
    bytes internal constant METADATA = "Test metadata";

    FiatTokenV2_2 private usdc;
    MockMintableToken private mockToken;

    MintAuthorization private crossChainBaseAuth;
    MintAuthorization private sameChainBaseAuth;

    SpendMinter private minter;
    SpendWallet private wallet;

    function setUp() public {
        domain = ForkTestUtils.forkVars().domain;
        usdc = FiatTokenV2_2(ForkTestUtils.forkVars().usdc);
        (wallet, minter) = deploy(owner, domain);
        mockToken = new MockMintableToken();

        (mintAuthorizationSigner, mintAuthorizationSignerKey) = makeAddrAndKey("mintAuthorizationSigner");
        vm.startPrank(owner);
        {
            minter.addSupportedToken(address(usdc));
            minter.addSupportedToken(address(mockToken));
            minter.updateDenylister(owner);
            minter.updateMintAuthorizationSigner(mintAuthorizationSigner);
            minter.updateMintAuthority(address(usdc), address(usdc));
        }
        vm.stopPrank();

        // Setup minter as USDC minter
        address masterMinterAddr = usdc.masterMinter();
        if (masterMinterAddr.code.length > 0) {
            MasterMinter masterMinter = MasterMinter(masterMinterAddr);
            address masterMinterOwner = masterMinter.owner();
            vm.startPrank(masterMinterOwner);
            masterMinter.configureController(masterMinterOwner, address(minter));
            masterMinter.configureMinter(type(uint256).max);
            vm.stopPrank();
        } else {
            // On testnet MasterMinter can be an EOA
            vm.startPrank(masterMinterAddr);
            usdc.configureMinter(address(minter), type(uint256).max);
            vm.stopPrank();
        }

        crossChainBaseAuth = MintAuthorization({
            maxBlockHeight: block.number + defaultMaxBlockHeightOffset,
            spec: TransferSpec({
                version: TRANSFER_SPEC_VERSION,
                sourceDomain: domain + 1, // A different source domain
                destinationDomain: domain,
                sourceContract: _addressToBytes32(sourceContract),
                destinationContract: _addressToBytes32(address(minter)),
                sourceToken: _addressToBytes32(sourceToken),
                destinationToken: _addressToBytes32(address(usdc)),
                sourceDepositor: _addressToBytes32(depositor),
                destinationRecipient: _addressToBytes32(recipient),
                sourceSigner: bytes32(0),
                destinationCaller: bytes32(0),
                value: spendValue,
                nonce: keccak256("nonceCrossChain"),
                metadata: METADATA
            })
        });

        sameChainBaseAuth = MintAuthorization({
            maxBlockHeight: block.number + defaultMaxBlockHeightOffset,
            spec: TransferSpec({
                version: TRANSFER_SPEC_VERSION,
                sourceDomain: domain,
                destinationDomain: domain,
                sourceContract: _addressToBytes32(address(wallet)),
                destinationContract: _addressToBytes32(address(minter)),
                sourceToken: _addressToBytes32(address(usdc)),
                destinationToken: _addressToBytes32(address(usdc)),
                sourceDepositor: _addressToBytes32(depositor),
                destinationRecipient: _addressToBytes32(recipient),
                sourceSigner: bytes32(0),
                destinationCaller: bytes32(0),
                value: spendValue,
                nonce: keccak256("nonceSameChain"),
                metadata: METADATA
            })
        });
    }

    function _callSpendSignedBy(bytes memory authorizations, uint256 signerKey) internal {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, keccak256(authorizations).toEthSignedMessageHash());
        bytes memory signature = abi.encodePacked(r, s, v);

        minter.spend(authorizations, signature);
    }

    // ===== Entry Checks / Modifier Tests =====

    function test_spend_revertIfPaused() public {
        vm.startPrank(owner);
        minter.pause();
        vm.stopPrank();

        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(crossChainBaseAuth);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfCallerDenylisted() public {
        vm.startPrank(owner);
        minter.denylist(address(this));
        vm.stopPrank();

        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(crossChainBaseAuth);
        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, address(this)));
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    // ===== Signature Tests =====

    function test_spend_emptyAuth_revertsOnCorrectSigner() public {
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.AuthorizationDataTooShort.selector, BYTES4_BYTES, 0));
        _callSpendSignedBy(new bytes(0), mintAuthorizationSignerKey);
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

    // ===== Authorization Structural Validation Tests =====

    function test_spend_revertIfNoAuthsProvided() public {
        MintAuthorization[] memory authorizations = new MintAuthorization[](0);
        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthorizations = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        vm.expectRevert(SpendMinter.MustHaveAtLeastOneMintAuthorization.selector);
        _callSpendSignedBy(encodedAuthorizations, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfInvalidMagic() public {
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(crossChainBaseAuth);
        // Corrupt magic
        encodedAuth[0] = hex"FF";

        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedAuth[i];
        }
        bytes4 corruptedMagic = bytes4(tempBytes);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidAuthorizationMagic.selector, corruptedMagic));
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    // ===== Authorization Content Validation Tests =====

    function test_spend_revertIfExpiredAuth() public {
        crossChainBaseAuth.maxBlockHeight = block.number - 1;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(crossChainBaseAuth);
        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.AuthorizationExpired.selector, 0, crossChainBaseAuth.maxBlockHeight, block.number
            )
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfExpiredAuthSet() public {
        MintAuthorization memory expiredAuth = crossChainBaseAuth; // storage -> memory creates a copy
        expiredAuth.maxBlockHeight = block.number - 1;

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = crossChainBaseAuth;
        authorizations[1] = expiredAuth;

        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthorizations = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.AuthorizationExpired.selector, 1, expiredAuth.maxBlockHeight, block.number
            )
        );
        _callSpendSignedBy(encodedAuthorizations, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfZeroValue() public {
        crossChainBaseAuth.spec.value = 0;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(crossChainBaseAuth);
        vm.expectRevert(abi.encodeWithSelector(SpendMinter.MintValueMustBePositive.selector, 0));
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfZeroValueAuthSet() public {
        MintAuthorization memory zeroValueAuth = crossChainBaseAuth; // storage -> memory creates a copy
        zeroValueAuth.spec.value = 0;

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = crossChainBaseAuth;
        authorizations[1] = zeroValueAuth;

        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthorizations = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        vm.expectRevert(abi.encodeWithSelector(SpendMinter.MintValueMustBePositive.selector, 1));
        _callSpendSignedBy(encodedAuthorizations, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfDestinationRecipientDenylisted() public {
        vm.startPrank(owner);
        minter.denylist(recipient);
        vm.stopPrank();

        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(crossChainBaseAuth);
        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, recipient));
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfDestinationRecipientDenylistedAuthSet() public {
        MintAuthorization memory denylistedRecipientAuth = crossChainBaseAuth; // storage -> memory creates a copy
        address denylistedRecipient = makeAddr("denylistedRecipient");
        denylistedRecipientAuth.spec.destinationRecipient = _addressToBytes32(denylistedRecipient);

        vm.startPrank(owner);
        minter.denylist(denylistedRecipient);
        vm.stopPrank();

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = crossChainBaseAuth;
        authorizations[1] = denylistedRecipientAuth;

        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthorizations = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, denylistedRecipient));
        _callSpendSignedBy(encodedAuthorizations, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfNonZeroAndInvalidDestinationCaller() public {
        address destinationCaller = makeAddr("destinationCallerOtherThanThis");
        crossChainBaseAuth.spec.destinationCaller = _addressToBytes32(destinationCaller);
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(crossChainBaseAuth);

        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.InvalidAuthorizationDestinationCaller.selector, 0, destinationCaller, address(this)
            )
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfNonZeroAndInvalidDestinationCallerAuthSet() public {
        MintAuthorization memory invalidDestinationCallerAuth = crossChainBaseAuth; // storage -> memory creates a copy
        address destinationCaller = makeAddr("destinationCallerOtherThanThis");
        invalidDestinationCallerAuth.spec.destinationCaller = _addressToBytes32(destinationCaller);

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = crossChainBaseAuth;
        authorizations[1] = invalidDestinationCallerAuth;

        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthorizations = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.InvalidAuthorizationDestinationCaller.selector, 1, destinationCaller, address(this)
            )
        );
        _callSpendSignedBy(encodedAuthorizations, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfInvalidDestinationDomainAuth() public {
        crossChainBaseAuth.spec.destinationDomain = domain + 1;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(crossChainBaseAuth);
        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.InvalidAuthorizationDestinationDomain.selector,
                0,
                crossChainBaseAuth.spec.destinationDomain,
                domain
            )
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfInvalidDestinationDomainAuthSet() public {
        MintAuthorization memory invalidDomainAuth = crossChainBaseAuth; // storage -> memory creates a copy
        invalidDomainAuth.spec.destinationDomain = domain + 1;

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = crossChainBaseAuth;
        authorizations[1] = invalidDomainAuth;

        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthorizations = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.InvalidAuthorizationDestinationDomain.selector,
                1,
                invalidDomainAuth.spec.destinationDomain,
                domain
            )
        );
        _callSpendSignedBy(encodedAuthorizations, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfInvalidDestinationContract() public {
        address invalidDestinationContract = makeAddr("invalidDestinationContract");
        crossChainBaseAuth.spec.destinationContract = _addressToBytes32(invalidDestinationContract);
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(crossChainBaseAuth);

        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.InvalidAuthorizationDestinationContract.selector, 0, invalidDestinationContract
            )
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfInvalidDestinationContractAuthSet() public {
        MintAuthorization memory invalidContractAuth = crossChainBaseAuth; // storage -> memory creates a copy
        address invalidDestinationContract = makeAddr("invalidDestinationContract");
        invalidContractAuth.spec.destinationContract = _addressToBytes32(invalidDestinationContract);

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = crossChainBaseAuth;
        authorizations[1] = invalidContractAuth;

        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthorizations = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.InvalidAuthorizationDestinationContract.selector, 1, invalidDestinationContract
            )
        );
        _callSpendSignedBy(encodedAuthorizations, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfSameChainInvalidSourceContract() public {
        MintAuthorization memory auth = sameChainBaseAuth;
        address invalidSourceContract = makeAddr("invalidSourceContract");
        auth.spec.sourceContract = _addressToBytes32(invalidSourceContract); // Set wrong source contract
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);

        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.InvalidAuthorizationSourceContract.selector, 0, invalidSourceContract, address(wallet)
            )
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfSameChainInvalidSourceContractAuthSet() public {
        MintAuthorization memory invalidSourceAuth = sameChainBaseAuth;
        address invalidSourceContract = makeAddr("invalidSourceContract");
        invalidSourceAuth.spec.sourceContract = _addressToBytes32(invalidSourceContract); // Set wrong source contract

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = sameChainBaseAuth;
        authorizations[1] = invalidSourceAuth;

        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthorizations = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.InvalidAuthorizationSourceContract.selector, 1, invalidSourceContract, address(wallet)
            )
        );
        _callSpendSignedBy(encodedAuthorizations, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfSameChainInvalidToken() public {
        MintAuthorization memory auth = sameChainBaseAuth;
        address differentSourceToken = makeAddr("differentSourceToken");
        auth.spec.sourceToken = _addressToBytes32(differentSourceToken); // Set different source token
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);

        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.InvalidAuthorizationToken.selector, 0, differentSourceToken, address(usdc)
            )
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfSameChainInvalidTokenAuthSet() public {
        MintAuthorization memory invalidTokenAuth = sameChainBaseAuth;
        address differentSourceToken = makeAddr("differentSourceToken");
        invalidTokenAuth.spec.sourceToken = _addressToBytes32(differentSourceToken); // Set different source token

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = sameChainBaseAuth;
        authorizations[1] = invalidTokenAuth;

        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthorizations = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.InvalidAuthorizationToken.selector, 1, differentSourceToken, address(usdc)
            )
        );
        _callSpendSignedBy(encodedAuthorizations, mintAuthorizationSignerKey);
    }

    // ===== Replay Protection Tests =====

    function test_spend_revertIfTransferSpecAlreadySpent() public {
        bytes32 specHash = keccak256(TransferSpecLib.encodeTransferSpec(crossChainBaseAuth.spec));
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(crossChainBaseAuth);
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
        vm.expectRevert(abi.encodeWithSelector(SpendHashes.SpendHashUsed.selector, specHash));
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    // ===== Cross-chain Tests =====

    function test_spend_crossChain_successValidAuthAndMintAuthority() public {
        MintAuthorization memory authorization = crossChainBaseAuth;
        authorization.spec.value = spendValue;

        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(authorization);
        bytes32 specHash = keccak256(TransferSpecLib.encodeTransferSpec(authorization.spec));

        assertEq(usdc.balanceOf(recipient), 0);

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient,
            specHash,
            authorization.spec.sourceDomain,
            _addressToBytes32(depositor),
            spendValue,
            encodedAuth
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);

        assertEq(usdc.balanceOf(recipient), spendValue);
    }

    function test_spend_crossChain_customDestinationCaller_successValidAuthAndMintAuthority() public {
        MintAuthorization memory auth = crossChainBaseAuth;
        address destinationCaller = makeAddr("destinationCaller");
        auth.spec.destinationCaller = _addressToBytes32(destinationCaller);
        auth.spec.value = spendValue;

        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        bytes32 specHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));

        assertEq(usdc.balanceOf(recipient), 0);

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient,
            specHash,
            auth.spec.sourceDomain,
            _addressToBytes32(depositor),
            spendValue,
            encodedAuth
        );

        vm.startPrank(destinationCaller);
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
        vm.stopPrank();

        assertEq(usdc.balanceOf(recipient), spendValue);
    }

    function test_spend_crossChain_successValidAuthAndNoMintAuthority() public {
        MintAuthorization memory auth = crossChainBaseAuth;
        auth.spec.value = spendValue;
        auth.spec.destinationToken = _addressToBytes32(address(mockToken));

        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        bytes32 specHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));

        assertEq(mockToken.balanceOf(recipient), 0);

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(mockToken),
            recipient,
            specHash,
            auth.spec.sourceDomain,
            _addressToBytes32(depositor),
            spendValue,
            encodedAuth
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);

        assertEq(mockToken.balanceOf(recipient), spendValue);
    }

    function test_spend_crossChain_sameRecipient_sameToken_successValidAuthSetAndMintAuthority() public {
        MintAuthorization memory auth1 = crossChainBaseAuth;
        auth1.spec.value = spendValue;
        MintAuthorization memory auth2 = crossChainBaseAuth;
        auth2.spec.value = spendValue + 1;

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;
        bytes memory encodedAuth =
            MintAuthorizationLib.encodeMintAuthorizationSet(MintAuthorizationSet({authorizations: authorizations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(auth1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(auth2.spec));

        assertEq(usdc.balanceOf(recipient), 0);

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient,
            specHash1,
            auth1.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth1.spec.value,
            encodedAuth
        );
        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient,
            specHash2,
            auth2.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth2.spec.value,
            encodedAuth
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);

        assertEq(usdc.balanceOf(recipient), auth1.spec.value + auth2.spec.value);
    }

    function test_spend_crossChain_sameRecipient_differentTokens_successValidAuthSet() public {
        MintAuthorization memory auth1 = crossChainBaseAuth;
        auth1.spec.value = spendValue;
        auth1.spec.destinationToken = _addressToBytes32(address(usdc));
        auth1.spec.destinationRecipient = _addressToBytes32(recipient);

        MintAuthorization memory auth2 = crossChainBaseAuth;
        auth2.spec.value = spendValue / 2;
        auth2.spec.destinationToken = _addressToBytes32(address(mockToken));
        auth2.spec.destinationRecipient = _addressToBytes32(recipient);

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;
        bytes memory encodedAuth =
            MintAuthorizationLib.encodeMintAuthorizationSet(MintAuthorizationSet({authorizations: authorizations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(auth1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(auth2.spec));

        assertEq(usdc.balanceOf(recipient), 0, "Initial USDC balance recipient");
        assertEq(mockToken.balanceOf(recipient), 0, "Initial MockToken balance recipient");

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient,
            specHash1,
            auth1.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth1.spec.value,
            encodedAuth
        );

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(mockToken),
            recipient,
            specHash2,
            auth2.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth2.spec.value,
            encodedAuth
        );

        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);

        assertEq(usdc.balanceOf(recipient), auth1.spec.value, "Final USDC balance recipient");
        assertEq(mockToken.balanceOf(recipient), auth2.spec.value, "Final MockToken balance recipient");
    }

    function test_spend_crossChain_differentRecipients_sameToken_successValidAuthSetAndMintAuthority() public {
        MintAuthorization memory auth1 = crossChainBaseAuth;
        auth1.spec.value = spendValue;
        address recipient1 = makeAddr("recipient1");
        auth1.spec.destinationRecipient = _addressToBytes32(recipient1);
        MintAuthorization memory auth2 = crossChainBaseAuth;
        auth2.spec.value = spendValue / 2;
        address recipient2 = makeAddr("recipient2");
        auth2.spec.destinationRecipient = _addressToBytes32(recipient2);

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;
        bytes memory encodedAuth =
            MintAuthorizationLib.encodeMintAuthorizationSet(MintAuthorizationSet({authorizations: authorizations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(auth1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(auth2.spec));

        assertEq(usdc.balanceOf(recipient1), 0);
        assertEq(usdc.balanceOf(recipient2), 0);

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient1,
            specHash1,
            auth1.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth1.spec.value,
            encodedAuth
        );
        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient2,
            specHash2,
            auth2.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth2.spec.value,
            encodedAuth
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);

        assertEq(usdc.balanceOf(recipient1), auth1.spec.value);
        assertEq(usdc.balanceOf(recipient2), auth2.spec.value);
    }

    function test_spend_crossChain_differentRecipients_differentTokens_successValidAuthSetAndMintAuthority() public {
        MintAuthorization memory auth1 = crossChainBaseAuth;
        auth1.spec.value = spendValue;
        address recipient1 = makeAddr("recipient1");
        auth1.spec.destinationRecipient = _addressToBytes32(recipient1);

        MintAuthorization memory auth2 = crossChainBaseAuth;
        auth2.spec.value = spendValue / 2;
        address recipient2 = makeAddr("recipient2");
        auth2.spec.destinationRecipient = _addressToBytes32(recipient2);
        auth2.spec.destinationToken = _addressToBytes32(address(mockToken));

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;
        bytes memory encodedAuth =
            MintAuthorizationLib.encodeMintAuthorizationSet(MintAuthorizationSet({authorizations: authorizations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(auth1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(auth2.spec));

        assertEq(usdc.balanceOf(recipient1), 0, "Initial USDC balance recipient1");
        assertEq(mockToken.balanceOf(recipient2), 0, "Initial MockToken balance recipient2");

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient1,
            specHash1,
            auth1.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth1.spec.value,
            encodedAuth
        );

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(mockToken),
            recipient2,
            specHash2,
            auth2.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth2.spec.value,
            encodedAuth
        );

        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);

        assertEq(usdc.balanceOf(recipient1), auth1.spec.value, "Final USDC balance recipient1");
        assertEq(mockToken.balanceOf(recipient2), auth2.spec.value, "Final MockToken balance recipient2");
    }

    function test_spend_crossChain_revertIfMintAuthorityMisconfigured() public {
        vm.startPrank(owner);
        minter.updateMintAuthority(address(usdc), makeAddr("invalidMintAuthority"));
        vm.stopPrank();

        MintAuthorization memory auth = crossChainBaseAuth;
        auth.spec.value = spendValue;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);

        // Expect a generic revert because the (mis)configured mint authority is an EOA
        vm.expectRevert();
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_crossChain_revertIfNotConfiguredAsMinter() public {
        MasterMinter masterMinter = MasterMinter(usdc.masterMinter());
        address masterMinterAddr = address(masterMinter);

        if (masterMinterAddr.code.length > 0) {
            address masterMinterOwner = masterMinter.owner();
            vm.startPrank(masterMinterOwner);
            masterMinter.removeMinter();
            vm.stopPrank();
        } else {
            vm.startPrank(masterMinterAddr);
            usdc.removeMinter(address(minter));
            vm.stopPrank();
        }

        MintAuthorization memory auth = crossChainBaseAuth;
        auth.spec.value = spendValue;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);

        vm.expectRevert("FiatToken: caller is not a minter");
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    // ===== Same-chain Tests =====

    function test_spend_sameChain_successValidAuth() public {
        MintAuthorization memory auth = sameChainBaseAuth;
        auth.spec.value = spendValue;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(auth);
        bytes32 specHash = keccak256(TransferSpecLib.encodeTransferSpec(auth.spec));
        assertEq(usdc.balanceOf(recipient), 0);

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient,
            specHash,
            auth.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth.spec.value,
            encodedAuth
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);

        // TODO: uncomment when same chain spend is implemented on the wallet contract
        // assertEq(usdc.balanceOf(recipient), spendValue);
    }

    function test_spend_sameChain_sameRecipient_sameToken_successValidAuthSet() public {
        MintAuthorization memory auth1 = sameChainBaseAuth;
        auth1.spec.value = spendValue;
        MintAuthorization memory auth2 = sameChainBaseAuth;
        auth2.spec.value = spendValue + 1;

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;
        bytes memory encodedAuth =
            MintAuthorizationLib.encodeMintAuthorizationSet(MintAuthorizationSet({authorizations: authorizations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(auth1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(auth2.spec));

        assertEq(usdc.balanceOf(recipient), 0);

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient,
            specHash1,
            auth1.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth1.spec.value,
            encodedAuth
        );
        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient,
            specHash2,
            auth2.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth2.spec.value,
            encodedAuth
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);

        // TODO: uncomment when same chain spend is implemented on the wallet contract
        // assertEq(usdc.balanceOf(recipient), auth1.spec.value + auth2.spec.value);
    }

    function test_spend_sameChain_sameRecipient_differentTokens_successValidAuthSet() public {
        MintAuthorization memory auth1 = sameChainBaseAuth;
        auth1.spec.value = spendValue;

        MintAuthorization memory auth2 = sameChainBaseAuth;
        auth2.spec.value = spendValue / 2;
        auth2.spec.sourceToken = _addressToBytes32(address(mockToken));
        auth2.spec.destinationToken = _addressToBytes32(address(mockToken));
        auth2.spec.destinationRecipient = _addressToBytes32(recipient);

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;
        bytes memory encodedAuth =
            MintAuthorizationLib.encodeMintAuthorizationSet(MintAuthorizationSet({authorizations: authorizations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(auth1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(auth2.spec));

        assertEq(usdc.balanceOf(recipient), 0, "Initial USDC balance recipient");
        assertEq(mockToken.balanceOf(recipient), 0, "Initial MockToken balance recipient");

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient,
            specHash1,
            auth1.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth1.spec.value,
            encodedAuth
        );

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(mockToken),
            recipient,
            specHash2,
            auth2.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth2.spec.value,
            encodedAuth
        );

        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);

        // TODO: uncomment when same chain spend is implemented on the wallet contract
        // assertEq(usdc.balanceOf(recipient), auth1.spec.value);
        // assertEq(mockToken.balanceOf(recipient), auth2.spec.value);
    }

    function test_spend_sameChain_differentRecipients_sameToken_successValidAuthSet() public {
        MintAuthorization memory auth1 = sameChainBaseAuth;
        auth1.spec.value = spendValue;
        address recipient1 = makeAddr("recipient1");
        auth1.spec.destinationRecipient = _addressToBytes32(recipient1);

        MintAuthorization memory auth2 = sameChainBaseAuth;
        auth2.spec.value = spendValue / 2;
        address recipient2 = makeAddr("recipient2");
        auth2.spec.destinationRecipient = _addressToBytes32(recipient2);

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;
        bytes memory encodedAuth =
            MintAuthorizationLib.encodeMintAuthorizationSet(MintAuthorizationSet({authorizations: authorizations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(auth1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(auth2.spec));

        assertEq(usdc.balanceOf(recipient1), 0, "Initial USDC balance recipient1");
        assertEq(usdc.balanceOf(recipient2), 0, "Initial USDC balance recipient2");

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient1,
            specHash1,
            auth1.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth1.spec.value,
            encodedAuth
        );
        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient2,
            specHash2,
            auth2.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth2.spec.value,
            encodedAuth
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);

        // TODO: uncomment when same chain spend is implemented on the wallet contract
        // assertEq(usdc.balanceOf(recipient1), auth1.spec.value);
        // assertEq(usdc.balanceOf(recipient2), auth2.spec.value);
    }

    function test_spend_sameChain_differentRecipients_differentTokens_successValidAuthSet() public {
        MintAuthorization memory auth1 = sameChainBaseAuth;
        auth1.spec.value = spendValue;
        address recipient1 = makeAddr("recipient1");
        auth1.spec.destinationRecipient = _addressToBytes32(recipient1);

        MintAuthorization memory auth2 = sameChainBaseAuth;
        auth2.spec.value = spendValue / 2;
        address recipient2 = makeAddr("recipient2");
        auth2.spec.destinationRecipient = _addressToBytes32(recipient2);
        auth2.spec.sourceToken = _addressToBytes32(address(mockToken));
        auth2.spec.destinationToken = _addressToBytes32(address(mockToken));

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = auth1;
        authorizations[1] = auth2;
        bytes memory encodedAuth =
            MintAuthorizationLib.encodeMintAuthorizationSet(MintAuthorizationSet({authorizations: authorizations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(auth1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(auth2.spec));

        assertEq(usdc.balanceOf(recipient1), 0, "Initial USDC balance recipient1");
        assertEq(mockToken.balanceOf(recipient2), 0, "Initial MockToken balance recipient2");

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(usdc),
            recipient1,
            specHash1,
            auth1.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth1.spec.value,
            encodedAuth
        );

        vm.expectEmit(true, true, true, true);
        emit SpendMinter.Spent(
            address(mockToken),
            recipient2,
            specHash2,
            auth2.spec.sourceDomain,
            _addressToBytes32(depositor),
            auth2.spec.value,
            encodedAuth
        );

        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);

        // TODO: uncomment when same chain spend is implemented on the wallet contract
        // assertEq(usdc.balanceOf(recipient1), auth1.spec.value);
        // assertEq(mockToken.balanceOf(recipient2), auth2.spec.value);
    }
}
