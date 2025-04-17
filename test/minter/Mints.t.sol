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

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {MintAuthorization, MintAuthorizationSet} from "src/lib/authorizations/MintAuthorizations.sol";
import {MintAuthorizationLib} from "src/lib/authorizations/MintAuthorizationLib.sol";
import {TransferSpec, TRANSFER_SPEC_VERSION} from "src/lib/authorizations/TransferSpec.sol";
import {TransferSpecLib, BYTES4_BYTES} from "src/lib/authorizations/TransferSpecLib.sol";
import {SpendHashes, SpendHashesStorage} from "src/lib/common/SpendHashes.sol";
import {_addressToBytes32} from "src/lib/util/addresses.sol";
import {SpendMinter} from "src/SpendMinter.sol";
import {SpendWallet} from "src/SpendWallet.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";
import {Test} from "forge-std/Test.sol";
import {Denylistable} from "src/lib/common/Denylistable.sol";

/// Tests minting functionality of SpendMinter
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

    SpendMinter private minter;
    SpendWallet private wallet;
    MintAuthorization private baseAuth;
    MintAuthorization private sameChainBaseAuth;

    function setUp() public {
        domain = ForkTestUtils.forkVars().domain;
        (wallet, minter) = deploy(owner, domain);
        (mintAuthorizationSigner, mintAuthorizationSignerKey) = makeAddrAndKey("mintAuthorizationSigner");
        vm.startPrank(owner);
        minter.updateMintAuthorizationSigner(mintAuthorizationSigner);
        minter.updateDenylister(owner);
        vm.stopPrank();

        baseAuth = MintAuthorization({
            maxBlockHeight: block.number + defaultMaxBlockHeightOffset,
            spec: TransferSpec({
                version: TRANSFER_SPEC_VERSION,
                sourceDomain: 2 * domain,
                destinationDomain: domain,
                sourceContract: _addressToBytes32(sourceContract),
                destinationContract: _addressToBytes32(address(minter)),
                sourceToken: _addressToBytes32(sourceToken),
                destinationToken: _addressToBytes32(destinationToken),
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
                sourceToken: _addressToBytes32(destinationToken),
                destinationToken: _addressToBytes32(destinationToken),
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

    function test_spend_revertIfCallerDenylisted() public {
        vm.startPrank(owner);
        minter.denylist(address(this));
        vm.stopPrank();

        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(baseAuth);
        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, address(this)));
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    // ===== Signature Tests =====

    function test_spend_emptyAuth_revertsOnCorrectSigner() public {
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.AuthorizationDataTooShort.selector, BYTES4_BYTES, 0));
        _callSpendSignedBy(new bytes(0), mintAuthorizationSignerKey);
    }

    // TODO: Uncomment and move when full minting is implemented
    // function test_spend_validAuth_correctSigner(MintAuthorization memory authorization) public {
    //     authorization.spec.metadata = METADATA;
    //     bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(authorization);
    //     _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    // }

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

    function test_spend_revertIfInvalidMagic() public {
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(baseAuth);
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
        baseAuth.maxBlockHeight = block.number - 1;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(baseAuth);
        vm.expectRevert(
            abi.encodeWithSelector(SpendMinter.AuthorizationExpired.selector, 0, baseAuth.maxBlockHeight, block.number)
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfExpiredAuthSet() public {
        MintAuthorization memory expiredAuth = baseAuth; // storage -> memory creates a copy
        expiredAuth.maxBlockHeight = block.number - 1;

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = baseAuth;
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
        baseAuth.spec.value = 0;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(baseAuth);
        vm.expectRevert(abi.encodeWithSelector(SpendMinter.MintValueMustBePositive.selector, 0));
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfZeroValueAuthSet() public {
        MintAuthorization memory zeroValueAuth = baseAuth; // storage -> memory creates a copy
        zeroValueAuth.spec.value = 0;

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = baseAuth;
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

        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(baseAuth);
        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, recipient));
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfDestinationRecipientDenylistedAuthSet() public {
        MintAuthorization memory denylistedRecipientAuth = baseAuth; // storage -> memory creates a copy
        address denylistedRecipient = makeAddr("denylistedRecipient");
        denylistedRecipientAuth.spec.destinationRecipient = _addressToBytes32(denylistedRecipient);

        vm.startPrank(owner);
        minter.denylist(denylistedRecipient);
        vm.stopPrank();

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = baseAuth;
        authorizations[1] = denylistedRecipientAuth;

        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthorizations = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        vm.expectRevert(abi.encodeWithSelector(Denylistable.AccountDenylisted.selector, denylistedRecipient));
        _callSpendSignedBy(encodedAuthorizations, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfNonZeroAndInvalidDestinationCaller() public {
        address invalidDestinationCaller = makeAddr("invalidDestinationCaller");
        baseAuth.spec.destinationCaller = _addressToBytes32(invalidDestinationCaller);
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(baseAuth);

        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.InvalidAuthorizationDestinationCaller.selector, 0, invalidDestinationCaller, address(this)
            )
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfNonZeroAndInvalidDestinationCallerAuthSet() public {
        MintAuthorization memory invalidDestinationCallerAuth = baseAuth; // storage -> memory creates a copy
        address invalidDestinationCaller = makeAddr("invalidDestinationCaller");
        invalidDestinationCallerAuth.spec.destinationCaller = _addressToBytes32(invalidDestinationCaller);

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = baseAuth;
        authorizations[1] = invalidDestinationCallerAuth;

        MintAuthorizationSet memory authSet = MintAuthorizationSet({authorizations: authorizations});
        bytes memory encodedAuthorizations = MintAuthorizationLib.encodeMintAuthorizationSet(authSet);

        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.InvalidAuthorizationDestinationCaller.selector, 1, invalidDestinationCaller, address(this)
            )
        );
        _callSpendSignedBy(encodedAuthorizations, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfInvalidDestinationDomainAuth() public {
        baseAuth.spec.destinationDomain = domain + 1;
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(baseAuth);
        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.InvalidAuthorizationDestinationDomain.selector,
                0,
                baseAuth.spec.destinationDomain,
                domain
            )
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfInvalidDestinationDomainAuthSet() public {
        MintAuthorization memory invalidDomainAuth = baseAuth; // storage -> memory creates a copy
        invalidDomainAuth.spec.destinationDomain = domain + 1;

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = baseAuth;
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
        baseAuth.spec.destinationContract = _addressToBytes32(invalidDestinationContract);
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(baseAuth);

        vm.expectRevert(
            abi.encodeWithSelector(
                SpendMinter.InvalidAuthorizationDestinationContract.selector, 0, invalidDestinationContract
            )
        );
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }

    function test_spend_revertIfInvalidDestinationContractAuthSet() public {
        MintAuthorization memory invalidContractAuth = baseAuth; // storage -> memory creates a copy
        address invalidDestinationContract = makeAddr("invalidDestinationContract");
        invalidContractAuth.spec.destinationContract = _addressToBytes32(invalidDestinationContract);

        MintAuthorization[] memory authorizations = new MintAuthorization[](2);
        authorizations[0] = baseAuth;
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
                SpendMinter.InvalidAuthorizationToken.selector, 0, differentSourceToken, destinationToken
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
                SpendMinter.InvalidAuthorizationToken.selector, 1, differentSourceToken, destinationToken
            )
        );
        _callSpendSignedBy(encodedAuthorizations, mintAuthorizationSignerKey);
    }

    // ===== Replay Protection =====
    function test_spend_revertIfTransferSpecAlreadySpent() public {
        bytes32 specHash = keccak256(TransferSpecLib.encodeTransferSpec(baseAuth.spec));
        bytes memory encodedAuth = MintAuthorizationLib.encodeMintAuthorization(baseAuth);
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
        vm.expectRevert(abi.encodeWithSelector(SpendHashesStorage.SpendHashUsed.selector, specHash));
        _callSpendSignedBy(encodedAuth, mintAuthorizationSignerKey);
    }
}
