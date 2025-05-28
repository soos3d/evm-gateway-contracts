/**
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
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
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Test} from "forge-std/Test.sol";
import {GatewayMinter} from "src/GatewayMinter.sol";
import {GatewayWallet} from "src/GatewayWallet.sol";
import {AddressLib} from "src/lib/AddressLib.sol";
import {AttestationLib} from "src/lib/AttestationLib.sol";
import {Attestation, AttestationSet} from "src/lib/Attestations.sol";
import {TransferSpec, TRANSFER_SPEC_VERSION} from "src/lib/TransferSpec.sol";
import {TransferSpecLib, BYTES4_BYTES} from "src/lib/TransferSpecLib.sol";
import {Denylist} from "src/modules/common/Denylist.sol";
import {TransferSpecHashes} from "src/modules/common/TransferSpecHashes.sol";
import {Mints} from "src/modules/minter/Mints.sol";
import {MasterMinter} from "test/mock_fiattoken/contracts/minting/MasterMinter.sol";
import {FiatTokenV2_2} from "test/mock_fiattoken/contracts/v2/FiatTokenV2_2.sol";
import {DeployUtils} from "test/util/DeployUtils.sol";
import {ForkTestUtils} from "test/util/ForkTestUtils.sol";

contract MockMintableToken is ERC20 {
    constructor() ERC20("Mock Mintable Token", "MOCK") {}

    function mint(address to, uint256 amount) external returns (bool) {
        _mint(to, amount);
        return true;
    }
}

/// Tests minting functionality of GatewayMinter
// solhint-disable max-states-count
contract GatewayMinterMintsTest is Test, DeployUtils {
    using MessageHashUtils for bytes32;

    uint32 private domain;
    address private owner = makeAddr("owner");
    address private attestationSigner;
    uint256 private attestationSignerKey;
    address private sourceSigner = makeAddr("sourceSigner");
    address private sourceContract = makeAddr("sourceContract");
    address private sourceToken = makeAddr("sourceToken");
    address private destinationToken = makeAddr("destinationToken");
    address private recipient = makeAddr("recipient");
    address private depositor = makeAddr("depositor");
    uint256 private mintValue = 1000 * 10 ** 6;
    uint256 private defaultMaxBlockHeightOffset = 100;
    bytes internal constant HOOK_DATA = "Test hook data";

    FiatTokenV2_2 private usdc;
    MockMintableToken private mockToken;

    Attestation private crossChainBaseAttestation;
    Attestation private sameChainBaseAttestation;

    GatewayMinter private minter;
    GatewayWallet private wallet;

    function setUp() public {
        domain = ForkTestUtils.forkVars().domain;
        usdc = FiatTokenV2_2(ForkTestUtils.forkVars().usdc);
        (wallet, minter) = deploy(owner, domain);
        mockToken = new MockMintableToken();

        (attestationSigner, attestationSignerKey) = makeAddrAndKey("attestationSigner");
        vm.startPrank(owner);
        {
            minter.addSupportedToken(address(usdc));
            minter.addSupportedToken(address(mockToken));
            minter.updateDenylister(owner);
            minter.addAttestationSigner(attestationSigner);
            minter.updateMintAuthority(address(usdc), address(usdc));
        }
        vm.stopPrank();

        deal(address(usdc), address(wallet), mintValue * 3);
        deal(address(mockToken), address(wallet), mintValue * 3);

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

        crossChainBaseAttestation = Attestation({
            maxBlockHeight: block.number + defaultMaxBlockHeightOffset,
            spec: TransferSpec({
                version: TRANSFER_SPEC_VERSION,
                sourceDomain: domain + 1, // A different source domain
                destinationDomain: domain,
                sourceContract: AddressLib._addressToBytes32(sourceContract),
                destinationContract: AddressLib._addressToBytes32(address(minter)),
                sourceToken: AddressLib._addressToBytes32(sourceToken),
                destinationToken: AddressLib._addressToBytes32(address(usdc)),
                sourceDepositor: AddressLib._addressToBytes32(depositor),
                destinationRecipient: AddressLib._addressToBytes32(recipient),
                sourceSigner: AddressLib._addressToBytes32(sourceSigner),
                destinationCaller: bytes32(0),
                value: mintValue,
                salt: keccak256("saltCrossChain"),
                hookData: HOOK_DATA
            })
        });

        sameChainBaseAttestation = Attestation({
            maxBlockHeight: block.number + defaultMaxBlockHeightOffset,
            spec: TransferSpec({
                version: TRANSFER_SPEC_VERSION,
                sourceDomain: domain,
                destinationDomain: domain,
                sourceContract: AddressLib._addressToBytes32(address(wallet)),
                destinationContract: AddressLib._addressToBytes32(address(minter)),
                sourceToken: AddressLib._addressToBytes32(address(usdc)),
                destinationToken: AddressLib._addressToBytes32(address(usdc)),
                sourceDepositor: AddressLib._addressToBytes32(depositor),
                destinationRecipient: AddressLib._addressToBytes32(recipient),
                sourceSigner: AddressLib._addressToBytes32(sourceSigner),
                destinationCaller: bytes32(0),
                value: mintValue,
                salt: keccak256("saltSameChain"),
                hookData: HOOK_DATA
            })
        });
    }

    function _callGatewayMintSignedBy(bytes memory attestation, uint256 signerKey) internal {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, keccak256(attestation).toEthSignedMessageHash());
        bytes memory signature = abi.encodePacked(r, s, v);

        minter.gatewayMint(attestation, signature);
    }

    // ===== Entry Checks / Modifier Tests =====

    function test_gatewayMint_revertIfPaused() public {
        vm.startPrank(owner);
        minter.pause();
        vm.stopPrank();

        bytes memory encodedAttestation = AttestationLib.encodeAttestation(crossChainBaseAttestation);
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    function test_gatewayMint_revertIfCallerDenylisted() public {
        vm.startPrank(owner);
        minter.denylist(address(this));
        vm.stopPrank();

        bytes memory encodedAttestation = AttestationLib.encodeAttestation(crossChainBaseAttestation);
        vm.expectRevert(abi.encodeWithSelector(Denylist.AccountDenylisted.selector, address(this)));
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    // ===== Signature Tests =====

    function test_gatewayMint_emptyAttestation_revertsOnCorrectSigner() public {
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.TransferPayloadDataTooShort.selector, BYTES4_BYTES, 0));
        _callGatewayMintSignedBy(new bytes(0), attestationSignerKey);
    }

    function test_gatewayMint_emptyAttestation_wrongSigner() public {
        (, uint256 wrongSignerKey) = makeAddrAndKey("wrongSigner");
        vm.expectRevert(Mints.InvalidAttestationSigner.selector);
        _callGatewayMintSignedBy(new bytes(0), wrongSignerKey);
    }

    function test_gatewayMint_validAttestation_wrongSigner(Attestation memory attestation) public {
        attestation.spec.hookData = HOOK_DATA;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        (, uint256 wrongSignerKey) = makeAddrAndKey("wrongSigner");
        vm.expectRevert(Mints.InvalidAttestationSigner.selector);
        _callGatewayMintSignedBy(encodedAttestation, wrongSignerKey);
    }

    function test_gatewayMint_wrongSignatureLength() public {
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 2));
        minter.gatewayMint(new bytes(0), hex"aaaa");
    }

    // ===== Attestation Structural Validation Tests =====

    function test_gatewayMint_revertIfNoAttestationsProvided() public {
        Attestation[] memory attestations = new Attestation[](0);
        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestations = AttestationLib.encodeAttestationSet(attestationSet);

        vm.expectRevert(Mints.MustHaveAtLeastOneAttestation.selector);
        _callGatewayMintSignedBy(encodedAttestations, attestationSignerKey);
    }

    function test_gatewayMint_revertIfInvalidMagic() public {
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(crossChainBaseAttestation);
        // Corrupt magic
        encodedAttestation[0] = hex"00";

        bytes memory tempBytes = new bytes(BYTES4_BYTES);
        for (uint8 i = 0; i < BYTES4_BYTES; i++) {
            tempBytes[i] = encodedAttestation[i];
        }
        bytes4 corruptedMagic = bytes4(tempBytes);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecLib.InvalidTransferPayloadMagic.selector, corruptedMagic));
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    // ===== Attestation Content Validation Tests =====

    function test_gatewayMint_revertIfExpiredAttestation() public {
        crossChainBaseAttestation.maxBlockHeight = block.number - 1;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(crossChainBaseAttestation);
        vm.expectRevert(
            abi.encodeWithSelector(
                Mints.AttestationExpiredAtIndex.selector, 0, crossChainBaseAttestation.maxBlockHeight, block.number
            )
        );
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    function test_gatewayMint_revertIfExpiredAttestationSet() public {
        Attestation memory expiredAttestation = crossChainBaseAttestation; // storage -> memory creates a copy
        expiredAttestation.maxBlockHeight = block.number - 1;

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = crossChainBaseAttestation;
        attestations[1] = expiredAttestation;

        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestations = AttestationLib.encodeAttestationSet(attestationSet);

        vm.expectRevert(
            abi.encodeWithSelector(
                Mints.AttestationExpiredAtIndex.selector, 1, expiredAttestation.maxBlockHeight, block.number
            )
        );
        _callGatewayMintSignedBy(encodedAttestations, attestationSignerKey);
    }

    function test_gatewayMint_revertIfZeroValue() public {
        crossChainBaseAttestation.spec.value = 0;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(crossChainBaseAttestation);
        vm.expectRevert(abi.encodeWithSelector(Mints.AttestationValueMustBePositiveAtIndex.selector, 0));
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    function test_gatewayMint_revertIfZeroValueAttestationSet() public {
        Attestation memory zeroValueAttestation = crossChainBaseAttestation; // storage -> memory creates a copy
        zeroValueAttestation.spec.value = 0;

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = crossChainBaseAttestation;
        attestations[1] = zeroValueAttestation;

        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestations = AttestationLib.encodeAttestationSet(attestationSet);

        vm.expectRevert(abi.encodeWithSelector(Mints.AttestationValueMustBePositiveAtIndex.selector, 1));
        _callGatewayMintSignedBy(encodedAttestations, attestationSignerKey);
    }

    function test_gatewayMint_revertIfDestinationRecipientDenylisted() public {
        vm.startPrank(owner);
        minter.denylist(recipient);
        vm.stopPrank();

        bytes memory encodedAttestation = AttestationLib.encodeAttestation(crossChainBaseAttestation);
        vm.expectRevert(abi.encodeWithSelector(Denylist.AccountDenylisted.selector, recipient));
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    function test_gatewayMint_revertIfDestinationRecipientDenylistedAttestationSet() public {
        Attestation memory denylistedRecipientAttestation = crossChainBaseAttestation; // storage -> memory creates a copy
        address denylistedRecipient = makeAddr("denylistedRecipient");
        denylistedRecipientAttestation.spec.destinationRecipient = AddressLib._addressToBytes32(denylistedRecipient);

        vm.startPrank(owner);
        minter.denylist(denylistedRecipient);
        vm.stopPrank();

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = crossChainBaseAttestation;
        attestations[1] = denylistedRecipientAttestation;

        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestations = AttestationLib.encodeAttestationSet(attestationSet);

        vm.expectRevert(abi.encodeWithSelector(Denylist.AccountDenylisted.selector, denylistedRecipient));
        _callGatewayMintSignedBy(encodedAttestations, attestationSignerKey);
    }

    function test_gatewayMint_revertIfNonZeroAndInvalidDestinationCaller() public {
        address destinationCaller = makeAddr("destinationCallerOtherThanThis");
        crossChainBaseAttestation.spec.destinationCaller = AddressLib._addressToBytes32(destinationCaller);
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(crossChainBaseAttestation);

        vm.expectRevert(
            abi.encodeWithSelector(
                Mints.InvalidAttestationDestinationCallerAtIndex.selector, 0, destinationCaller, address(this)
            )
        );
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    function test_gatewayMint_revertIfNonZeroAndInvalidDestinationCallerAttestationSet() public {
        Attestation memory invalidDestinationCallerAttestation = crossChainBaseAttestation; // storage -> memory creates a copy
        address destinationCaller = makeAddr("destinationCallerOtherThanThis");
        invalidDestinationCallerAttestation.spec.destinationCaller = AddressLib._addressToBytes32(destinationCaller);

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = crossChainBaseAttestation;
        attestations[1] = invalidDestinationCallerAttestation;

        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestations = AttestationLib.encodeAttestationSet(attestationSet);

        vm.expectRevert(
            abi.encodeWithSelector(
                Mints.InvalidAttestationDestinationCallerAtIndex.selector, 1, destinationCaller, address(this)
            )
        );
        _callGatewayMintSignedBy(encodedAttestations, attestationSignerKey);
    }

    function test_gatewayMint_revertIfInvalidDestinationDomainAttestation() public {
        crossChainBaseAttestation.spec.destinationDomain = domain + 1;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(crossChainBaseAttestation);
        vm.expectRevert(
            abi.encodeWithSelector(
                Mints.InvalidAttestationDestinationDomainAtIndex.selector,
                0,
                crossChainBaseAttestation.spec.destinationDomain,
                domain
            )
        );
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    function test_gatewayMint_revertIfInvalidDestinationDomainAttestationSet() public {
        Attestation memory invalidDomainAttestation = crossChainBaseAttestation; // storage -> memory creates a copy
        invalidDomainAttestation.spec.destinationDomain = domain + 1;

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = crossChainBaseAttestation;
        attestations[1] = invalidDomainAttestation;

        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestations = AttestationLib.encodeAttestationSet(attestationSet);

        vm.expectRevert(
            abi.encodeWithSelector(
                Mints.InvalidAttestationDestinationDomainAtIndex.selector,
                1,
                invalidDomainAttestation.spec.destinationDomain,
                domain
            )
        );
        _callGatewayMintSignedBy(encodedAttestations, attestationSignerKey);
    }

    function test_gatewayMint_revertIfInvalidDestinationContract() public {
        address invalidDestinationContract = makeAddr("invalidDestinationContract");
        crossChainBaseAttestation.spec.destinationContract = AddressLib._addressToBytes32(invalidDestinationContract);
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(crossChainBaseAttestation);

        vm.expectRevert(
            abi.encodeWithSelector(
                Mints.InvalidAttestationDestinationContractAtIndex.selector,
                0,
                invalidDestinationContract,
                address(minter)
            )
        );
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    function test_gatewayMint_revertIfInvalidDestinationContractAttestationSet() public {
        Attestation memory invalidContractAttestation = crossChainBaseAttestation; // storage -> memory creates a copy
        address invalidDestinationContract = makeAddr("invalidDestinationContract");
        invalidContractAttestation.spec.destinationContract = AddressLib._addressToBytes32(invalidDestinationContract);

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = crossChainBaseAttestation;
        attestations[1] = invalidContractAttestation;

        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestations = AttestationLib.encodeAttestationSet(attestationSet);

        vm.expectRevert(
            abi.encodeWithSelector(
                Mints.InvalidAttestationDestinationContractAtIndex.selector,
                1,
                invalidDestinationContract,
                address(minter)
            )
        );
        _callGatewayMintSignedBy(encodedAttestations, attestationSignerKey);
    }

    function test_gatewayMint_revertIfUnsupportedDestinationToken() public {
        Attestation memory unsupportedDestinationTokenAttestation = crossChainBaseAttestation;
        address unsupportedToken = makeAddr("unsupportedToken");
        unsupportedDestinationTokenAttestation.spec.destinationToken = AddressLib._addressToBytes32(unsupportedToken);
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(unsupportedDestinationTokenAttestation);

        vm.expectRevert(abi.encodeWithSelector(Mints.UnsupportedTokenAtIndex.selector, 0, unsupportedToken));
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    function test_gatewayMint_revertIfUnsupportedDestinationTokenAttestationSet() public {
        Attestation memory unsupportedDestinationTokenAttestation = crossChainBaseAttestation;
        address unsupportedToken = makeAddr("unsupportedToken");
        unsupportedDestinationTokenAttestation.spec.destinationToken = AddressLib._addressToBytes32(unsupportedToken);

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = crossChainBaseAttestation;
        attestations[1] = unsupportedDestinationTokenAttestation;

        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestations = AttestationLib.encodeAttestationSet(attestationSet);

        vm.expectRevert(abi.encodeWithSelector(Mints.UnsupportedTokenAtIndex.selector, 1, unsupportedToken));
        _callGatewayMintSignedBy(encodedAttestations, attestationSignerKey);
    }

    function test_gatewayMint_revertIfSameChainInvalidSourceContract() public {
        Attestation memory attestation = sameChainBaseAttestation;
        address invalidSourceContract = makeAddr("invalidSourceContract");
        attestation.spec.sourceContract = AddressLib._addressToBytes32(invalidSourceContract); // Set wrong source contract
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);

        vm.expectRevert(
            abi.encodeWithSelector(
                Mints.InvalidAttestationSourceContractAtIndex.selector, 0, invalidSourceContract, address(wallet)
            )
        );
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    function test_gatewayMint_revertIfSameChainInvalidSourceContractAttestationSet() public {
        Attestation memory invalidSourceAttestation = sameChainBaseAttestation;
        address invalidSourceContract = makeAddr("invalidSourceContract");
        invalidSourceAttestation.spec.sourceContract = AddressLib._addressToBytes32(invalidSourceContract); // Set wrong source contract

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = sameChainBaseAttestation;
        attestations[1] = invalidSourceAttestation;

        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestations = AttestationLib.encodeAttestationSet(attestationSet);

        vm.expectRevert(
            abi.encodeWithSelector(
                Mints.InvalidAttestationSourceContractAtIndex.selector, 1, invalidSourceContract, address(wallet)
            )
        );
        _callGatewayMintSignedBy(encodedAttestations, attestationSignerKey);
    }

    function test_gatewayMint_revertIfSameChainInvalidToken() public {
        Attestation memory attestation = sameChainBaseAttestation;
        address differentSourceToken = makeAddr("differentSourceToken");
        attestation.spec.sourceToken = AddressLib._addressToBytes32(differentSourceToken); // Set different source token
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);

        vm.expectRevert(
            abi.encodeWithSelector(
                Mints.InvalidAttestationTokenAtIndex.selector, 0, differentSourceToken, address(usdc)
            )
        );
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    function test_gatewayMint_revertIfSameChainInvalidTokenAttestationSet() public {
        Attestation memory invalidTokenAttestation = sameChainBaseAttestation;
        address differentSourceToken = makeAddr("differentSourceToken");
        invalidTokenAttestation.spec.sourceToken = AddressLib._addressToBytes32(differentSourceToken); // Set different source token

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = sameChainBaseAttestation;
        attestations[1] = invalidTokenAttestation;

        AttestationSet memory attestationSet = AttestationSet({attestations: attestations});
        bytes memory encodedAttestations = AttestationLib.encodeAttestationSet(attestationSet);

        vm.expectRevert(
            abi.encodeWithSelector(
                Mints.InvalidAttestationTokenAtIndex.selector, 1, differentSourceToken, address(usdc)
            )
        );
        _callGatewayMintSignedBy(encodedAttestations, attestationSignerKey);
    }

    // ===== Replay Protection Tests =====

    function test_gatewayMint_revertIfTransferSpecHashAlreadyUsed() public {
        bytes32 specHash = keccak256(TransferSpecLib.encodeTransferSpec(crossChainBaseAttestation.spec));
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(crossChainBaseAttestation);
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
        vm.expectRevert(abi.encodeWithSelector(TransferSpecHashes.TransferSpecHashUsed.selector, specHash));
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    // ===== Cross-chain Tests =====

    function test_gatewayMint_crossChain_successValidAttestationAndMintAuthority() public {
        Attestation memory attestation = crossChainBaseAttestation;
        attestation.spec.value = mintValue;

        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        bytes32 specHash = keccak256(TransferSpecLib.encodeTransferSpec(attestation.spec));

        assertEq(usdc.balanceOf(recipient), 0);

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient,
            specHash,
            attestation.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            mintValue
        );
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);

        assertEq(usdc.balanceOf(recipient), mintValue);
    }

    function test_gatewayMint_crossChain_customDestinationCaller_successValidAttestationAndMintAuthority() public {
        Attestation memory attestation = crossChainBaseAttestation;
        address destinationCaller = makeAddr("destinationCaller");
        attestation.spec.destinationCaller = AddressLib._addressToBytes32(destinationCaller);
        attestation.spec.value = mintValue;

        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        bytes32 specHash = keccak256(TransferSpecLib.encodeTransferSpec(attestation.spec));

        assertEq(usdc.balanceOf(recipient), 0);

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient,
            specHash,
            attestation.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            mintValue
        );

        vm.startPrank(destinationCaller);
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
        vm.stopPrank();

        assertEq(usdc.balanceOf(recipient), mintValue);
    }

    function test_gatewayMint_crossChain_successValidAttestationAndNoMintAuthority() public {
        Attestation memory attestation = crossChainBaseAttestation;
        attestation.spec.value = mintValue;
        attestation.spec.destinationToken = AddressLib._addressToBytes32(address(mockToken));

        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        bytes32 specHash = keccak256(TransferSpecLib.encodeTransferSpec(attestation.spec));

        assertEq(mockToken.balanceOf(recipient), 0);

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(mockToken),
            recipient,
            specHash,
            attestation.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            mintValue
        );
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);

        assertEq(mockToken.balanceOf(recipient), mintValue);
    }

    function test_gatewayMint_crossChain_sameRecipient_sameToken_successValidAttestationSetAndMintAuthority() public {
        Attestation memory attestation1 = crossChainBaseAttestation;
        attestation1.spec.value = mintValue;
        Attestation memory attestation2 = crossChainBaseAttestation;
        attestation2.spec.value = mintValue + 1;

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = attestation1;
        attestations[1] = attestation2;
        bytes memory encodedAttestation =
            AttestationLib.encodeAttestationSet(AttestationSet({attestations: attestations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(attestation1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(attestation2.spec));

        assertEq(usdc.balanceOf(recipient), 0);

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient,
            specHash1,
            attestation1.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation1.spec.value
        );
        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient,
            specHash2,
            attestation2.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation2.spec.value
        );
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);

        assertEq(usdc.balanceOf(recipient), attestation1.spec.value + attestation2.spec.value);
    }

    function test_gatewayMint_crossChain_sameRecipient_differentTokens_successValidAttestationSet() public {
        Attestation memory attestation1 = crossChainBaseAttestation;
        attestation1.spec.value = mintValue;
        attestation1.spec.destinationToken = AddressLib._addressToBytes32(address(usdc));
        attestation1.spec.destinationRecipient = AddressLib._addressToBytes32(recipient);

        Attestation memory attestation2 = crossChainBaseAttestation;
        attestation2.spec.value = mintValue / 2;
        attestation2.spec.destinationToken = AddressLib._addressToBytes32(address(mockToken));
        attestation2.spec.destinationRecipient = AddressLib._addressToBytes32(recipient);

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = attestation1;
        attestations[1] = attestation2;
        bytes memory encodedAttestation =
            AttestationLib.encodeAttestationSet(AttestationSet({attestations: attestations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(attestation1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(attestation2.spec));

        assertEq(usdc.balanceOf(recipient), 0, "Initial USDC balance recipient");
        assertEq(mockToken.balanceOf(recipient), 0, "Initial MockToken balance recipient");

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient,
            specHash1,
            attestation1.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation1.spec.value
        );

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(mockToken),
            recipient,
            specHash2,
            attestation2.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation2.spec.value
        );

        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);

        assertEq(usdc.balanceOf(recipient), attestation1.spec.value, "Final USDC balance recipient");
        assertEq(mockToken.balanceOf(recipient), attestation2.spec.value, "Final MockToken balance recipient");
    }

    function test_gatewayMint_crossChain_differentRecipients_sameToken_successValidAttestationSetAndMintAuthority()
        public
    {
        Attestation memory attestation1 = crossChainBaseAttestation;
        attestation1.spec.value = mintValue;
        address recipient1 = makeAddr("recipient1");
        attestation1.spec.destinationRecipient = AddressLib._addressToBytes32(recipient1);
        Attestation memory attestation2 = crossChainBaseAttestation;
        attestation2.spec.value = mintValue / 2;
        address recipient2 = makeAddr("recipient2");
        attestation2.spec.destinationRecipient = AddressLib._addressToBytes32(recipient2);

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = attestation1;
        attestations[1] = attestation2;
        bytes memory encodedAttestation =
            AttestationLib.encodeAttestationSet(AttestationSet({attestations: attestations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(attestation1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(attestation2.spec));

        assertEq(usdc.balanceOf(recipient1), 0);
        assertEq(usdc.balanceOf(recipient2), 0);

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient1,
            specHash1,
            attestation1.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation1.spec.value
        );
        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient2,
            specHash2,
            attestation2.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation2.spec.value
        );
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);

        assertEq(usdc.balanceOf(recipient1), attestation1.spec.value);
        assertEq(usdc.balanceOf(recipient2), attestation2.spec.value);
    }

    function test_gatewayMint_crossChain_differentRecipients_differentTokens_successValidAttestationSetAndMintAuthority(
    ) public {
        Attestation memory attestation1 = crossChainBaseAttestation;
        attestation1.spec.value = mintValue;
        address recipient1 = makeAddr("recipient1");
        attestation1.spec.destinationRecipient = AddressLib._addressToBytes32(recipient1);

        Attestation memory attestation2 = crossChainBaseAttestation;
        attestation2.spec.value = mintValue / 2;
        address recipient2 = makeAddr("recipient2");
        attestation2.spec.destinationRecipient = AddressLib._addressToBytes32(recipient2);
        attestation2.spec.destinationToken = AddressLib._addressToBytes32(address(mockToken));

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = attestation1;
        attestations[1] = attestation2;
        bytes memory encodedAttestation =
            AttestationLib.encodeAttestationSet(AttestationSet({attestations: attestations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(attestation1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(attestation2.spec));

        assertEq(usdc.balanceOf(recipient1), 0, "Initial USDC balance recipient1");
        assertEq(mockToken.balanceOf(recipient2), 0, "Initial MockToken balance recipient2");

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient1,
            specHash1,
            attestation1.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation1.spec.value
        );

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(mockToken),
            recipient2,
            specHash2,
            attestation2.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation2.spec.value
        );

        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);

        assertEq(usdc.balanceOf(recipient1), attestation1.spec.value, "Final USDC balance recipient1");
        assertEq(mockToken.balanceOf(recipient2), attestation2.spec.value, "Final MockToken balance recipient2");
    }

    function test_gatewayMint_crossChain_revertIfMintAuthorityMisconfigured() public {
        vm.startPrank(owner);
        minter.updateMintAuthority(address(usdc), makeAddr("invalidMintAuthority"));
        vm.stopPrank();

        Attestation memory attestation = crossChainBaseAttestation;
        attestation.spec.value = mintValue;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);

        // Expect a generic revert because the (mis)configured mint authority is an EOA
        vm.expectRevert();
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    function test_gatewayMint_crossChain_revertIfNotConfiguredAsMinter() public {
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

        Attestation memory attestation = crossChainBaseAttestation;
        attestation.spec.value = mintValue;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);

        vm.expectRevert("FiatToken: caller is not a minter");
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);
    }

    // ===== Same-chain Tests =====

    function test_gatewayMint_sameChain_successValidAttestation() public {
        Attestation memory attestation = sameChainBaseAttestation;
        attestation.spec.value = mintValue;
        bytes memory encodedAttestation = AttestationLib.encodeAttestation(attestation);
        bytes32 specHash = keccak256(TransferSpecLib.encodeTransferSpec(attestation.spec));
        assertEq(usdc.balanceOf(recipient), 0);

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient,
            specHash,
            attestation.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation.spec.value
        );
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);

        assertEq(usdc.balanceOf(recipient), mintValue);
    }

    function test_gatewayMint_sameChain_sameRecipient_sameToken_successValidAttestationSet() public {
        Attestation memory attestation1 = sameChainBaseAttestation;
        attestation1.spec.value = mintValue;
        Attestation memory attestation2 = sameChainBaseAttestation;
        attestation2.spec.value = mintValue + 1;

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = attestation1;
        attestations[1] = attestation2;
        bytes memory encodedAttestation =
            AttestationLib.encodeAttestationSet(AttestationSet({attestations: attestations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(attestation1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(attestation2.spec));

        assertEq(usdc.balanceOf(recipient), 0);

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient,
            specHash1,
            attestation1.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation1.spec.value
        );
        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient,
            specHash2,
            attestation2.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation2.spec.value
        );
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);

        assertEq(usdc.balanceOf(recipient), attestation1.spec.value + attestation2.spec.value);
    }

    function test_gatewayMint_sameChain_sameRecipient_differentTokens_successValidAttestationSet() public {
        Attestation memory attestation1 = sameChainBaseAttestation;
        attestation1.spec.value = mintValue;

        Attestation memory attestation2 = sameChainBaseAttestation;
        attestation2.spec.value = mintValue / 2;
        attestation2.spec.sourceToken = AddressLib._addressToBytes32(address(mockToken));
        attestation2.spec.destinationToken = AddressLib._addressToBytes32(address(mockToken));
        attestation2.spec.destinationRecipient = AddressLib._addressToBytes32(recipient);

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = attestation1;
        attestations[1] = attestation2;
        bytes memory encodedAttestation =
            AttestationLib.encodeAttestationSet(AttestationSet({attestations: attestations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(attestation1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(attestation2.spec));

        assertEq(usdc.balanceOf(recipient), 0, "Initial USDC balance recipient");
        assertEq(mockToken.balanceOf(recipient), 0, "Initial MockToken balance recipient");

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient,
            specHash1,
            attestation1.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation1.spec.value
        );

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(mockToken),
            recipient,
            specHash2,
            attestation2.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation2.spec.value
        );

        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);

        assertEq(usdc.balanceOf(recipient), attestation1.spec.value);
        assertEq(mockToken.balanceOf(recipient), attestation2.spec.value);
    }

    function test_gatewayMint_sameChain_differentRecipients_sameToken_successValidAttestationSet() public {
        Attestation memory attestation1 = sameChainBaseAttestation;
        attestation1.spec.value = mintValue;
        address recipient1 = makeAddr("recipient1");
        attestation1.spec.destinationRecipient = AddressLib._addressToBytes32(recipient1);

        Attestation memory attestation2 = sameChainBaseAttestation;
        attestation2.spec.value = mintValue / 2;
        address recipient2 = makeAddr("recipient2");
        attestation2.spec.destinationRecipient = AddressLib._addressToBytes32(recipient2);

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = attestation1;
        attestations[1] = attestation2;
        bytes memory encodedAttestation =
            AttestationLib.encodeAttestationSet(AttestationSet({attestations: attestations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(attestation1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(attestation2.spec));

        assertEq(usdc.balanceOf(recipient1), 0, "Initial USDC balance recipient1");
        assertEq(usdc.balanceOf(recipient2), 0, "Initial USDC balance recipient2");

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient1,
            specHash1,
            attestation1.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation1.spec.value
        );
        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient2,
            specHash2,
            attestation2.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation2.spec.value
        );
        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);

        assertEq(usdc.balanceOf(recipient1), attestation1.spec.value);
        assertEq(usdc.balanceOf(recipient2), attestation2.spec.value);
    }

    function test_gatewayMint_sameChain_differentRecipients_differentTokens_successValidAttestationSet() public {
        Attestation memory attestation1 = sameChainBaseAttestation;
        attestation1.spec.value = mintValue;
        address recipient1 = makeAddr("recipient1");
        attestation1.spec.destinationRecipient = AddressLib._addressToBytes32(recipient1);

        Attestation memory attestation2 = sameChainBaseAttestation;
        attestation2.spec.value = mintValue / 2;
        address recipient2 = makeAddr("recipient2");
        attestation2.spec.destinationRecipient = AddressLib._addressToBytes32(recipient2);
        attestation2.spec.sourceToken = AddressLib._addressToBytes32(address(mockToken));
        attestation2.spec.destinationToken = AddressLib._addressToBytes32(address(mockToken));

        Attestation[] memory attestations = new Attestation[](2);
        attestations[0] = attestation1;
        attestations[1] = attestation2;
        bytes memory encodedAttestation =
            AttestationLib.encodeAttestationSet(AttestationSet({attestations: attestations}));
        bytes32 specHash1 = keccak256(TransferSpecLib.encodeTransferSpec(attestation1.spec));
        bytes32 specHash2 = keccak256(TransferSpecLib.encodeTransferSpec(attestation2.spec));

        assertEq(usdc.balanceOf(recipient1), 0, "Initial USDC balance recipient1");
        assertEq(mockToken.balanceOf(recipient2), 0, "Initial MockToken balance recipient2");

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(usdc),
            recipient1,
            specHash1,
            attestation1.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation1.spec.value
        );

        vm.expectEmit(true, true, true, true);
        emit Mints.AttestationUsed(
            address(mockToken),
            recipient2,
            specHash2,
            attestation2.spec.sourceDomain,
            AddressLib._addressToBytes32(depositor),
            AddressLib._addressToBytes32(sourceSigner),
            attestation2.spec.value
        );

        _callGatewayMintSignedBy(encodedAttestation, attestationSignerKey);

        assertEq(usdc.balanceOf(recipient1), attestation1.spec.value);
        assertEq(mockToken.balanceOf(recipient2), attestation2.spec.value);
    }
}
