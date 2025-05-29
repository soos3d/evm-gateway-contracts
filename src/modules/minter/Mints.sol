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

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {GatewayCommon} from "src/GatewayCommon.sol";
import {IMintableToken} from "src/interfaces/IMintableToken.sol";
import {AddressLib} from "src/lib/AddressLib.sol";
import {AttestationLib} from "src/lib/AttestationLib.sol";
import {Cursor} from "src/lib/Cursor.sol";
import {TransferSpecLib} from "src/lib/TransferSpecLib.sol";

/// @title Mints
///
/// @notice Manages mints for the `GatewayMinter` contract
contract Mints is GatewayCommon {
    using TransferSpecLib for bytes29;
    using AttestationLib for bytes29;
    using AttestationLib for Cursor;
    using MessageHashUtils for bytes32;

    /// Emitted when an attestation is used
    ///
    /// @param token              The token that was minted
    /// @param recipient          The recipient of the funds
    /// @param transferSpecHash   The `keccak256` hash of the `TransferSpec`, shared with the burn intent
    /// @param sourceDomain       The domain the funds came from
    /// @param sourceDepositor    The depositor on the source domain
    /// @param sourceSigner       The signer that authorized the transfer
    /// @param value              The amount that was minted
    event AttestationUsed(
        address indexed token,
        address indexed recipient,
        bytes32 indexed transferSpecHash,
        uint32 sourceDomain,
        bytes32 sourceDepositor,
        bytes32 sourceSigner,
        uint256 value
    );

    /// Emitted when an attestation signer is added
    ///
    /// @param signer   The attestation signer address that was added
    event AttestationSignerAdded(address indexed signer);

    /// Emitted when an attestation signer is removed
    ///
    /// @param signer   The attestation signer address that was removed
    event AttestationSignerRemoved(address indexed signer);

    /// Emitted when the mint authority is updated for a token
    ///
    /// @param token              The token whose mint authority was updated
    /// @param oldMintAuthority   The previous mint authority address
    /// @param newMintAuthority   The new mint authority address
    event MintAuthorityChanged(
        address indexed token, address indexed oldMintAuthority, address indexed newMintAuthority
    );

    /// Thrown when an attestation set is empty
    error MustHaveAtLeastOneAttestation();

    /// Thrown when an attestation was not signed by a valid attestation signer
    error InvalidAttestationSigner();

    /// Thrown when an attestation is expired
    ///
    /// @param index            The index of the attestation with the issue
    /// @param maxBlockHeight   The attestation's expiration block height
    /// @param currentBlock     The current block height
    error AttestationExpiredAtIndex(uint32 index, uint256 maxBlockHeight, uint256 currentBlock);

    /// Thrown when an attestation's value is zero
    ///
    /// @param index   The index of the attestation with the issue
    error AttestationValueMustBePositiveAtIndex(uint32 index);

    /// Thrown when an attestation has a non-zero destination caller but was used by a different caller
    ///
    /// @param index               The index of the attestation with the issue
    /// @param attestationCaller   The destination caller from the attestation
    /// @param actualCaller        The caller that used the attestation
    error InvalidAttestationDestinationCallerAtIndex(uint32 index, address attestationCaller, address actualCaller);

    /// Thrown when an attestation has a destination domain that does not match the one for this contract
    ///
    /// @param index               The index of the attestation with the issue
    /// @param attestationDomain   The destination domain from the attestation
    /// @param expectedDomain      The domain of this contract
    error InvalidAttestationDestinationDomainAtIndex(uint32 index, uint32 attestationDomain, uint32 expectedDomain);

    /// Thrown when an attestation has the wrong destination contract
    ///
    /// @param index                 The index of the attestation with the issue
    /// @param attestationContract   The destination contract from the attestation
    /// @param expectedContract      The address of this contract
    error InvalidAttestationDestinationContractAtIndex(
        uint32 index, address attestationContract, address expectedContract
    );

    /// Thrown when the destination token in an attestation is not supported
    ///
    /// @param index              The index of the attestation with the issue
    /// @param destinationToken   The destination token from the attestation
    error UnsupportedTokenAtIndex(uint32 index, address destinationToken);

    /// Thrown when an attestation is for the same domain as the source but has a source contract that does not
    /// match the expected counterpart wallet contract address
    ///
    /// @param index                 The index of the attestation with the issue
    /// @param attestationContract   The source contract from the attestation
    /// @param expectedContract      The address of the wallet contract on the same domain
    error InvalidAttestationSourceContractAtIndex(uint32 index, address attestationContract, address expectedContract);

    /// Thrown when an attestation is for the same domain as the source but has a source token that does not
    /// match the destination token
    ///
    /// @param index              The index of the attestation with the issue
    /// @param sourceToken        The source token
    /// @param destinationToken   The destination token
    error InvalidAttestationTokenAtIndex(uint32 index, address sourceToken, address destinationToken);

    /// Initializes an attestation signer and any initial token mint authorities
    ///
    /// @param attestationSigner_      The address to initialize as a valid attestation signer
    /// @param tokens_                 The list of tokens to support initially
    /// @param tokenMintAuthorities_   The list of initial token mint authorities (use the zero address for none)
    function __Mints_init(
        address attestationSigner_,
        address[] calldata tokens_,
        address[] calldata tokenMintAuthorities_
    ) internal onlyInitializing {
        addAttestationSigner(attestationSigner_);

        for (uint256 i = 0; i < tokenMintAuthorities_.length; i++) {
            address mintAuthority = tokenMintAuthorities_[i];

            if (mintAuthority != address(0)) {
                updateMintAuthority(tokens_[i], tokenMintAuthorities_[i]);
            }
        }
    }

    /// Mint funds via a signed attestation. Accepts either a single encoded `Attestation` or several in
    /// an encoded `AttestationSet`. Emits an event containing the `keccak256` hash of the encoded
    /// `TransferSpec` (which is the same for the corresponding burn that will happen on the source domain), to be
    /// used as a cross-chain identifier and for replay protection.
    ///
    /// @dev See `Attestations.sol` for encoding details
    ///
    /// @param attestationPayload   The byte-encoded attestation(s)
    /// @param signature            The signature from a valid attestation signer on `attestationPayload`
    function gatewayMint(bytes memory attestationPayload, bytes memory signature)
        external
        whenNotPaused
        notDenylisted(msg.sender)
    {
        // Verify that the payload was signed by the expected signer
        _verifyAttestationSignature(attestationPayload, signature);

        // Validate the attestation(s) and get an iteration cursor
        Cursor memory cursor = AttestationLib.cursor(attestationPayload);

        // Ensure there is at least one attestation
        if (cursor.numElements == 0) {
            revert MustHaveAtLeastOneAttestation();
        }

        // Iterate over the attestations, validating and processing each one
        bytes29 attestation;
        while (!cursor.done) {
            attestation = cursor.next();

            // Ensure the attestation is not expired
            uint32 index = cursor.index - 1;
            _validateAttestationNotExpired(attestation, index);

            // Extract and validate the `TransferSpec`
            bytes29 spec = attestation.getTransferSpec();
            _validateAttestationTransferSpec(spec, index);

            // Mint funds according to the spec
            _mint(spec);
        }
    }

    /// Whether or not an address is a valid attestation signer that may sign attestations to mint funds
    ///
    /// @param signer   The address to check
    /// @return         `true` if the address is a valid attestation signer, `false` otherwise
    function isAttestationSigner(address signer) public view returns (bool) {
        return MintsStorage.get().attestationSigners[signer];
    }

    /// The mint authority for a token
    ///
    /// @param token   The token to check
    /// @return        The token's mint authority
    function tokenMintAuthority(address token) public view returns (address) {
        return MintsStorage.get().tokenMintAuthorities[token];
    }

    /// Updates the mint authority for a token
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param token              The token address to update the mint authority for
    /// @param newMintAuthority   The address to set as the new mint authority
    function updateMintAuthority(address token, address newMintAuthority) public onlyOwner tokenSupported(token) {
        AddressLib._checkNotZeroAddress(newMintAuthority);

        MintsStorage.Data storage $ = MintsStorage.get();
        address oldMintAuthority = $.tokenMintAuthorities[token];
        $.tokenMintAuthorities[token] = newMintAuthority;
        emit MintAuthorityChanged(token, oldMintAuthority, newMintAuthority);
    }

    /// Adds an address that may sign attestations
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param signer   The attestation signer address to add
    function addAttestationSigner(address signer) public onlyOwner {
        AddressLib._checkNotZeroAddress(signer);

        MintsStorage.get().attestationSigners[signer] = true;
        emit AttestationSignerAdded(signer);
    }

    /// Removes an address from the set of valid attestation signers
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param signer   The attestation signer address to remove
    function removeAttestationSigner(address signer) public onlyOwner {
        AddressLib._checkNotZeroAddress(signer);

        MintsStorage.get().attestationSigners[signer] = false;
        emit AttestationSignerRemoved(signer);
    }

    /// Verifies the signature for a (set of) attestation(s)
    ///
    /// @dev Recovers the signer from the signature and ensures it is a valid attestation signer
    ///
    /// @param attestation   The byte-encoded attestation(s)
    /// @param signature     The signature on the `attestation` from a valid attestation signer
    function _verifyAttestationSignature(bytes memory attestation, bytes memory signature) internal view {
        address recoveredSigner = ECDSA.recover(keccak256(attestation).toEthSignedMessageHash(), signature);
        if (!isAttestationSigner(recoveredSigner)) {
            revert InvalidAttestationSigner();
        }
    }

    /// Validates that an attestation is not expired
    ///
    /// @dev Reverts if the attestation is expired
    ///
    /// @param attestation   A `TypedMemView` reference to the byte-encoded attestation
    /// @param index         The index of the attesation within the batch (used for error reporting)
    function _validateAttestationNotExpired(bytes29 attestation, uint32 index) internal view {
        // Ensure the attestation is not expired
        uint256 maxBlockHeight = attestation.getMaxBlockHeight();
        if (maxBlockHeight < block.number) {
            revert AttestationExpiredAtIndex(index, maxBlockHeight, block.number);
        }
    }

    /// Validates a single attestation's transfer spec
    ///
    /// @dev Checks value, recipient denylist status, destination caller, destination domain, destination
    ///      contract, and (when the domains match) source contract and token consistency
    ///
    /// @param spec    A `TypedMemView` reference to the transfer spec portion of the attestation
    /// @param index   The index of the attestation within the batch (used for error reporting)
    function _validateAttestationTransferSpec(bytes29 spec, uint32 index) internal view {
        // Ensure the value is nonzero
        uint256 value = spec.getValue();
        if (value == 0) {
            revert AttestationValueMustBePositiveAtIndex(index);
        }

        // Ensure the intended recipient is not denylisted
        _ensureNotDenylisted(AddressLib._bytes32ToAddress(spec.getDestinationRecipient()));

        // Ensure the caller is the specified destination caller (if any)
        address destinationCaller = AddressLib._bytes32ToAddress(spec.getDestinationCaller());
        if (destinationCaller != address(0) && destinationCaller != msg.sender) {
            revert InvalidAttestationDestinationCallerAtIndex(index, destinationCaller, msg.sender);
        }

        // Ensure the attestation is for the current domain
        uint32 destinationDomain = spec.getDestinationDomain();
        if (!_isCurrentDomain(destinationDomain)) {
            revert InvalidAttestationDestinationDomainAtIndex(index, destinationDomain, domain());
        }

        // Ensure the attestation is for this minter contract
        address destinationContract = AddressLib._bytes32ToAddress(spec.getDestinationContract());
        if (destinationContract != address(this)) {
            revert InvalidAttestationDestinationContractAtIndex(index, destinationContract, address(this));
        }

        // Ensure the destination token is supported
        address destinationToken = AddressLib._bytes32ToAddress(spec.getDestinationToken());
        if (!isTokenSupported(destinationToken)) {
            revert UnsupportedTokenAtIndex(index, destinationToken);
        }

        // If the source and destinations match, perform additional validations
        uint32 sourceDomain = spec.getSourceDomain();
        if (sourceDomain == destinationDomain) {
            // Ensure the source contract is the wallet contract on the same domain
            address sourceContract = AddressLib._bytes32ToAddress(spec.getSourceContract());
            address walletAddr = _counterpart();
            if (sourceContract != walletAddr) {
                revert InvalidAttestationSourceContractAtIndex(index, sourceContract, walletAddr);
            }

            // Ensure the source and destination tokens are the same
            address sourceToken = AddressLib._bytes32ToAddress(spec.getSourceToken());
            if (sourceToken != destinationToken) {
                revert InvalidAttestationTokenAtIndex(index, sourceToken, destinationToken);
            }
        }
    }

    /// Executes a mint operation based on the provided `TransferSpec`. The function mints tokens through
    /// the designated mint authority and records the transfer spec hash to prevent replay attacks
    ///
    /// @param spec   A `TypedMemView` reference to the `TransferSpec` from the attestation
    function _mint(bytes29 spec) internal {
        // Check for replay and mark this transfer spec hash as used
        bytes32 specHash = spec.getHash();
        _checkAndMarkTransferSpecHash(specHash);

        // Extract the relevant fields from the `TransferSpec`
        address recipient = AddressLib._bytes32ToAddress(spec.getDestinationRecipient());
        uint256 value = spec.getValue();
        address token = AddressLib._bytes32ToAddress(spec.getDestinationToken());
        uint32 sourceDomain = spec.getSourceDomain();
        bytes32 depositorBytes = spec.getSourceDepositor();
        bytes32 signerBytes = spec.getSourceSigner();

        // Mint to the recipient using the appropriate mint authority
        address mintAuthority = tokenMintAuthority(token);
        address minter = (mintAuthority == address(0)) ? token : mintAuthority;
        IMintableToken(minter).mint(recipient, value);

        // Emit an event with the attestation details
        emit AttestationUsed(token, recipient, specHash, sourceDomain, depositorBytes, signerBytes, value);
    }
}

/// @title MintsStorage
///
/// @notice Implements the EIP-7201 storage pattern for the `Mints` module
library MintsStorage {
    /// @custom:storage-location erc7201:circle.gateway.Mints
    struct Data {
        /// The addresses that may sign attestations to mint funds
        mapping(address signer => bool valid) attestationSigners;
        /// Maps token addresses to their corresponding minter contract addresses. Absence of an entry means the token
        /// itself should be used as the minter. This contract must have permission to mint the associated token via
        /// the minter contract.
        mapping(address token => address tokenMintAuthority) tokenMintAuthorities;
    }

    /// `keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Mints"))) - 1)) & ~bytes32(uint256(0xff))`
    bytes32 public constant SLOT = 0xa13f18ce64168e6d2f5aa74009cc3360c0bed33f0845237965d1e1378d32aa00;

    /// EIP-7201 getter for the storage slot
    ///
    /// @return $   The storage struct for the `Mints` module
    function get() internal pure returns (Data storage $) {
        assembly ("memory-safe") {
            $.slot := SLOT
        }
    }
}
