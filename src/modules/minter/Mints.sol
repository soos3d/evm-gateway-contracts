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

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {GatewayCommon} from "src/GatewayCommon.sol";
import {GatewayWallet} from "src/GatewayWallet.sol";
import {IMintToken} from "src/interfaces/IMintToken.sol";
import {AuthorizationCursor} from "src/lib/authorizations/AuthorizationCursor.sol";
import {MintAuthorizationLib} from "src/lib/authorizations/MintAuthorizationLib.sol";
import {TransferSpecLib} from "src/lib/authorizations/TransferSpecLib.sol";
import {AddressLib} from "src/lib/util/AddressLib.sol";

/// @title Mints
///
/// @notice Manages mints for the GatewayMinter contract
contract Mints is GatewayCommon {
    using TransferSpecLib for bytes29;
    using MintAuthorizationLib for bytes29;
    using MintAuthorizationLib for AuthorizationCursor;
    using MessageHashUtils for bytes32;

    /// Emitted when a mint authorization is used
    ///
    /// @param token              The token that was minted or transferred
    /// @param recipient          The recipient of the funds
    /// @param transferSpecHash   The `keccak256` hash of the `TransferSpec`, shared with the burn authorization
    /// @param sourceDomain       The domain the funds came from
    /// @param sourceDepositor    The depositor on the source domain
    /// @param sourceSigner       The signer that authorized the transfer
    /// @param value              The amount that was minted or transferred
    event MintAuthorizationUsed(
        address indexed token,
        address indexed recipient,
        bytes32 indexed transferSpecHash,
        uint32 sourceDomain,
        bytes32 sourceDepositor,
        bytes32 sourceSigner,
        uint256 value
    );

    /// Emitted when the mint authority is updated for a token
    ///
    /// @param token              The token whose mint authority was updated
    /// @param oldMintAuthority   The previous mint authority address
    /// @param newMintAuthority   The new mint authority address
    event MintAuthorityUpdated(address token, address oldMintAuthority, address newMintAuthority);

    /// Emitted when the `mintAuthorizationSigner` role is updated
    ///
    /// @param oldMintAuthorizationSigner   The previous mint authorization signer address
    /// @param newMintAuthorizationSigner   The new mint authorization signer address
    event MintAuthorizationSignerUpdated(address oldMintAuthorizationSigner, address newMintAuthorizationSigner);

    /// Thrown when a mint authorization set is empty
    error MustHaveAtLeastOneMintAuthorization();

    /// Thrown when a mint authorization was not signed by the right address
    error InvalidMintAuthorizationSigner();

    /// Thrown when a mint authorization is expired
    ///
    /// @param index            The index of the mint authorization with the issue
    /// @param maxBlockHeight   The mint authorization's expiration block height
    /// @param currentBlock     The current block height
    error AuthorizationExpiredAtIndex(uint32 index, uint256 maxBlockHeight, uint256 currentBlock);

    /// Thrown when a mint authorization's value is zero
    ///
    /// @param index   The index of the mint authorization with the issue
    error AuthorizationValueMustBePositiveAtIndex(uint32 index);

    /// Thrown when a mint authorization has a non-zero destination caller but was used by a different caller
    ///
    /// @param index          The index of the mint authorization with the issue
    /// @param authCaller     The destination caller from the mint authorization
    /// @param actualCaller   The caller that used the mint authorization
    error InvalidAuthorizationDestinationCallerAtIndex(uint32 index, address authCaller, address actualCaller);

    /// Thrown when a mint authorization has a destination domain that does not match the one for this contract
    ///
    /// @param index            The index of the mint authorization with the issue
    /// @param authDomain       The destination domain from the mint authorization
    /// @param expectedDomain   The domain of this contract
    error InvalidAuthorizationDestinationDomainAtIndex(uint32 index, uint32 authDomain, uint32 expectedDomain);

    /// Thrown when a mint authorization has the wrong destination contract
    ///
    /// @param index              The index of the mint authorization with the issue
    /// @param authContract       The destination contract from the mint authorization
    /// @param expectedContract   The address of this contract
    error InvalidAuthorizationDestinationContractAtIndex(uint32 index, address authContract, address expectedContract);

    /// Thrown then the destination token in a mint authorization is not supported
    ///
    /// @param index              The index of the mint authorization with the issue
    /// @param destinationToken   The destination token from the mint authorization
    error UnsupportedTokenAtIndex(uint32 index, address destinationToken);

    /// Thrown when a mint authorization is for the same domain as the source but has a source contract that does not
    /// match the address of the wallet contract on the same domain
    ///
    /// @param index              The index of the mint authorization with the issue
    /// @param authContract       The source contract from the mint authorization
    /// @param expectedContract   The address of the wallet contract on the same domain
    error InvalidAuthorizationSourceContractAtIndex(uint32 index, address authContract, address expectedContract);

    /// Thrown when a mint authorization is for the same domain as the source but has a source token that does not
    /// match the destination token
    ///
    /// @param index              The index of the mint authorization with the issue
    /// @param sourceToken        The source token
    /// @param destinationToken   The destination token
    error InvalidAuthorizationTokenAtIndex(uint32 index, address sourceToken, address destinationToken);

    /// Mint funds (or transfer them from the wallet contract if on the same domain) via a signed mint authorization.
    /// Accepts either a single encoded `MintAuthorization` or several in an encoded `MintAuthorizationSet`. Emits an
    /// event containing the `keccak256` hash of the encoded `TransferSpec` (which is the same for the corresponding
    /// burn that will happen on the source domain), to be used as a cross-chain identifier and for replay protection.
    ///
    /// @dev See `MintAuthorizations.sol` for encoding details
    ///
    /// @param authorization   The byte-encoded mint authorization(s)
    /// @param signature       The signature of the `mintAuthorizationSigner` on the `authorization`
    function gatewayMint(bytes memory authorization, bytes memory signature)
        external
        whenNotPaused
        notDenylisted(msg.sender)
    {
        // Verify that the payload was signed by the expected signer
        _verifyMintAuthorizationSignature(authorization, signature);

        // Validate the mint authorization(s) and get an iteration cursor
        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(authorization);

        // Ensure there is at least one mint authorization
        if (cursor.numAuths == 0) {
            revert MustHaveAtLeastOneMintAuthorization();
        }

        // Iterate over the mint authorizations, validating and processing each one
        bytes29 auth;
        while (!cursor.done) {
            auth = cursor.next();
            _validateMintAuthorization(auth, cursor.index - 1);
            _mintOrTransfer(auth.getTransferSpec());
        }
    }

    /// The mint authorization signer that is recognized by the contract
    ///
    /// @return   The mint authorization signer address
    function mintAuthorizationSigner() public view returns (address) {
        return MintsStorage.get().mintAuthorizationSigner;
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
    function updateMintAuthority(address token, address newMintAuthority) external onlyOwner tokenSupported(token) {
        AddressLib._checkNotZeroAddress(newMintAuthority);

        MintsStorage.Data storage $ = MintsStorage.get();
        address oldMintAuthority = $.tokenMintAuthorities[token];
        $.tokenMintAuthorities[token] = newMintAuthority;
        emit MintAuthorityUpdated(token, oldMintAuthority, newMintAuthority);
    }

    /// Sets the address that may sign mint authorizations
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newMintAuthorizationSigner   The new mint authorization signer address
    function updateMintAuthorizationSigner(address newMintAuthorizationSigner) external onlyOwner {
        AddressLib._checkNotZeroAddress(newMintAuthorizationSigner);

        MintsStorage.Data storage $ = MintsStorage.get();
        address oldMintAuthorizationSigner = $.mintAuthorizationSigner;
        $.mintAuthorizationSigner = newMintAuthorizationSigner;
        emit MintAuthorizationSignerUpdated(oldMintAuthorizationSigner, newMintAuthorizationSigner);
    }

    /// Verifies the signature for a (set of) mint authorization(s)
    ///
    /// @dev Recovers the signer from the signature and compares it to the `mintAuthorizationSigner`
    ///
    /// @param authorization   The byte-encoded mint authorization(s)
    /// @param signature       The signature on the `authorization` to verify
    function _verifyMintAuthorizationSignature(bytes memory authorization, bytes memory signature) internal view {
        address recoveredSigner = ECDSA.recover(keccak256(authorization).toEthSignedMessageHash(), signature);
        if (recoveredSigner != mintAuthorizationSigner()) {
            revert InvalidMintAuthorizationSigner();
        }
    }

    /// Validates a single mint authorization
    ///
    /// @dev Checks expiration, value, recipient denylist status, destination caller, destination domain, destination
    ///      contract, and (when the domains match) source contract and token consistency
    ///
    /// @param auth    A `TypedMemView` reference to the byte-encoded mint authorization
    /// @param index   The index of the mint authorization within the batch (used for error reporting)
    function _validateMintAuthorization(bytes29 auth, uint32 index) internal view {
        // Ensure the mint authorization is not expired
        uint256 maxBlockHeight = auth.getMaxBlockHeight();
        if (maxBlockHeight < block.number) {
            revert AuthorizationExpiredAtIndex(index, maxBlockHeight, block.number);
        }

        // Extract the `TransferSpec`
        bytes29 spec = auth.getTransferSpec();

        // Ensure the value is nonzero
        uint256 value = spec.getValue();
        if (value == 0) {
            revert AuthorizationValueMustBePositiveAtIndex(index);
        }

        // Ensure the intended recipient is not denylisted
        _ensureNotDenylisted(AddressLib._bytes32ToAddress(spec.getDestinationRecipient()));

        // Ensure the caller is the specified destination caller (if any)
        address destinationCaller = AddressLib._bytes32ToAddress(spec.getDestinationCaller());
        if (destinationCaller != address(0) && destinationCaller != msg.sender) {
            revert InvalidAuthorizationDestinationCallerAtIndex(index, destinationCaller, msg.sender);
        }

        // Ensure the mint authorization is for the current domain
        uint32 destinationDomain = spec.getDestinationDomain();
        if (!_isCurrentDomain(destinationDomain)) {
            revert InvalidAuthorizationDestinationDomainAtIndex(index, destinationDomain, domain());
        }

        // Ensure the mint authorization is for this minter contract
        address destinationContract = AddressLib._bytes32ToAddress(spec.getDestinationContract());
        if (destinationContract != address(this)) {
            revert InvalidAuthorizationDestinationContractAtIndex(index, destinationContract, address(this));
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
                revert InvalidAuthorizationSourceContractAtIndex(index, sourceContract, walletAddr);
            }

            // Ensure the source and destination tokens are the same
            address sourceToken = AddressLib._bytes32ToAddress(spec.getSourceToken());
            if (sourceToken != destinationToken) {
                revert InvalidAuthorizationTokenAtIndex(index, sourceToken, destinationToken);
            }
        }
    }

    /// Processes a single mint authorization according to its `TransferSpec`. If the source and destination domains
    /// match, calls `gatewayTransfer` on the wallet contract to transfer the funds directly to the recipient. Otherwise,
    /// mints tokens using the appropriate mint authority. Marks the transfer spec hash as used for replay protection
    ///
    /// @param spec   A `TypedMemView` reference to the `TransferSpec` from the mint authorization
    function _mintOrTransfer(bytes29 spec) internal {
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

        // If the source and destination domains match, call `gatewayTransfer` on the wallet contract. Otherwise, mint
        // to the recipient using the appropriate mint authority
        if (sourceDomain == domain()) {
            GatewayWallet(_counterpart()).gatewayTransfer(
                token,
                AddressLib._bytes32ToAddress(depositorBytes),
                recipient,
                AddressLib._bytes32ToAddress(signerBytes),
                value,
                specHash
            );
        } else {
            address mintAuthority = tokenMintAuthority(token);
            address minter = (mintAuthority == address(0)) ? token : mintAuthority;
            IMintToken(minter).mint(recipient, value);
        }

        // Emit an event with the mint authorization details
        emit MintAuthorizationUsed(token, recipient, specHash, sourceDomain, depositorBytes, signerBytes, value);
    }
}

/// Implements the EIP-7201 storage pattern for the `Mints` module
library MintsStorage {
    /// @custom:storage-location 7201:circle.gateway.Mints
    struct Data {
        /// Maps token addresses to their corresponding minter contract addresses. Absence of an entry means the token
        /// itself should be used as the minter. This contract must have permission to mint the associated token via
        /// the minter contract.
        mapping(address token => address tokenMintAuthority) tokenMintAuthorities;
        /// The address of the operator that can sign mint authorizations
        address mintAuthorizationSigner;
    }

    /// `keccak256(abi.encode(uint256(keccak256(bytes("circle.gateway.Mints"))) - 1)) & ~bytes32(uint256(0xff))`
    bytes32 public constant SLOT = 0xa13f18ce64168e6d2f5aa74009cc3360c0bed33f0845237965d1e1378d32aa00;

    /// EIP-7201 getter for the storage slot
    function get() internal pure returns (Data storage $) {
        assembly {
            $.slot := SLOT
        }
    }
}
