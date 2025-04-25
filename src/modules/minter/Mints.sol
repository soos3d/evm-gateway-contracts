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
import {IMintToken} from "src/interfaces/IMintToken.sol";
import {AuthorizationCursor} from "src/lib/authorizations/AuthorizationCursor.sol";
import {MintAuthorizationLib} from "src/lib/authorizations/MintAuthorizationLib.sol";
import {TransferSpecLib} from "src/lib/authorizations/TransferSpecLib.sol";
import {_checkNotZeroAddress, _bytes32ToAddress} from "src/lib/util/addresses.sol";
import {SpendCommon} from "src/SpendCommon.sol";
import {GatewayWallet} from "src/GatewayWallet.sol";

/// @title Mints
///
/// Manages mints for the SpendMinter module
contract Mints is SpendCommon {
    using TransferSpecLib for bytes29;
    using MintAuthorizationLib for bytes29;
    using MintAuthorizationLib for AuthorizationCursor;
    using MessageHashUtils for bytes32;

    /// Emitted when the a spend authorization is used
    ///
    /// @param token             The token that was spent
    /// @param recipient         The recipient of the funds
    /// @param spendHash         The keccak256 hash of the `TransferSpec`
    /// @param sourceDomain      The domain the funds came from
    /// @param sourceDepositor   The depositor on the source domain
    /// @param sourceSigner      The signer that authorized the transfer
    /// @param value             The amount that was minted/transferred
    event Spent(
        address indexed token,
        address indexed recipient,
        bytes32 indexed spendHash,
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

    /// Emitted when the mintAuthorizationSigner role is updated
    ///
    /// @param oldMintAuthorizationSigner   The previous mint authorization signer address
    /// @param newMintAuthorizationSigner   The new mint authorization signer address
    event MintAuthorizationSignerUpdated(address oldMintAuthorizationSigner, address newMintAuthorizationSigner);

    error InvalidMintAuthorizationSigner();
    error MustHaveAtLeastOneMintAuthorization();
    error AuthorizationValueMustBePositiveAtIndex(uint32 index);
    error AuthorizationExpiredAtIndex(uint32 index, uint256 maxBlockHeight, uint256 currentBlock);
    error InvalidAuthorizationDestinationDomainAtIndex(
        uint32 index, uint32 expectedDestinationDomain, uint32 actualDomain
    );
    error InvalidAuthorizationDestinationContractAtIndex(uint32 index, address expectedDestinationContract);
    error InvalidAuthorizationSourceContractAtIndex(
        uint32 index, address sourceContract, address expectedSourceContract
    );
    error InvalidAuthorizationTokenAtIndex(uint32 index, address sourceToken, address destinationToken);
    error InvalidAuthorizationDestinationCallerAtIndex(
        uint32 index, address expectedDestinationCaller, address actualCaller
    );

    /// Spend funds via a signed spend authorization from the operator. Accepts either a single encoded
    /// `SpendAuthorization` or an encoded set of them. Emits an event containing the keccak256 hash of the encoded
    /// `SpendSpec` (which is the same for the burn), to be used as a cross-chain identifier.
    ///
    /// @param authorization   The byte-encoded spend authorization(s)
    /// @param signature       The signature from the operator
    function spend(bytes memory authorization, bytes memory signature)
        external
        whenNotPaused
        notDenylisted(msg.sender)
    {
        _validateMintAuthorizationSignature(authorization, signature);
        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(authorization);

        if (cursor.numAuths == 0) {
            revert MustHaveAtLeastOneMintAuthorization();
        }

        bytes29 auth;
        while (!cursor.done) {
            auth = cursor.next();
            _validateMintAuthorization(auth, cursor.index - 1);
            _spend(auth.getTransferSpec());
        }
    }

    /// Returns the mint authorization signer that is recognized by the contract
    function mintAuthorizationSigner() public view returns (address) {
        return MintsStorage.get().mintAuthorizationSigner;
    }

    /// Returns the mint authority for a token
    ///
    /// @param token   The token to check
    function tokenMintAuthority(address token) public view returns (address) {
        return MintsStorage.get().tokenMintAuthorities[token];
    }

    /// Updates the mint authority for a token.
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param token              The token address to update the mint authority for
    /// @param newMintAuthority   The address to set as the new mint authority
    function updateMintAuthority(address token, address newMintAuthority) external onlyOwner tokenSupported(token) {
        _checkNotZeroAddress(newMintAuthority);

        MintsStorage.Data storage $ = MintsStorage.get();
        address oldMintAuthority = $.tokenMintAuthorities[token];
        $.tokenMintAuthorities[token] = newMintAuthority;
        emit MintAuthorityUpdated(token, oldMintAuthority, newMintAuthority);
    }

    /// Sets the operator address that may sign mint authorizations
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newMintAuthorizationSigner   The new mint authorization signer address
    function updateMintAuthorizationSigner(address newMintAuthorizationSigner) external onlyOwner {
        _checkNotZeroAddress(newMintAuthorizationSigner);

        MintsStorage.Data storage $ = MintsStorage.get();
        address oldMintAuthorizationSigner = $.mintAuthorizationSigner;
        $.mintAuthorizationSigner = newMintAuthorizationSigner;
        emit MintAuthorizationSignerUpdated(oldMintAuthorizationSigner, newMintAuthorizationSigner);
    }

    /// @notice Validates the signature for a (set of) mint authorization(s).
    /// @dev Recovers the signer from the signature and compares it to the `mintAuthorizationSigner`.
    /// @param authorization The byte-encoded mint authorization(s).
    /// @param signature The signature from the operator on the `authorization`.
    function _validateMintAuthorizationSignature(bytes memory authorization, bytes memory signature) internal view {
        bytes32 authorizationsHash = keccak256(authorization);
        address recoveredSigner = ECDSA.recover(authorizationsHash.toEthSignedMessageHash(), signature);
        if (recoveredSigner != MintsStorage.get().mintAuthorizationSigner) {
            revert InvalidMintAuthorizationSigner();
        }
    }

    /// @notice Validates a single mint authorization.
    /// @dev Checks expiration, value, recipient denylist status, destination caller, destination domain, destination
    /// contract, and (for same-chain spends) source contract and token consistency.
    /// @param auth A reference to the byte-encoded mint authorization.
    /// @param index The index of the authorization within the batch (used for error reporting).
    function _validateMintAuthorization(bytes29 auth, uint32 index) internal view {
        uint256 maxBlockHeight = auth.getMaxBlockHeight();
        if (maxBlockHeight < block.number) {
            revert AuthorizationExpiredAtIndex(index, maxBlockHeight, block.number);
        }

        bytes29 spec = auth.getTransferSpec();

        uint256 value = spec.getValue();
        if (value == 0) {
            revert AuthorizationValueMustBePositiveAtIndex(index);
        }

        _ensureNotDenylisted(_bytes32ToAddress(spec.getDestinationRecipient()));

        address destinationCaller = _bytes32ToAddress(spec.getDestinationCaller());
        if (destinationCaller != address(0) && destinationCaller != msg.sender) {
            revert InvalidAuthorizationDestinationCallerAtIndex(index, destinationCaller, msg.sender);
        }

        uint32 destinationDomain = spec.getDestinationDomain();
        if (!_isCurrentDomain(destinationDomain)) {
            revert InvalidAuthorizationDestinationDomainAtIndex(index, destinationDomain, domain());
        }

        address destinationContract = _bytes32ToAddress(spec.getDestinationContract());
        if (destinationContract != address(this)) {
            revert InvalidAuthorizationDestinationContractAtIndex(index, destinationContract);
        }

        address destinationToken = _bytes32ToAddress(spec.getDestinationToken());
        _ensureTokenSupported(destinationToken);

        uint32 sourceDomain = spec.getSourceDomain();
        if (sourceDomain == destinationDomain) {
            // Same chain spend
            address sourceContract = _bytes32ToAddress(spec.getSourceContract());
            address walletAddr = _counterpart();
            if (sourceContract != walletAddr) {
                revert InvalidAuthorizationSourceContractAtIndex(index, sourceContract, walletAddr);
            }
            address sourceToken = _bytes32ToAddress(spec.getSourceToken());
            if (sourceToken != destinationToken) {
                revert InvalidAuthorizationTokenAtIndex(index, sourceToken, destinationToken);
            }
        }
    }

    /// @notice Executes a single spend based on the provided transfer specification.
    /// @dev Marks the spend hash as used. For same-chain spends, calls `sameChainSpend` on the wallet counterpart contract.
    /// For cross-chain spends, mints tokens using the appropriate mint authority. Emits a `Spent` event.
    /// @param spec A reference to the `TransferSpec` defining the spend details.
    function _spend(bytes29 spec) internal {
        bytes32 specHash = spec.getHash();
        _checkAndMarkSpendHash(specHash);

        address recipient = _bytes32ToAddress(spec.getDestinationRecipient());
        uint256 value = spec.getValue();
        address token = _bytes32ToAddress(spec.getDestinationToken());
        uint32 sourceDomain = spec.getSourceDomain();
        bytes32 depositorBytes = spec.getSourceDepositor();
        bytes32 signerBytes = spec.getSourceSigner();

        if (sourceDomain == domain()) {
            address sourceSigner = _bytes32ToAddress(signerBytes);
            GatewayWallet(_counterpart()).sameChainSpend(
                token, _bytes32ToAddress(depositorBytes), recipient, sourceSigner, value, specHash
            );
        } else {
            address mintAuthority = MintsStorage.get().tokenMintAuthorities[token];
            address minter = (mintAuthority == address(0)) ? token : mintAuthority;
            IMintToken(minter).mint(recipient, value);
        }

        emit Spent(token, recipient, specHash, sourceDomain, depositorBytes, signerBytes, value);
    }
}

/// Implements the EIP-7201 storage pattern for the Mints module
library MintsStorage {
    /// @custom:storage-location 7201:circle.gateway.Mints
    struct Data {
        /// Maps token addresses to their corresponding minter contract addresses.
        /// The token minter contracts must have permission to mint the associated token.
        mapping(address token => address tokenMintAuthority) tokenMintAuthorities;
        /// The address of the operator that can sign mint authorizations
        address mintAuthorizationSigner;
    }

    /// keccak256(abi.encode(uint256(keccak256("circle.gateway.Mints")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant SLOT = 0xa13f18ce64168e6d2f5aa74009cc3360c0bed33f0845237965d1e1378d32aa00;

    /// EIP-7201 getter for the storage slot
    function get() internal pure returns (Data storage $) {
        assembly {
            $.slot := SLOT
        }
    }
}
