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

import {SpendCommon} from "src/SpendCommon.sol";
import {SpendWallet} from "src/SpendWallet.sol";
import {_checkNotZeroAddress, _bytes32ToAddress} from "src/lib/util/addresses.sol";
import {AuthorizationCursor} from "src/lib/authorizations/AuthorizationCursor.sol";
import {TransferSpecLib} from "src/lib/authorizations/TransferSpecLib.sol";
import {MintAuthorization} from "src/lib/authorizations/MintAuthorizations.sol";
import {MintAuthorizationLib} from "src/lib/authorizations/MintAuthorizationLib.sol";
import {IMintToken} from "src/interfaces/IMintToken.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title Spend Minter
///
/// This contract allows the spending of funds from the SpendWallet contract, either on the same chain or on a different
/// chain. Spending requires a signed authorization from the operator. See the documentation for the SpendWallet
/// contract for more details.
contract SpendMinter is SpendCommon {
    using MessageHashUtils for bytes32;
    using TransferSpecLib for bytes29;
    using MintAuthorizationLib for bytes29;
    using MintAuthorizationLib for AuthorizationCursor;

    error InvalidMintAuthorizationSigner();
    error MustHaveAtLeastOneMintAuthorization();
    error AuthorizationValueMustBePositive(uint32 index);
    error AuthorizationExpired(uint32 index, uint256 maxBlockHeight, uint256 currentBlock);
    error InvalidAuthorizationDestinationDomain(uint32 index, uint32 expectedDestinationDomain, uint32 actualDomain);
    error InvalidAuthorizationDestinationContract(uint32 index, address expectedDestinationContract);
    error InvalidAuthorizationSourceContract(uint32 index, address sourceContract, address expectedSourceContract);
    error InvalidAuthorizationToken(uint32 index, address sourceToken, address destinationToken);
    error InvalidAuthorizationDestinationCaller(uint32 index, address expectedDestinationCaller, address actualCaller);

    /// Maps token addresses to their corresponding minter contract addresses.
    /// The token minter contracts must have permission to mint the associated token.
    mapping(address token => address tokenMintAuthority) public tokenMintAuthorities;

    /// The address of the operator that can sign mint authorizations
    address public mintAuthorizationSigner;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Initialization

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Ensure that the implementation contract cannot be initialized, only the proxy
        _disableInitializers();
    }

    /// Initializes the contract with the counterpart wallet address
    ///
    /// @param wallet   The address of the wallet contract on the same chain
    /// @param domain   The operator-issued identifier for this chain
    function initialize(address wallet, uint32 domain) public reinitializer(2) {
        __SpendCommon_init(wallet, domain);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Spending

    /// Emitted when the a spend authorization is used
    ///
    /// @param token                The token that was spent
    /// @param recipient            The recipient of the funds
    /// @param spendHash            The keccak256 hash of the `SpendSpec`
    /// @param sourceDomain         The domain the funds came from
    /// @param depositor            The depositor on the source domain
    /// @param value                The amount that was minted/transferred
    /// @param spendAuthorization   The entire spend authorization that was used
    event Spent(
        address indexed token,
        address indexed recipient,
        bytes32 indexed spendHash,
        uint32 sourceDomain,
        bytes32 depositor,
        uint256 value,
        bytes spendAuthorization
    );

    /// Spend funds via a signed spend authorization from the operator. Accepts either a single encoded
    /// `SpendAuthorization` or an encoded set of them. Emits an event containing the keccak256 hash of the encoded
    /// `SpendSpec` (which is the same for the burn), to be used as a cross-chain identifier.
    ///
    /// @param authorizations   The byte-encoded spend authorization(s)
    /// @param signature        The signature from the operator
    function spend(bytes memory authorizations, bytes memory signature)
        external
        whenNotPaused
        notDenylisted(msg.sender)
    {
        _validateMintAuthorizationSignature(authorizations, signature);
        AuthorizationCursor memory cursor = MintAuthorizationLib.cursor(authorizations);

        if (cursor.numAuths == 0) {
            revert MustHaveAtLeastOneMintAuthorization();
        }

        bytes29 auth;
        while (!cursor.done) {
            auth = cursor.next();
            _validateMintAuthorization(auth, cursor.index - 1);
            _spend(auth.getTransferSpec(), authorizations);
        }
    }

    /// @notice Validates the signature for a set of mint authorizations.
    /// @dev Recovers the signer from the signature and compares it to the `mintAuthorizationSigner`.
    /// @param authorizations The byte-encoded mint authorization(s).
    /// @param signature The signature from the operator over the `authorizations` hash.
    function _validateMintAuthorizationSignature(bytes memory authorizations, bytes memory signature) internal view {
        bytes32 authorizationsHash = keccak256(authorizations);
        address recoveredSigner = ECDSA.recover(authorizationsHash.toEthSignedMessageHash(), signature);
        if (recoveredSigner != mintAuthorizationSigner) {
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
            revert AuthorizationExpired(index, maxBlockHeight, block.number);
        }

        bytes29 spec = auth.getTransferSpec();

        uint256 value = spec.getValue();
        if (value == 0) {
            revert AuthorizationValueMustBePositive(index);
        }

        _ensureNotDenylisted(_bytes32ToAddress(spec.getDestinationRecipient()));

        address destinationCaller = _bytes32ToAddress(spec.getDestinationCaller());
        if (destinationCaller != address(0) && destinationCaller != msg.sender) {
            revert InvalidAuthorizationDestinationCaller(index, destinationCaller, msg.sender);
        }

        uint32 destinationDomain = spec.getDestinationDomain();
        if (!_isCurrentDomain(destinationDomain)) {
            revert InvalidAuthorizationDestinationDomain(index, destinationDomain, domain());
        }

        address destinationContract = _bytes32ToAddress(spec.getDestinationContract());
        if (destinationContract != address(this)) {
            revert InvalidAuthorizationDestinationContract(index, destinationContract);
        }

        address destinationToken = _bytes32ToAddress(spec.getDestinationToken());
        _ensureTokenSupported(destinationToken);

        uint32 sourceDomain = spec.getSourceDomain();
        if (sourceDomain == destinationDomain) {
            // Same chain spend
            address sourceContract = _bytes32ToAddress(spec.getSourceContract());
            address walletAddr = _counterpart();
            if (sourceContract != walletAddr) {
                revert InvalidAuthorizationSourceContract(index, sourceContract, walletAddr);
            }
            address sourceToken = _bytes32ToAddress(spec.getSourceToken());
            if (sourceToken != destinationToken) {
                revert InvalidAuthorizationToken(index, sourceToken, destinationToken);
            }
        }
    }

    /// @notice Executes a single spend based on the provided transfer specification.
    /// @dev Marks the spend hash as used. For same-chain spends, calls `sameChainSpend` on the wallet counterpart contract.
    /// For cross-chain spends, mints tokens using the appropriate mint authority. Emits a `Spent` event.
    /// @param spec A reference to the `TransferSpec` defining the spend details.
    /// @param authorizations The full byte-encoded authorization(s) used.
    function _spend(bytes29 spec, bytes memory authorizations) internal {
        bytes32 specHash = spec.getHash();
        _checkAndMark(specHash);
        address recipient = _bytes32ToAddress(spec.getDestinationRecipient());
        uint256 value = spec.getValue();
        address token = _bytes32ToAddress(spec.getDestinationToken());
        bytes32 depositorBytes = spec.getSourceDepositor();
        uint32 sourceDomain = spec.getSourceDomain();
        if (sourceDomain == domain()) {
            address sourceSigner = _bytes32ToAddress(spec.getSourceSigner());
            SpendWallet(_counterpart()).sameChainSpend(
                token, _bytes32ToAddress(depositorBytes), recipient, sourceSigner, value, specHash, authorizations
            );
        } else {
            address mintAuthority = tokenMintAuthorities[token];
            address minter = (mintAuthority == address(0)) ? token : mintAuthority;
            IMintToken(minter).mint(recipient, value);
        }
        emit Spent(token, recipient, specHash, sourceDomain, depositorBytes, value, authorizations);
    }

    /// Emitted when the mint authority is updated for a token
    ///
    /// @param token              The token whose mint authority was updated
    /// @param oldMintAuthority   The previous mint authority address
    /// @param newMintAuthority   The new mint authority address
    event MintAuthorityUpdated(address token, address oldMintAuthority, address newMintAuthority);

    /// Updates the mint authority for a token.
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param token              The token address to update the mint authority for
    /// @param newMintAuthority   The address to set as the new mint authority
    function updateMintAuthority(address token, address newMintAuthority) external onlyOwner tokenSupported(token) {
        _checkNotZeroAddress(newMintAuthority);

        address oldMintAuthority = tokenMintAuthorities[token];
        tokenMintAuthorities[token] = newMintAuthority;
        emit MintAuthorityUpdated(token, oldMintAuthority, newMintAuthority);
    }

    /// Returns the byte encoding of a single mint authorization
    ///
    /// @param authorization   The mint authorization to encode
    function encodeMintAuthorization(MintAuthorization memory authorization) external pure returns (bytes memory) {}

    /// Returns the byte encoding of a set of mint authorizations
    ///
    /// @dev The mint authorizations must be sorted by domain
    ///
    /// @param authorizations   The mint authorizations to encode
    function encodeMintAuthorizations(MintAuthorization[] memory authorizations) external pure returns (bytes memory) {}

    /// Emitted when the mintAuthorizationSigner role is updated
    ///
    /// @param oldMintAuthorizationSigner   The previous mint authorization signer address
    /// @param newMintAuthorizationSigner   The new mint authorization signer address
    event MintAuthorizationSignerUpdated(address oldMintAuthorizationSigner, address newMintAuthorizationSigner);

    /// Sets the operator address that may sign mint authorizations
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newMintAuthorizationSigner   The new mint authorization signer address
    function updateMintAuthorizationSigner(address newMintAuthorizationSigner) external onlyOwner {
        _checkNotZeroAddress(newMintAuthorizationSigner);

        address oldMintAuthorizationSigner = mintAuthorizationSigner;
        mintAuthorizationSigner = newMintAuthorizationSigner;
        emit MintAuthorizationSignerUpdated(oldMintAuthorizationSigner, newMintAuthorizationSigner);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Informational

    function walletContract() external view returns (SpendWallet) {
        return SpendWallet(_counterpart());
    }
}
