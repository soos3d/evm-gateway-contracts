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

import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title EIP712Domain
///
/// @notice This contract implements EIP-712 domain separator functionality
///
/// @dev Adapted from OpenZeppelin's EIP712 implementation (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/acd4ff7/contracts/utils/cryptography/EIP712.sol)
/// @dev This implementation intentionally deviates from the standard by omitting `chainId` and `verifyingContract`
/// fields from the domain separator. This modification ensures burn intents can be verified across different
/// chains and contract deployments.
contract EIP712Domain is IERC5267 {
    /// keccak256("EIP712Domain(string name,string version)");
    bytes32 public constant EIP712_DOMAIN_TYPE_HASH = 0xb03948446334eb9b2196d5eb166f69b9d49403eb4a12f36de8d3f9f3cb8e15c3;

    /// Constants for the domain name and version
    string private constant _NAME = "GatewayWallet";
    string private constant _VERSION = "1";

    /// Cache the domain separator as a constant
    bytes32 private constant _CACHED_DOMAIN_SEPARATOR =
        keccak256(abi.encode(EIP712_DOMAIN_TYPE_HASH, keccak256(bytes(_NAME)), keccak256(bytes(_VERSION))));

    /// @return The cached domain separator
    function domainSeparator() public pure returns (bytes32) {
        return _CACHED_DOMAIN_SEPARATOR;
    }

    /// Returns the EIP712 domain separator fields
    ///
    /// @dev See IERC5267 for more details (https://eips.ethereum.org/EIPS/eip-5267)
    ///
    /// @return fields The EIP712 domain separator fields
    /// @return name The name of the domain
    /// @return version The version of the domain
    /// @return chainId The chain id of the domain
    /// @return verifyingContract The verifying contract of the domain
    /// @return salt The salt of the domain
    /// @return extensions The extensions of the domain
    function eip712Domain()
        public
        view
        virtual
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        return (
            hex"03", // 00011 - only name and version are used
            _NAME,
            _VERSION,
            0,
            address(0),
            bytes32(0),
            new uint256[](0)
        );
    }

    /// Returns the hash of the fully encoded EIP712 message for this domain.
    ///
    /// ```solidity
    /// bytes32 digest = _hashTypedData(keccak256(abi.encode(
    ///     keccak256("Mail(address to,string contents)"),
    ///     mailTo,
    ///     keccak256(bytes(mailContents))
    /// )));
    /// address signer = ECDSA.recover(digest, signature);
    /// ```
    /// @param structHash The hash of the struct to be hashed
    /// @return The hash of the fully encoded EIP712 message for this domain
    function _hashTypedData(bytes32 structHash) internal view virtual returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(domainSeparator(), structHash);
    }
}
