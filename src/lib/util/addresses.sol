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

/// Thrown when an address is the zero address
error InvalidAddress();

/// Validates that an address is not the zero address
///
/// @param addr   The address being checked
function _checkNotZeroAddress(address addr) pure {
    if (addr == address(0)) {
        revert InvalidAddress();
    }
}

/// Casts an address to bytes32.
/// @dev The 20-byte address is right-aligned in the 32-byte result, padded with leading zeros.
/// Example: `address(0x11...11)` becomes `bytes32(0x00000000000000000000000011...11)`
/// @param addr   The address to cast.
/// @return buf   The bytes32 representation.
function _addressToBytes32(address addr) pure returns (bytes32) {
    return bytes32(uint256(uint160(addr)));
}

/// Casts bytes32 to an address.
/// @dev Extracts the rightmost 20 bytes of the bytes32 value.
/// Example: `bytes32(0x...11...11)` becomes `address(0x11...11)`.
/// @param _buf   The bytes32 to cast.
/// @return The address represented by the lower 20 bytes of _buf.
function _bytes32ToAddress(bytes32 _buf) pure returns (address) {
    return address(uint160(uint256(_buf)));
}
