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

/// @title IBurnToken
///
/// Used interact with a token that supports burning
interface IBurnToken {
    /// Allows a minter to burn some of its own tokens
    ///
    /// @dev The caller must be a minter, must not be blacklisted, and the amount to burn should be less than or equal
    ///      to the account's balance.
    ///
    /// @param _amount   The amount of tokens to be burned
    function burn(uint256 _amount) external;
}
