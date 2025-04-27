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

/// @title IERC1155Balance
///
/// @notice The balance interface from ERC-1155
interface IERC1155Balance {
    /// Returns the value of tokens of token type `id` owned by `account`
    ///
    /// @param account   The account to check
    /// @param id        The token type to check
    function balanceOf(address account, uint256 id) external view returns (uint256);

    /// The batched version of `balanceOf`
    ///
    /// @param accounts   The accounts to check
    /// @param ids        The token types to check
    function balanceOfBatch(address[] memory accounts, uint256[] memory ids) external view returns (uint256[] memory);
}
