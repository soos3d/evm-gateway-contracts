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

/// @title AuthorizationCursor
///
/// @notice Used to iterate over a single authorization or a set of authorizations in a uniform way
struct AuthorizationCursor {
    /// The view pointing to the start of the encoded single authorization or authorization set
    bytes29 setOrAuthView;
    /// The byte offset within the `setOrAuthView` data where the next authorization begins
    uint256 offset;
    /// The total number of authorizations contained within `setOrAuthView`. Always 1 for a single authorization.
    uint32 numAuths;
    /// The 0-based index of the next authorization
    uint32 index;
    /// A flag indicating whether iteration is complete (i.e., `index == numAuths`)
    bool done;
}
