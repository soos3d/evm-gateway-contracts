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

/**
 * @title AuthorizationCursor
 * @notice Used to iterate over a single authorization or a set of authorizations.
 */
struct AuthorizationCursor {
    bytes29 setOrAuthView; // The view pointing to the start of the encoded single authorization or authorization set.
    uint256 offset; // The byte offset within the `setOrAuthView` data where the next authorization begins.
    uint32 numAuths; // The total number of authorizations contained within `setOrAuthView`. Always 1 for a single authorization.
    uint32 index; // The 0-based index of the next authorization.
    bool done; // A flag indicating whether iteration is complete (i.e., `index == numAuths`).
}
