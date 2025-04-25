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

import {Mints} from "src/modules/minter/Mints.sol";
import {GatewayCommon} from "src/GatewayCommon.sol";
import {GatewayWallet} from "src/GatewayWallet.sol";

/// @title Gateway Minter
///
/// This contract allows the spending of funds from the GatewayWallet contract, either on the same chain or on a different
/// chain. Spending requires a signed authorization from the operator. See the documentation for the GatewayWallet
/// contract for more details.
contract GatewayMinter is GatewayCommon, Mints {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Ensure that the implementation contract cannot be initialized, only the proxy
        _disableInitializers();
    }

    /// Initializes the contract with the counterpart wallet address
    ///
    /// @param wallet   The address of the wallet contract on the same chain
    /// @param domain   The operator-issued identifier for this chain
    function initialize(address wallet, uint32 domain) external reinitializer(2) {
        __GatewayCommon_init(wallet, domain);
    }

    /// The address of the corresponding wallet contract on the same domain
    function walletContract() external view returns (GatewayWallet) {
        return GatewayWallet(_counterpart());
    }
}
