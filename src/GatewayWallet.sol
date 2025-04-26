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

import {Burns} from "src/modules/wallet/Burns.sol";
import {Deposits} from "src/modules/wallet/Deposits.sol";
import {Withdrawals} from "src/modules/wallet/Withdrawals.sol";
import {GatewayCommon} from "src/GatewayCommon.sol";
import {GatewayMinter} from "src/GatewayMinter.sol";

/// @title Gateway Wallet
///
/// @notice This contract allows users to deposit supported tokens. Once deposits are observed in a finalized block by
/// the API, the user may request an authorization to instantly mint those funds on another chain. Minted funds are then
/// burnt on the chain where they were deposited.
///
/// @notice The available balance is the amount the user has deposited that may be spent on other chains, subject to
/// finality observed by the API and an authorization obtained from the API. To obtain an authorization, the user must
/// provide the API with a signed message containing the desired parameters along with an authorization to the API that
/// will allow the operator to burn those funds once the mint is observed on the destination chain.
///
/// @notice To mint funds on another chain, the user may request an authorization from the API and then use it to call
/// `gatewayMint` on the GatewayMinter contract on the desired chain. This will mint the funds to the requested
/// destination, and may be composed with other actions via a multicall contract or SCA implementation.
///
/// @notice To withdraw funds on the same chain, the user may request an authorization from the API just like any other
/// mint authorization. If the source and destination domains of the mint authorization are the same, the minter
/// contract will call `gatewayTransfer` on this contract to transfer the funds to the recipient instead of minting. No
/// fee is charged for these transfers.
///
/// @notice To ensure funds are withdrawable even if the API is unavailable, users may withdraw permissionlessly using a
/// two-step process. First, the user must call `initiateWithdrawal` with the desired withdrawal amount. After a delay,
/// the user may call `withdraw` to complete the withdrawal and receive the funds. This delay ensures that no
/// double-spends are possible and that the operator has time to burn any funds that are spent. The amount that is in
/// the process of being withdrawn will no longer be available as soon as the withdrawal initiation is observed by the
/// API in a finalized block. If a double-spend was attempted, the contract will burn the user's funds from both their
/// `available` and `withdrawing` balances.
contract GatewayWallet is GatewayCommon, Deposits, Withdrawals, Burns {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Ensure that the implementation contract cannot be initialized, only the proxy
        _disableInitializers();
    }

    /// Initializes the contract with the counterpart minter address
    ///
    /// @param minter   The address of the minter contract on the same chain
    /// @param domain   The operator-issued identifier for this chain
    function initialize(address minter, uint32 domain) external reinitializer(2) {
        __GatewayCommon_init(minter, domain);
    }

    /// The address of the corresponding minter contract on the same domain
    function minterContract() external view returns (GatewayMinter) {
        return GatewayMinter(_counterpart());
    }
}
