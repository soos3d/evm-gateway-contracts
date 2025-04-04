/*
 * Copyright 2025 Circle Internet Group, Inc. All rights reserved.

 * SPDX-License-Identifier: GPL-3.0-or-later

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
pragma solidity ^0.8.28;

import {SpendCommon} from "src/SpendCommon.sol";
import {SpendWallet} from "src/SpendWallet.sol";

/// @title Spend Minter
///
/// This contract allows the spending of funds from the SpendWallet contract, either on the same chain or on a different
/// chain. Spending requires a signed authorization from the operator. See the documentation for the SpendWallet
/// contract for more details.
contract SpendMinter is SpendCommon {
    /// Maps token addresses to their corresponding minter contract addresses.
    /// The token minter contracts must have permission to mint the associated token.
    mapping(address token => address tokenMintAuthority) public tokenMintAuthorities;

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
    function initialize(address wallet) public reinitializer(2) {
        __SpendCommon_init(wallet);
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
    function spend(bytes memory authorizations, bytes memory signature) external whenNotPaused {
        // For each spend authorization:
        // IMintToken(tokenMintAuthorities[token]).mint(to, amount);
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

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Informational

    function walletContract() external view returns (SpendWallet) {
        return SpendWallet(_counterpart());
    }
}
