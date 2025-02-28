// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

/// Methods for the SpendDestination contract that are only callable by various
///      admin roles
interface ISpendDestinationAdmin {
    /// Denies a recipient from receiving funds from future spends.
    ///      Used to deny service for legal reasons.
    ///
    /// @param recipient   The recipient to be denied
    function denyRecipient(address recipient) external;

    /// Allows a previously-denied recipient to receive funds again
    ///
    /// @param recipient   The recipient to be allowed
    function allowRecipient(address recipient) external;

    /// Sets the address of the corresponding wallet contract on this chain,
    ///      in order to call `sameChainSpend`
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newWalletContract   The new wallet contract address
    function updateWalletContract(address newWalletContract) external;

    /// Sets the address that may call `pause` and `unpause`
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newPauser   The new pauser address
    function updatePauser(address newPauser) external;
}
