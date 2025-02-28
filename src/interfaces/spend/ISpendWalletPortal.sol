// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

/// Methods for the SpendWallet contract that are only callable by the
///      SpendDestination contract on the same chain
interface ISpendWalletPortal {
    /// Debits the depositor's balance like `burnSpent`, but transfers
    ///      funds instead of burning them. Used when a spend happens on the
    ///      same chain to avoid burning and minting. No fee is charged.
    ///
    /// @dev The caller of this method must be the `destinationContract`
    /// @dev The source and destination domains must both be this contract's
    ///      domain
    /// @dev See the docs for `SpendAuthorization` for encoding details
    ///
    /// @param authorization   The spend authorization that was passed to the
    ///                        destination contract
    /// @param signature       The signature from the operator
    function sameChainSpend(bytes memory authorization, bytes memory signature)
        external;
}
