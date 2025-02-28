// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

/// Methods for the SpendWallet contract that are only callable by various
///      admin roles
interface ISpendWalletAdmin {
    /// Debit the depositor's balance and burn the tokens after a spend was
    ///      authorized
    ///
    /// @dev May only be called by the `burner` role
    /// @dev `authorizations` and `signatures` must be the same length
    /// @dev Will revert if `destinationDomain` is the same as `sourceDomain`
    ///      (since no burn is required)
    /// @dev For a set of burn authorizations, authorizations from other domains
    ///      are ignored. The whole set is still needed to verify the signature.
    /// @dev See the docs for `BurnAuthorization` for encoding details
    ///
    /// @param authorizations   An array of byte-encoded burn authorizations
    /// @param signatures       One signature from the spender of each burn
    ///                         authorization
    /// @param fees             The fees to be collected for each burn. Fees for
    ///                         burns on other domains are ignored and may be
    ///                         passed as zero. Each fee must be no more than
    ///                         `maxFee` of the corresponding burn authorization.
    function burnSpent(
        bytes[] memory authorizations,
        bytes[] memory signatures,
        uint256[][] memory fees
    ) external;

    /// Marks a token as supported. Once supported, tokens can not be
    ///      un-supported.
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param token   The token to be added
    function addSupportedToken(address token) external;

    /// Denies a depositor from future spends, forcing them to withdraw instead.
    ///      Used to deny service for legal reasons.
    ///
    /// @param depositor   The depositor to be denied
    function denyDepositor(address depositor) external;

    /// Allows a previously-denied depositor to spend again
    ///
    /// @param depositor   The depositor to be allowed
    function allowDepositor(address depositor) external;

    /// Sets the address that may call `sameChainSpend`
    ///
    /// @dev May only be called by the `owner` role
    /// @dev Always refers to the destination contract on the same chain
    ///
    /// @param newDestinationContract   The new destination contract address
    function updateDestinationContract(address newDestinationContract)
        external;

    /// Sets the number of blocks that must pass before a withdrawal can be
    ///      completed
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newDelay   The new value of the delay, in blocks
    function updateWithdrawalDelay(uint256 newDelay) external;

    /// Sets the address that may call `burnSpent`
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newBurner   The new burner address
    function updateBurner(address newBurner) external;

    /// Sets the address that may call `pause` and `unpause`
    ///
    /// @dev May only be called by the `owner` role
    ///
    /// @param newPauser   The new pauser address
    function updatePauser(address newPauser) external;
}
