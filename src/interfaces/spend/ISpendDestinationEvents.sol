// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

/// Events emitted by the SpendDestination contract
interface ISpendDestinationEvents {
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

    /// Emitted when a recipient is added to the denylist
    ///
    /// @param recipient   The address that is denied from receiving funds
    event RecipientDenied(address recipient);

    /// Emitted when a recipient is removed from the denylist
    ///
    /// @param recipient   The address that is allowed to receive funds again
    event RecipientAllowed(address recipient);

    /// Emitted when the wallet contract is updated
    ///
    /// @param newWalletContract   The new wallet contract address
    event WalletContractUpdated(address newWalletContract);

    /// Emitted when the pauser address is updated
    ///
    /// @param newPauser   The new pauser address
    event PauserUpdated(address newPauser);
}
