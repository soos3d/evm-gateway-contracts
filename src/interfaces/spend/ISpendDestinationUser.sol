// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

/// User-facing methods for the SpendDestination contract
interface ISpendDestinationUser {
    /// Spend funds via a signed spend authorization from the operator. Accepts
    ///      either a single encoded `SpendAuthorization` or an encoded set of
    ///      them. Emits an event containing the keccak256 hash of the encoded
    ///      `SpendSpec` (which is the same for the burn), to be used as a
    ///      cross-chain identifier.
    ///
    /// @param authorizations   The byte-encoded spend authorization(s)
    /// @param signature        The signature from the operator
    function spend(bytes memory authorizations, bytes memory signature)
        external;
}
