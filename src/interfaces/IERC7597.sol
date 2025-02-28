// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

/// The EIP-2612 extension that allows for permit signatures from SCAs
interface IERC7597 {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        bytes memory signature
    ) external;
}