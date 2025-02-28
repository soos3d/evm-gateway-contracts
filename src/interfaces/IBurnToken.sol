// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

/// Used to interact with a token that allows burning
interface IBurnToken {
    function burn(uint256 amount) external;
}