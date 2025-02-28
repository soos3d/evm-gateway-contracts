// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

/// The balance interface from ERC-1155
interface IERC1155Balance {
    function balanceOf(address depositor, uint256 id)
        external
        view
        returns (uint256);

    function balanceOfBatch(address[] memory depositors, uint256[] memory ids)
        external
        view
        returns (uint256[] memory);
}