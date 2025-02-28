// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import {ISpendDestinationUser} from
    "src/interfaces/spend/ISpendDestinationUser.sol";
import {ISpendDestinationAdmin} from
    "src/interfaces/spend/ISpendDestinationAdmin.sol";
import {ISpendDestinationEvents} from
    "src/interfaces/spend/ISpendDestinationEvents.sol";

/// The interface for the SpendDestination contract where funds are spent
interface ISpendDestination is
    ISpendDestinationUser,
    ISpendDestinationAdmin,
    ISpendDestinationEvents
{}
