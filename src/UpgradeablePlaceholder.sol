// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import {Ownable2StepUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from
    "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from
    "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// A no-op, upgradeable implementation contract for UUPS proxies
contract UpgradeablePlaceholder is
    Initializable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable
{
    /// Allow the owner to upgrade the contract
    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyOwner
    {}

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address newOwner) public initializer {
        __UUPSUpgradeable_init();
        __Ownable_init(newOwner);
        __Ownable2Step_init();
    }
}