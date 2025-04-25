/**
 * Copyright 2023 Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pragma solidity ^0.8.29;

import {ECRecover} from "../util/ECRecover.sol";
import {IERC1271} from "../interface/IERC1271.sol";

/**
 * @title MockERC1271WalletCustomValidation
 * @dev An ERC-1271 compatible wallet that performs custom signature validation
 */
contract MockERC1271Wallet is IERC1271 {
    address private _owner;
    bool private _signatureValid;

    constructor(address owner) {
        _owner = owner;
    }

    function setSignatureValid(bool signatureValid) external {
        _signatureValid = signatureValid;
    }

    function isValidSignature(bytes32, bytes memory) external view override returns (bytes4 magicValue) {
        return _signatureValid ? IERC1271.isValidSignature.selector : bytes4(0);
    }
}
