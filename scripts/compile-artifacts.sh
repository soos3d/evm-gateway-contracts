#!/usr/bin/env bash

set -e

forge clean
forge build

cp out/ERC1967Proxy.sol/ERC1967Proxy.json \
   script/compiled-contract-artifacts/ERC1967Proxy.json
echo "Copied ERC1967Proxy.json"

cp out/UpgradeablePlaceholder.sol/UpgradeablePlaceholder.json \
   script/compiled-contract-artifacts/UpgradeablePlaceholder.json
echo "Copied UpgradeablePlaceholder.json"

cp out/GatewayMinter.sol/GatewayMinter.json \
   script/compiled-contract-artifacts/GatewayMinter.json
echo "Copied GatewayMinter.json"

cp out/GatewayWallet.sol/GatewayWallet.json \
   script/compiled-contract-artifacts/GatewayWallet.json
echo "Copied GatewayWallet.json"
