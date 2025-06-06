#!/usr/bin/env bash

# Ensure that required environment variables are set
if [ -z "$SALT_MINE_CREATE2_FACTORY_ADDRESS" ]; then
  echo "SALT_MINE_CREATE2_FACTORY_ADDRESS is not set in .env file."
  exit 1
fi
if [ -z "$WALLET_PROXY_INIT_CODE_HASH" ]; then
  echo "WALLET_PROXY_INIT_CODE_HASH is not set in .env file."
  exit 1
fi
if [ -z "$MINTER_PROXY_INIT_CODE_HASH" ]; then
  echo "MINTER_PROXY_INIT_CODE_HASH is not set in .env file."
  exit 1
fi


# Mine Wallet Proxy salt
echo "****** Mining salt for GatewayWallet proxy... ******"

cast create2 --starts-with "7777777" --deployer $SALT_MINE_CREATE2_FACTORY_ADDRESS --init-code-hash $WALLET_PROXY_INIT_CODE_HASH


# Mine Minter Proxy salt
echo -e "\n--------------------------------------------------------------------------------------------------------\n"
echo "****** Mining salt for GatewayMinter proxy... ******"

cast create2 --starts-with "2222222" --deployer $SALT_MINE_CREATE2_FACTORY_ADDRESS --init-code-hash $MINTER_PROXY_INIT_CODE_HASH