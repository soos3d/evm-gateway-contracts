#!/usr/bin/env bash

set -e

EIP_170_SIZE_LIMIT=24576

exceeded=false

for contract in SpendWallet BurnLib SpendMinter UpgradeablePlaceholder; do
  deployed_size=$(jq -r '.deployedBytecode.object | (length - 2) / 2' out/$contract.sol/$contract.json)
  if [[ deployed_size -gt $EIP_170_SIZE_LIMIT ]]; then
      echo -e "\e[31m❌ $contract (deployed bytecode size: $deployed_size) exceeds the EIP-170 size limit ($EIP_170_SIZE_LIMIT)\e[0m"
    exceeded=true
  else
      echo -e "\e[32m✅ $contract (deployed bytecode size: $deployed_size) is within the EIP-170 size limit ($EIP_170_SIZE_LIMIT)\e[0m"
  fi
done

if $exceeded; then
  exit 1
fi
