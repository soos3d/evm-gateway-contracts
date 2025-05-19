#!/usr/bin/env bash

set -e

filename="block-numbers.json"
chains=$(forge config --json | jq -r '.rpc_endpoints | keys[]')
new_block_numbers=""

function append() {
  new_block_numbers+="$1"
}

append "{"

first_time=true

for chain in ${chains[@]}; do
  rpc=$(forge config --json | jq -r ".rpc_endpoints.${chain}")
  block=$(cast block-number --rpc-url ${rpc})

  echo Latest block on ${chain} is ${block}

  if $first_time; then
    first_time=false
  else
    append ","
  fi

  append "\"${chain}\": ${block}"
done

append "}"

echo
echo "Updating block-numbers.json:"
echo

echo "${new_block_numbers}" | jq | tee block-numbers.json
