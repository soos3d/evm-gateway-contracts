#!/usr/bin/env bash

# Kill any existing anvil processes
killall -q anvil

# Start a new anvil instance
echo "Starting localnet"
anvil --quiet &
sleep 3

# Run the mocha tests and capture the result
echo "Running mocha tests"
mocha test/js/*.test.js
result=$?

# Kill anvil again
echo "Stopping localnet"
killall -q anvil > /dev/null 2>&1

# Exit with the result of the mocha tests
exit $result
