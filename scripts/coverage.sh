#!/usr/bin/env bash

forge coverage --report lcov
lcov --remove lcov.info 'test/**' -o lcov.info.pruned --ignore-errors inconsistent
genhtml lcov.info.pruned --output-directory coverage --ignore-errors inconsistent
open coverage/index.html

# Remove the lcov.info file
rm lcov.info
rm lcov.info.pruned
