# Circle Gateway Contracts

These are the contracts that support the Circle Gateway product. See the contract docs or Circle's website for more information about that product and how to use it.

## Install dependencies

- Run `git submodule update --init --recursive` to update/download all libraries.
- Ensure Yarn is installed and then run `yarn install` to install additional JS dependencies.

## Install Foundry CLI

- Run `curl -L https://foundry.paradigm.xyz | bash`
- Follow the instructions of that command to source env file
- run `foundryup`

## Test

### Unit Tests and Fork Tests (Foundry)

To run tests using Foundry, run `yarn test`. This will run all tests using the default Anvil localnet.

To run tests against each supported network (by forking from each network's RPC endpoint), run `yarn test:all`. If failures related to remote state from an old block are encountered, either point to archive nodes or run `./scripts/update_block_numbers.sh` to pin the latest block for each network and try again.

To run tests and output a gas report for the top-level contracts, run `yarn test:gas`.

### Mock FiatToken port

To simplify local development and testing we have a local port of the FiatToken contracts from the https://github.com/circlefin/stablecoin-evm repo. The port is based on commit [0642db6](https://github.com/circlefin/stablecoin-evm/commit/0642db65d656a51d4df21b8d03dd38124ad0e7b3). When there are essential changes to the FiatToken contracts (e.g., new version release), we'll need to:

1. Go through the diff between the above commit and the latest version, applying the latest changes into `test/mock_fiattoken`
2. Update dependency imports and relative imports
3. Bump solidity version and fix resulting compiler errors
4. Update `test/util/DeployMockFiatToken.sol` if necessary

### Linting and Formatting

Run `yarn lint` to lint all `.sol` files in the `src` and `test` directories, and `yarn lint:fix` to automatically fix any fixable linting errors.

Run `yarn format` to check the formatting of all `.sol` files in the `src` and `test` directories, and `yarn format:fix` to automatically format them.

### Coverage

Run `yarn coverage` to generate a coverage report for the tests.

## Development

### Contract Sizes

To check the bytecode size of all top-level contracts against the EIP-170 contract size limit, run `yarn sizes`.

### Important Considerations: Memory Initialization with TypedMemView

This project relies heavily on the `TypedMemView` library (`lib/memview-sol/`) for efficient memory manipulation, particularly within `AuthorizationLib.sol`.

**Warning:** As documented in the [TypedMemView](https://github.com/summa-tx/memview-sol/tree/main) library itself, it utilizes unallocated memory operations and **does not guarantee cleanup of unallocated memory regions** after its internal functions execute.

**Implication:** This means that memory subsequently allocated by contracts in _this_ project (e.g., declaring new `memory` variables like arrays or structs after `TypedMemView` operations have occurred within the same transaction execution path) **might not be zero-initialized**. It could contain residual data from previous operations.

**Required Precaution:** Developers working on this codebase **must not** assume that newly allocated memory variables or structures are automatically zero-initialized. If the logic relies on a memory variable starting at zero (or `false`, `address(0)`, etc.), it **must** be explicitly initialized after allocation.

## Continuous Integration using Github Actions

We use Github actions to run the linter and all the tests. The workflow configuration can be found in [.github/workflows/pipeline.yml](.github/workflows/pipeline.yml). While not a complete replacement, all CI steps may be run locally with `yarn ci`.

## Manual Triggering of the Olympix CI Workflow

You can manually trigger the Olympix.ai Code Scanning workflow using the `workflow_dispatch` feature of GitHub Actions.

1. Click on the `Actions` tab.
2. In the left sidebar, select `Olympix Scan`.
3. Select the branch & click on the `Run workflow` button.
