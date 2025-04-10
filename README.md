# Spend Contracts

## Install dependencies

- Run `git submodule update --init --recursive` to update/download all libraries.
- Run `nvm use 18` to use node 18. 
- Run `yarn install` to install any additional dependencies.

## Install Foundry CLI

- Run `curl -L https://foundry.paradigm.xyz | bash`
- Follow the instructions of that command to source env file
- run `foundryup`

## Test

### Unit Tests and Fork Tests (Foundry)
To run tests using Foundry, follow the steps below:

1. Run `forge build` to build the project
2. Run `forge test`

Alternatively, you can run a single test in isolation using something like 
```agsl
forge test -vv --match-test test_initialize_revertWhenReInitialized
```

Or to run a single test contract
```agsl
forge test -vv --match-contract UpgradeablePlaceholderTest
```

### Mock FiatToken port

To simplify local development and testing we have a local port of the FiatToken contracts from the https://github.com/circlefin/stablecoin-evm repo. The port is based on commit [0642db6](https://github.com/circlefin/stablecoin-evm/commit/0642db65d656a51d4df21b8d03dd38124ad0e7b3). When there are essential changes to the FiatToken contracts (e.g., new version release), we'll need to:

1) Go through the diff between the above commit and the latest version, applying the latest changes into `test/mock_fiattoken`
2) Update dependency imports and relative imports
3) Bump solidity version and fix resulting compiler errors
4) Update `test/util/DeployMockFiatToken.sol` if necessary

### Linting

Run `yarn lint` to lint all `.sol` files in the `src` and `test` directories.

## Development

### Dependencies

To add dependencies and make it compatible with our CI, you must do the following.

1. `forge install <alias>=<org>/<repo>@<version>`
    - E.g `forge install openzeppelin=OpenZeppelin/openzeppelin-contracts@v5.0.2`
2. Update `remappings.txt` to include your dependency

### Important Considerations: Memory Initialization with TypedMemView

This project relies heavily on the `TypedMemView` library (`lib/memview-sol/`) for efficient memory manipulation, particularly within `AuthorizationLib.sol`.

**Warning:** As documented in the [TypedMemView](https://github.com/summa-tx/memview-sol/tree/main) library itself, it utilizes unallocated memory operations and **does not guarantee cleanup of unallocated memory regions** after its internal functions execute.

**Implication:** This means that memory subsequently allocated by contracts in *this* project (e.g., declaring new `memory` variables like arrays or structs after `TypedMemView` operations have occurred within the same transaction execution path) **might not be zero-initialized**. It could contain residual data from previous operations.

**Required Precaution:** Developers working on this codebase **must not** assume that newly allocated memory variables or structures are automatically zero-initialized. If the logic relies on a memory variable starting at zero (or `false`, `address(0)`, etc.), it **must** be explicitly initialized after allocation.

## Deployment

Example: (this will simultaneously verify the contract as well)

```
forge create --rpc-url https://goerli.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161 \
    --constructor-args 0xD4a33860578De61DBAbDc8BFdb98FD742fA7028e  \
    --private-key /*insert private key*/ \
    --etherscan-api-key /* insert etherscan api key*/ \
    --verify \
    contracts/paymaster/StablecoinPermissionlessPaymaster.sol:StablecoinPermissionlessPaymaster
```

## Continuous Integration using Github Actions

We use Github actions to run linter and all the tests. The workflow configuration can be found in [.github/workflows/pipeline.yml](.github/workflows/pipeline.yml)

## Manual Triggering of the Olympix CI Workflow
You can manually trigger the Olympix.ai Code Scanning workflow using the `workflow_dispatch` feature of GitHub Actions.
1. Click on the `Actions` tab.
2. In the left sidebar, select `Olympix Scan`.
3. Select the branch & click on the `Run workflow` button.
