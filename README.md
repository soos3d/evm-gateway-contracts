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

### Linting

Run `yarn lint` to lint all `.sol` files in the `src` and `test` directories.

## Development

### Dependencies

To add dependencies and make it compatible with our CI, you must do the following.

1. `forge install <alias>=<org>/<repo>@<version>`
    - E.g `forge install openzeppelin=OpenZeppelin/openzeppelin-contracts@v5.0.2`
2. Update `remappings.txt` to include your dependency

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
