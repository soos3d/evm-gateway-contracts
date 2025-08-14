---
title: "Web (JavaScript/TypeScript) - AA"
description: "Leveraging Particle's AA SDK within web applications."
sidebarTitle: "Web (JS/TS) - AA"
---

## Account Abstraction for Web

Particle Network natively supports and facilitates end-to-end utilization of ERC-4337 account abstraction. This is primarily done through the account abstraction SDK, capable of constructing, sponsoring, and sending UserOperations, alongside deploying smart accounts, retrieving fee quotes, and other key functions. At the center of Particle Network's Modular Smart Wallet-as-a-Service is the AA SDK, which fully supports web applications.

## Repository

The Particle Network `aa-sdk` has an open-source [GitHub repository](https://github.com/Particle-Network/aa-sdk) providing full transparency of the underlying architecture. It may be worthwhile to look at this repository to contextualize the information below, making it easier to digest.

***

## Getting Started

Configuring and initializing the Particle Network AA SDK is simple, although there are two key steps to consider beforehand: installing `@particle-network/aa` with either Yarn or npm and retrieving required core values from the [Particle dashboard](https://dashboard.particle.network).

### Installation

To begin with installation, you'll need to choose either Yarn or npm, then run the command detailed below within your shell:

```shell Terminal
yarn add @particle-network/aa

// Or

npm install @particle-network/aa
```

### Setting up the Particle dashboard

You'll also need required values from the Particle dashboard: your `projectId`, `clientKey`, and `appId`. Each of these values will be used in the initial configuration/initialization of the SDK and directly link your instance of the SDK with the [Particle dashboard](https://dashboard.particle.network). Retrieving these values can be done by following the process below:

<Note>Follow the quickstart tutorial to set up a project and find the required keys: [Create a new project](/guides/wallet-as-a-service/waas/auth/web-quickstart#configuring-particle-auth).</Note>

<Tip>
Important details before initialization.
<p></p>
<p>Before initializing the SDK, there are a few key points to keep in mind, specifically regarding the utilization of Paymasters (to sponsor gas fees, pay for gas in ERC-20 tokens, etc.)</p>
<p></p>
<p>- All Testnets automatically have the Verifying Particle Network Omnichain Paymaster enabled. Transactions that request it will automatically be sponsored and thus gasless.</p>
<p>- On the occasion that you'd like to use the Particle Network Omnichain Paymaster for Mainnets, you'll need to deposit USDT on either Ethereum or BNB Chain within the <a href="https://dashboard.particle.network">Particle dashboard</a>. This USDT will then automatically be converted as needed into the native token of the network you're requesting (and qualifying for) sponsorship on.</p>
<p>- Alternatively, if you'd like to instead use Biconomy's Verifying Paymaster, you can head over to the <a href="https://dashboard.biconomy.io">Biconomy dashboard</a>, create a new Paymaster, and fill in `paymasterApiKeys` within `aaOptions` on `SmartAccount`.</p>
<p>- The Particle Network AA SDK automatically uses Biconomy's Token Paymaster (for paying gas in ERC20 tokens). Transactions that request it will be able to leverage it without additional configuration.</p>
</Tip>

## Initialization

Initializing the Particle Network AA SDK is done primarily through the `SmartAccount` object, which can be imported directly from `@particle-network/aa`. A new instance of `SmartAccount` should be saved to a variable that'll later be used either to construct a custom 1193 provider, or on its own to build and send User Operations. 

Specifically, `SmartAccount` takes the following parameters:

- `provider`, an 1193 provider to be called and used whenever specific functions are called (such as `sendTransaction`, `signMessage`, etc.); this can be `new ParticleProvider(particle.auth)` if you're using Particle Auth, otherwise, this can be any typical 1193 provider.
- Within the body of `SmartAccount`:
  - `projectId`, the `projectId` previously retrieved from the Particle dashboard.
  - `clientKey`, the `clientKey` previously retrieved from the Particle dashboard.
  - `appId`, the `appId` previously retrieved from the Particle dashboard.
  - `aaOptions`, an object containing the following:
    - `accountContracts`, an object dictating the smart account implementation(s) to be used. It can be:
      - `BICONOMY`, a [Biconomy smart account](https://www.biconomy.io/smart-accounts).
        - `version`, either `1.0.0` or `2.0.0`; both versions of Biconomy's smart account implementation are supported.
        - `chainIds`
      - `CYBERCONNECT`, a [CyberConnect smart account](https://wallet.cyber.co/).
        - `version`, currently only `1.0.0` is supported for `CYBERCONNECT`.
        - `chainIds`
      - `SIMPLE`, a [SimpleAccount implementation](https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/samples/SimpleAccount.sol).
        - `version`, either `1.0.0` or `2.0.0` is supported for `SIMPLE`.
        - `chainIds`
      - `LIGHT`, a [Light Account implementation by Alchemy](https://github.com/alchemyplatform/light-account).
        - `version`, currently only `1.0.2` is supported for `LIGHT`.
        - `chainIds`
      - `COINBASE`, a [Coinbase smart account](https://www.coinbase.com/en-br/wallet/smart-wallet).
        - `version`, currently only `1.0.0` is supported for `COINBASE`.
        - `chainIds`
  - `paymasterApiKeys`, an optional array (of objects) to be used when leveraging Biconomy's Paymaster.
    - `chainId`, the chain ID being used by the Paymaster.
    - `apiKey`, the Biconomy Paymaster API key.

Once `SmartAccount` has been initialized and assigned, you can use that assignment (`smartAccount` in this case) to call `setSmartAccountContract`, reiterating/selecting the smart account implementation choice by passing an object containing `name` (`BICONOMY`, `CYBERCONNECT`, or `SIMPLE`), and `version`.

```javascript JavaScript
import { SmartAccount } from '@particle-network/aa';
  
const smartAccount = new SmartAccount(provider, {
    projectId: 'Particle Network project ID',
    clientKey: 'Particle Network client key',
    appId: 'Particle Network app ID',
    aaOptions: {
        accountContracts: {  // 'BICONOMY', 'CYBERCONNECT', 'SIMPLE', 'LIGHT', 'COINBASE'
            BICONOMY: [
                {
                    version: '1.0.0',  
                    chainIds: [x, xx],
                },
                {  
                    version: '2.0.0',
                    chainIds: [x, xx],
                }
            ],
            CYBERCONNECT: [
                {
                    version: '1.0.0',
                    chainIds: [x, xx], 
                }
            ],
            SIMPLE: [
                {
                    version: '1.0.0',
                    chainIds: [x, xx],
                }
            ],
        },
        paymasterApiKeys: [{ // Optional
            chainId: 1,  
            apiKey: 'Biconomy Paymaster API Key',
        }]
    }, 
});

// Syntax to change the smart account implementation at any point
smartAccount.setSmartAccountContract({ name: 'BICONOMY', version: '2.0.0' });
```

## Examples of Utilization

### Get Smart Account

Once you've initialized `SmartAccount` and connected your EOA (from Particle's Wallet-as-a-Service or another wallet provider), you can retrieve the linked smart account address (according to the implementation chosen during initialization) with `smartAccount.getAddress`, the owner of that smart account (your EOA) with `smartAccount.getOwner`, and an object containing smart account information using `smartAccount.getAccount`. E.g.:

```javascript JavaScript
const address = await smartAccount.getAddress(); 
 
const address = await smartAccount.getOwner();

const accountInfo = await smartAccount.getAccount();
```

### Get Fee Quotes

Before sending transactions, if you'd like to manually retrieve fee quotes for user-paid (in native tokens), gasless, and user-paid (in ERC-20 tokens) UserOperations, all with one method call, you can use `smartAccount.getFeeQuotes`, passing in either one standard transaction object or an array with multiple (if you'd like to batch transactions). This will return an object containing UserOperation objects (and hashes) for each of the three aforementioned fee payment mechanisms, alongside fee quotes for the token Paymaster, as shown below:

```javascript JavaScript
const tx = {  
    to: '0x...',
    value: '0x...'
}

const txs = [
    {
        to: '0x...',
        value: '0x...' 
    },
    {
        to: '0x...',
        value: '0x...'
    }  
]

const feeQuotesResult = await smartAccount.getFeeQuotes(tx);
  
const gaslessUserOp = feeQuotesResult.verifyingPaymasterGasless?.userOp;  
const gaslessUserOpHash = feeQuotesResult.verifyingPaymasterGasless?.userOpHash;
  
const paidNativeUserOp = feeQuotesResult.verifyingPaymasterNative?.userOp;   
const paidNativeUserOpHash = feeQuotesResult.verifyingPaymasterNative?.userOpHash;
  
const tokenPaymasterAddress = feeQuotesResult.tokenPaymaster.tokenPaymasterAddress;
const tokenFeeQuotes = feeQuotesResult.tokenPaymaster.feeQuotes;
```

### Build UserOperation

To build a completed (ready for transaction) UserOperation object and corresponding hash, you can simply call `smartAccount.buildUserOperation`, passing in an object containing the following parameters:

- `tx`, an object, or multiple objects (in an array) representing a standard transaction structure.
- Optionally, `feeQuote`, which can be retrieved by `getFeeQuotes`, for utilizing a token Paymaster.
- Optionally, `tokenPaymasterAddress`, the `tokenPaymasterAddress` property on a result from `getFeeQuotes`.

```javascript JavaScript
const userOpBundle = await smartAccount.buildUserOperation({ tx, feeQuote, tokenPaymasterAddress }) 
const userOp = userOpBundle.userOp;  
const userOpHash = userOpBundle.userOpHash;
```

### Send UserOperation

You can send and push an (already built and complete) UserOperation to the network with `smartAccount.sendUserOperation`, which takes an object containing a `userOp` object and corresponding `userOpHash`. Both of these can be retrieved from passing a structured transaction into `buildUserOperation`, as was covered above. E.g.:

```javascript JavaScript
const txHash = await smartAccount.sendUserOperation({ userOp, userOpHash });  
```

### Wallet Deployment Flow

An undeployed smart account will automatically be deployed upon the first transaction (UserOperation) it sends through the SDK (the deployment transaction is bundled/batched with the other chosen transaction). If you'd like to initiate deployment manually, bypassing automatic deployment, then you can use `smartAccount.deployWalletContract`, which will create, request signature for, and send a deployment transaction. The status of deployment can be retrieved with `smartAccount.isDeployed`. E.g.:

```javascript JavaScript
const isDeploy = await smartAccount.isDeployed(); 
if (!isDeploy) {
    const txHash = await smartAccount.deployWalletContract();
}
```

### Custom 1193 AA Provider

Alternatively, if you'd like to plug the Particle Network AA SDK directly into Ethers or web3.js, you can do so by creating a custom 1193 provider; this will automatically route transactions through the provider and configuration defined within `SmartAccount`, converting typical transactions with Ethers, web3.js, and viem into UserOperations, handling everything on the backend.

This can be achieved by creating a new instance of `AAWrapProvider`, imported from `@particle-network/aa`. `AAWrapProvider` takes two parameters:

- `SmartAccount`, an instance of `SmartAccount`.
- `SendTransactionMode`, optionally defining the mechanism to be used for paying gas fees.
  - `SendTransactionMode` can be imported from `@particle-network/aa`, and includes:
    - `SendTransactionMode.UserPaidNative`, traditional gas payments.
    - `SendTransactionMode.Gasless`, sponsored. This will happen automatically for Testnets, and will pull from your previously defined (or configured) Paymaster for Mainnets.
    - `SendTransactionMode.UserSelect`, lets the user select which mechanism they'd like to use, including ERC-20 payments.

E.g.:

```javascript JavaScript
import { AAWrapProvider, SendTransactionMode, SendTransactionEvent } from '@particle-network/aa';
import Web3 from "web3";

const wrapProvider = new AAWrapProvider(smartAccount, SendTransactionMode.UserPaidNative);  
const web3 = new Web3(wrapProvider);  

await web3.eth.sendTransaction(tx);
  
  
const wrapProvider = new AAWrapProvider(smartAccount, SendTransactionMode.Gasless);
const web3 = new Web3(wrapProvider);
await web3.eth.sendTransaction(tx);


const wrapProvider = new AAWrapProvider(smartAccount, SendTransactionMode.UserSelect);
const web3 = new Web3(wrapProvider);
wrapProvider.once(SendTransactionEvent.Request, (feeQuotesResult) => {  
    wrapProvider.resolveSendTransaction({
        feeQuote: feeQuotesResult.tokenPaymaster.feeQuote[0],  
        tokenPaymasterAddress: feeQuotesResult.tokenPaymaster.tokenPaymasterAddress
    });

    wrapProvider.resolveSendTransaction(feeQuotesResult.verifyingPaymasterNative);
    
    if (feeQuotesResult.verifyingPaymasterGasless) {
        wrapProvider.resolveSendTransaction(feeQuotesResult.verifyingPaymasterGasless); 
    }   
});
await web3.eth.sendTransaction(tx);
```

***

## Master reference

For a direct, raw view into every method provided through `SmartAccount`, below is a table containing every relevant one alongside specific parameters and a short description. For methods listed that weren't covered in the above examples, live implementation often mimics the common structure covered throughout this document.

| Class        | Methods                 | Parameters (\* indicates optional)  |
| ------------ | ----------------------- | ----------------------------------- |
| SmartAccount | constructor             | provider, config                    |
| SmartAccount | setSmartAccountContract | contract                            |
| SmartAccount | getChainId              |                                     |
| SmartAccount | getAccountConfig        |                                     |
| SmartAccount | getPaymasterApiKey      |                                     |
| SmartAccount | getFeeQuotes            | tx                                  |
| SmartAccount | buildUserOperation      | tx, feeQuote, tokenPaymasterAddress |
| SmartAccount | signUserOperation       | userOpHash, userOp                  |
| SmartAccount | sendUserOperation       | userOpHash, userOp                  |
| SmartAccount | sendSignedUserOperation | userOp, sessionDataParams\*         |
| SmartAccount | sendTransaction         | tx, feeQuote, tokenPaymasterAddress |
| SmartAccount | getAccount              |                                     |
| SmartAccount | getAddress              |                                     |
| SmartAccount | getOwner                |                                     |
| SmartAccount | isDeployed              |                                     |
| SmartAccount | deployWalletContract    |                                     |
| SmartAccount | sendRpc                 | arg                                 |
| SmartAccount | createSessions          | options                             |
| SmartAccount | validateSession         | targetSession, sessions             |
