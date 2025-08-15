# Circle Gateway demo with Particle Account Abstraction

This repository contains a complete Circle Gateway demo, showcasing cross-chain USDC transfers using both traditional EOA (Externally Owned Account) and Account Abstraction modes through Particle Network's AA SDK.

## Overview

The demo deposits 2 USDC into Gateway on Ethereum Sepolia, Base Sepolia and Avalanche Fuji and then transfers it instantly to Base Sepolia, demonstrating Circle's Gateway protocol capabilities with optional gasless transactions via Account Abstraction.

The flow is:

1. Deposit 2 USDC into Gateway on Ethereum Sepolia, Base Sepolia and Avalanche Fuji 
2. Wait for finalization (Avalanche: instant, Ethereum/Base: ~20 minutes)
3. Perform cross-chain transfer
4. Verify final balances

> Note how due to the AA architecture we need to delegate the EOA into the Gateway smart contract in order to perform the cross-chain transfer. This is required by the Gateway API as it needs to sign the burn intents on behalf of the smart account.

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Environment Setup

Copy the example environment file:

```bash
cp .env.example .env
```

Configure your `.env` file:

```env
# Required: Private key for EOA (or smart account owner in AA mode)
PRIVATE_KEY="your-private-key-here"

# Smart Account Configuration (optional)
USE_SMART_ACCOUNT=true  # Set to 'false' or omit for EOA mode

# Particle Network Configuration (required if USE_SMART_ACCOUNT=true)
PARTICLE_PROJECT_ID="your-project-id"
PARTICLE_CLIENT_KEY="your-client-key" 
PARTICLE_APP_ID="your-app-id"
```

### 3. Get Particle Network Credentials (AA Mode Only)

1. Visit [Particle Dashboard](https://dashboard.particle.network)
2. Create a new project or use an existing one
3. Copy your `Project ID`, `Client Key`, and `App ID`
4. Add them to your `.env` file

### 4. Fund Your Wallet

Get USDC from the [Circle Faucet](https://faucet.circle.com/) and native gas tokens for each chain (if using EOA mode).

### 5. Run the Demo

```bash
# Deposit USDC into Gateway on all chains
node deposit.js

# Wait for finalization (Avalanche: instant, Ethereum/Base: ~20 minutes)

# Perform cross-chain transfer
node transfer.js

# Check balances (optional)
node check-balances.js
```

## Operating Modes

### EOA Mode (Traditional)

```bash
# Set in .env: USE_SMART_ACCOUNT=false (or omit)
node deposit.js
node transfer.js
node check-balances.js
```

- **Gas**: User pays gas fees in native tokens
- **Address**: Uses EOA address for all operations
- **Setup**: Simple single client configuration

### Smart Account Mode (Account Abstraction)

```bash
# Set in .env: USE_SMART_ACCOUNT=true
node deposit.js
node transfer.js
node check-balances.js
```

or

```bash
USE_SMART_ACCOUNT=true node deposit.js
USE_SMART_ACCOUNT=true node transfer.js
USE_SMART_ACCOUNT=true node check-balances.js
```

- **Gas**: Gasless transactions via Particle Network paymaster (testnet)
- **Address**: Uses smart account address for deposits/transfers
- **Setup**: Dual client architecture with AA provider

## Architecture

### Directory Structure

```
quickstart/
├── config/                 # Configuration files
│   └── aa-config.js        # Account Abstraction configuration
├── lib/                    # Core libraries and utilities
│   ├── abis.js            # Contract ABIs
│   ├── gateway-client.js  # Gateway API client
│   └── typed-data.js      # EIP-712 typed data utilities
├── utils/                  # Helper utilities
│   └── aa-utils.js        # AA transaction utilities
├── deposit.js             # Main demo: Deposit USDC into Gateway
├── transfer.js            # Main demo: Cross-chain USDC transfer
├── check-balances.js      # Utility: Check balances across chains
├── setup.js               # Core setup and chain configuration
└── .env.example           # Environment configuration template
```

### Transaction Flow Comparison

**EOA Mode:**
```
Private Key → EOA → Direct Transaction → Blockchain
               ↓
           Gas Payment Required
```

**Smart Account Mode:**
```
Private Key → EOA → Smart Account → UserOperation → Bundler → Blockchain
               ↓                        ↓
           Owner/Signer            Paymaster (gasless)
```

### Implementation Components

#### EOA Mode Setup
```javascript
// Simple setup - account is the signer
client = createPublicClient({ chain, account, transport: http() });
walletClient = client;
accountAddress = account.address;
```

#### AA Mode Setup
```javascript
// 1. Create EOA provider that wraps the private key account
const eoaProvider = {
  request: async ({ method, params }) => {
    // Handles signing methods but delegates transactions
  }
};

// 2. Create smart account with EOA as owner
smartAccount = createSmartAccount(eoaProvider, chainName);
const aaSetup = createAAWalletClient(smartAccount, chain);
accountAddress = await getSmartAccountAddress(smartAccount);

// 3. Create viem wallet client with AA provider as transport
walletClient = createWalletClient({
  account: { address: accountAddress, type: 'json-rpc' },
  chain,
  transport: custom({
    request: async ({ method, params }) => {
      return await aaSetup.aaProvider.request({ method, params });
    }
  })
});
```

## Demo Scripts Deep Dive

### `deposit.js` - Funding Gateway Wallets

Deposits USDC into Gateway Wallet contracts on all supported chains.

**What it does:**
1. **Smart Account Deployment**: Automatically deploys smart accounts if needed (AA mode only)
2. **Balance Validation**: Checks USDC balance on each chain before depositing
3. **USDC Approval**: Approves Gateway Wallet contract to spend USDC
4. **Deposit Execution**: Deposits USDC into Gateway Wallet on each chain
5. **Error Handling**: Provides clear feedback for insufficient balances or gas

**Key Features:**
- Configurable amount (currently 0.5 USDC per chain)
- Multi-chain support (Ethereum Sepolia, Base Sepolia, Avalanche Fuji)
- AA retry logic with nonce management
- Transaction delays for proper synchronization

### `transfer.js` - Cross-Chain USDC Transfer

Performs cross-chain transfer using Circle's Gateway protocol.

**What it does:**
1. **Balance Verification**: Checks Gateway API balances to ensure deposits are finalized
2. **Delegation Setup**: (AA mode only) Authorizes EOA to sign on behalf of smart account
3. **Burn Intent Creation**: Creates EIP-712 signed burn intents for cross-chain transfer
4. **Gateway API Call**: Submits burn intents to Gateway API for attestation
5. **Minting**: Uses attestation to mint USDC on destination chain (Base)

**Key Features:**
- Cross-chain transfer (1 USDC each from Ethereum + Avalanche → Base)
- EIP-712 signatures for burn intents
- Delegation system for AA authorization
- Attestation flow integration with Circle's Gateway API

## Supported Chains

- **Ethereum Sepolia** (testnet)
- **Base Sepolia** (testnet) 
- **Avalanche Fuji** (testnet)

All chains use the same Gateway contract addresses and support both EOA and AA modes.

## Key Implementation Details

### Dual Client Architecture
- **Reading**: Both modes use `createPublicClient()` for blockchain reads
- **Writing**: 
  - EOA: Same client instance handles reads and writes
  - AA: Separate `createWalletClient()` with custom AA transport

### EOA Provider Bridge (AA Mode)
The `eoaProvider` acts as a bridge between your EOA and the AA system:
- **Signing methods** (`personal_sign`, `eth_signTypedData_v4`): Handled by EOA
- **Transaction methods** (`eth_sendTransaction`): Delegated to AA provider
- **Account queries**: Returns smart account address, not EOA

### Address Handling
- **EOA Mode**: Uses EOA address directly
- **AA Mode**: Uses smart account address for deposits/transfers, but EOA signs burn intents

### AA-Specific Considerations
- **Delegation Required**: EOA must be authorized as delegate for smart account
- **Signing**: EOA signs burn intents even in AA mode (Gateway API requirement)
- **Nonce Management**: Uses retry logic for proper transaction sequencing

## Complete Workflow

```bash
# 1. Fund accounts with USDC
# Visit https://faucet.circle.com

# 2. Deposit USDC into Gateway Wallets
USE_SMART_ACCOUNT=true node deposit.js

# 3. Wait for finalization 
# - Avalanche: instant
# - Ethereum/Base: ~20 minutes

# 4. Perform cross-chain transfer
USE_SMART_ACCOUNT=true node transfer.js

# 5. Verify final balances
USE_SMART_ACCOUNT=true node check-balances.js
```

## Benefits

### Code Organization
1. **Clear Separation**: Main demo scripts easily identifiable in root
2. **Organized Dependencies**: Related utilities grouped logically
3. **Maintainability**: Configuration and utilities separated from main logic
4. **Scalability**: Easy to add new utilities or configuration files
5. **User Experience**: Simple commands from root directory

### Account Abstraction Benefits
- **Gasless Transactions**: No need for native tokens on testnets
- **Automatic Deployment**: Smart accounts deployed on first transaction
- **Seamless Integration**: Same API for both EOA and AA modes
- **Enhanced UX**: Users don't need to manage gas tokens

## Troubleshooting

### Common Issues
- **Insufficient Balance**: Ensure USDC balance before deposits
- **Finalization Wait**: Ethereum/Base deposits need ~20 minutes to finalize
- **AA Nonce Issues**: Script includes retry logic for nonce management
- **Missing Credentials**: Ensure Particle Network credentials are set for AA mode

### Environment Variables
- `PRIVATE_KEY`: Required - EOA private key (owner in AA mode)
- `USE_SMART_ACCOUNT`: Optional - Set to 'true' for AA mode
- `PARTICLE_PROJECT_ID`: Required for AA mode
- `PARTICLE_CLIENT_KEY`: Required for AA mode  
- `PARTICLE_APP_ID`: Required for AA mode
