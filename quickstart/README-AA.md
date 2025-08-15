# Circle Gateway with Particle Account Abstraction

This enhanced version of the Circle Gateway quickstart now supports **Account Abstraction (AA)** through Particle Network's AA SDK. You can run the demo with either traditional EOA (Externally Owned Account) or smart accounts.

## What's New

- **Smart Account Support**: Use Biconomy v2.0.0 smart accounts for gasless transactions
- **Dual Mode Operation**: Switch between EOA and smart account modes via environment variable
- **Automatic Deployment**: Smart accounts are automatically deployed on first transaction
- **Gasless Transactions**: Testnets support gasless transactions through Particle's paymaster

## Setup

### 1. Install Dependencies

```bash
npm install
```

The project now includes `@particle-network/aa` for Account Abstraction support.

### 2. Environment Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
# Required: Private key for the EOA that will own the smart account
PRIVATE_KEY="your-private-key-here"

# Smart Account Configuration (optional)
# Set to 'true' to enable smart account mode, 'false' or omit for EOA mode
USE_SMART_ACCOUNT=true

# Particle Network Configuration (required if USE_SMART_ACCOUNT=true)
# Get these values from https://dashboard.particle.network
PARTICLE_PROJECT_ID="your-project-id"
PARTICLE_CLIENT_KEY="your-client-key" 
PARTICLE_APP_ID="your-app-id"
```

### 3. Get Particle Network Credentials

1. Visit [Particle Dashboard](https://dashboard.particle.network)
2. Create a new project or use an existing one
3. Copy your `Project ID`, `Client Key`, and `App ID`
4. Add them to your `.env` file

## Usage

### EOA Mode (Original)

Set `USE_SMART_ACCOUNT=false` or omit it entirely:

```bash
# Run with traditional EOA
node deposit.js
node transfer.js
```

### Smart Account Mode (New)

Set `USE_SMART_ACCOUNT=true`:

```bash
# Run with smart accounts (gasless on testnets)
node deposit.js
node transfer.js
```

or

```bash
USE_SMART_ACCOUNT=true node deposit.js
USE_SMART_ACCOUNT=true node transfer.js
```

## How It Works

### Architecture Overview

The setup supports both traditional EOA and Account Abstraction modes:

#### EOA Mode (USE_SMART_ACCOUNT=false)
```
Private Key → EOA → Direct Transaction → Blockchain
               ↓
           Gas Payment Required
```
- **Signer**: EOA directly signs and sends transactions
- **Gas**: User pays gas fees in native tokens (ETH, AVAX, etc.)
- **Address**: Uses EOA address for all operations
- **Client Setup**: Single viem client handles both reading and writing

#### Account Abstraction Mode (USE_SMART_ACCOUNT=true)
```
Private Key → EOA → Smart Account → UserOperation → Bundler → Blockchain
               ↓                        ↓
           Owner/Signer            Paymaster (gasless)
```
- **Owner**: EOA owns and controls the smart account
- **Signer**: EOA signs operations on behalf of smart account
- **Executor**: Smart account executes transactions
- **Gas**: Gasless via Particle Network paymaster (testnet)
- **Address**: Uses smart account address for deposits/transfers

### Implementation Components

1. **EOA Provider**: Your private key creates an EOA that owns the smart account
2. **Smart Account**: Biconomy v2.0.0 smart account deployed deterministically
3. **AA Wrap Provider**: Particle's EIP-1193 compatible provider that routes transactions through AA
4. **Viem Integration**: Seamless integration with viem's wallet client

### Signer Instantiation

#### EOA Mode (Traditional)
```javascript
// Simple setup - account is the signer
client = createPublicClient({ chain, account, transport: http() });
walletClient = client;
accountAddress = account.address;
```

#### AA Mode (Smart Account)
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

### Transaction Signing Differences

#### EOA Mode
- **Signer**: EOA directly signs and sends transactions
- **Gas**: User pays gas fees
- **Flow**: `EOA → RPC → Blockchain`

#### AA Mode
- **Signer**: EOA signs, but Smart Account executes
- **Gas**: Gasless via Particle Network (on testnet)
- **Flow**: `EOA signs → AA Provider → Bundler → Smart Account → Blockchain`

### Key Implementation Details

#### EOA Provider Bridge (AA Mode)
The `eoaProvider` acts as a bridge between your EOA and the AA system:
- **Signing methods** (`personal_sign`, `eth_signTypedData_v4`): Handled by EOA
- **Transaction methods** (`eth_sendTransaction`): Delegated to AA provider
- **Account queries**: Returns smart account address, not EOA

#### Dual Client Architecture
- **Reading**: Both modes use `createPublicClient()` for blockchain reads
- **Writing**: 
  - EOA: Same client instance handles reads and writes
  - AA: Separate `createWalletClient()` with custom AA transport

```javascript
// Reading (both modes use public client)
client = createPublicClient({ chain, transport: http() });

// Writing differs:
// EOA: walletClient = client (same instance)
// AA: walletClient = custom client with AA transport
```

#### Contract Instances
Each chain setup returns both read and write contract instances:
- **Read contracts**: Use public client (same for both modes)
- **Write contracts**: Use wallet client (EOA client or AA client)

#### Address Handling
- **EOA Mode**: `accountAddress = account.address` (EOA address)
- **AA Mode**: `accountAddress = await getSmartAccountAddress(smartAccount)` (Smart Account address)

### Environment Configuration
- `PRIVATE_KEY`: Required - EOA private key (owner in AA mode)
- `USE_SMART_ACCOUNT`: Optional - Set to 'true' for AA mode
- `PARTICLE_PROJECT_ID`: Required for AA mode
- `PARTICLE_CLIENT_KEY`: Required for AA mode  
- `PARTICLE_APP_ID`: Required for AA mode

### Usage Examples

#### EOA Mode
```javascript
// .env: USE_SMART_ACCOUNT=false (or omit)
import { ethereum } from './setup.js';

// Same client for reads and writes
const balance = await ethereum.usdc.read.balanceOf([ethereum.accountAddress]);
const tx = await ethereum.usdcWrite.write.transfer([recipient, amount]);
```

#### AA Mode
```javascript
// .env: USE_SMART_ACCOUNT=true
import { ethereum } from './setup.js';

// Separate clients: public for reads, wallet for writes
const balance = await ethereum.usdc.read.balanceOf([ethereum.accountAddress]); // Smart account address
const tx = await ethereum.usdcWrite.write.transfer([recipient, amount]); // Gasless transaction
```

### Chain Support
- **Ethereum Sepolia** (testnet)
- **Base Sepolia** (testnet) 
- **Avalanche Fuji** (testnet)

All chains use the same Gateway contract addresses and support both EOA and AA modes.

### Transaction Flow

**EOA Mode:**
```
Private Key → EOA → Direct Transaction → Blockchain
```

**Smart Account Mode:**
```
Private Key → EOA → Smart Account → UserOperation → Bundler → Blockchain
                ↓
            Paymaster (gasless)
```

### AA Transaction Flow in Detail

1. **Contract Call**: `chain.usdcWrite.write.approve([...])`
2. **Viem**: Formats as `eth_sendTransaction`
3. **AA Transport**: Routes to `aaSetup.aaProvider.request()`
4. **Particle AA**: Bundles transaction for gasless execution
5. **Smart Account**: Executes on behalf of EOA owner

This architecture allows seamless switching between EOA and AA modes while maintaining the same contract interaction API through viem.
