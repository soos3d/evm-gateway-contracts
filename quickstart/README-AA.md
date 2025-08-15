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

### Architecture

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

#### EOA Provider Bridge
The `eoaProvider` acts as a bridge between your EOA and the AA system:
- **Signing methods** (`personal_sign`, `eth_signTypedData_v4`): Handled by EOA
- **Transaction methods** (`eth_sendTransaction`): Delegated to AA provider
- **Account queries**: Returns smart account address

#### Dual Client Architecture
```javascript
// Reading (both modes use public client)
client = createPublicClient({ chain, transport: http() });

// Writing differs:
// EOA: walletClient = client (same instance)
// AA: walletClient = custom client with AA transport
```

#### Address Handling
- **EOA Mode**: `accountAddress = account.address` (EOA address)
- **AA Mode**: `accountAddress = await getSmartAccountAddress(smartAccount)` (Smart Account address)

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
