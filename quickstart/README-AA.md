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

## How It Works

### Architecture

1. **EOA Provider**: Your private key creates an EOA that owns the smart account
2. **Smart Account**: Biconomy v2.0.0 smart account deployed deterministically
3. **AA Wrap Provider**: Particle's EIP-1193 compatible provider that routes transactions through AA
4. **Viem Integration**: Seamless integration with viem's wallet client

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

### Key Features

- **Gasless Transactions**: All testnet transactions are sponsored automatically
- **Automatic Deployment**: Smart accounts deploy on first transaction
- **Seamless Integration**: Same API as EOA mode, just with different underlying mechanics
- **Dual Address Support**: Tracks both EOA address (owner) and smart account address

## Files Modified

- **`aa-config.js`**: New configuration module for Particle AA SDK
- **`setup.js`**: Enhanced to support both EOA and AA modes
- **`deposit.js`**: Updated to work with smart accounts and handle deployment
- **`transfer.js`**: Modified to use correct account addresses for balances and recipients
- **`.env.example`**: Added Particle Network configuration variables

## Smart Account Benefits

1. **Gasless Experience**: Users don't need native tokens for gas on testnets
2. **Batch Transactions**: Multiple operations in a single UserOperation
3. **Advanced Security**: Programmable validation logic
4. **Recovery Options**: Social recovery and other advanced features
5. **Sponsored Transactions**: Dapps can sponsor user transactions

## Troubleshooting

### Common Issues

1. **Missing Particle Credentials**: Ensure all three Particle variables are set in `.env`
2. **Network Mismatch**: Verify chain IDs match between Particle dashboard and code
3. **Deployment Failures**: Smart accounts auto-deploy, but check gas availability for EOA
4. **Balance Checks**: Smart account addresses differ from EOA addresses

### Debug Mode

Add logging to see which mode is active:

```javascript
console.log(`Smart Account mode: ${USE_SMART_ACCOUNT ? 'ENABLED' : 'DISABLED'}`);
console.log(`Account address: ${chain.accountAddress}`);
console.log(`EOA address: ${account.address}`);
```

## Advanced Configuration

### Custom Smart Account Types

Modify `aa-config.js` to use different smart account implementations:

```javascript
accountContracts: {
  SIMPLE: [{ version: '1.0.0', chainIds: [chainId] }],
  LIGHT: [{ version: '1.0.2', chainIds: [chainId] }],
  COINBASE: [{ version: '1.0.0', chainIds: [chainId] }]
}
```

### Custom Paymaster

For mainnet usage, configure custom paymasters:

```javascript
paymasterApiKeys: [{
  chainId: 1,
  apiKey: 'your-biconomy-paymaster-key'
}]
```

## Next Steps

- Explore batch transactions for multiple operations
- Implement session keys for enhanced UX
- Add social recovery features
- Integrate with other AA infrastructure providers
