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
