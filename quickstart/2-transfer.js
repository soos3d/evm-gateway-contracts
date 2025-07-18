import { account, ethereum, base, avalanche } from "./setup.js";
import { GatewayClient } from "./gateway-client.js";
import { burnIntent, burnIntentTypedData } from "./typed-data.js";

// Initialize a lightweight API client for interacting with Gateway
const gatewayClient = new GatewayClient();

// Check the info endpoint to confirm which chains are supported
// Not necessary for the transfer, but useful information
console.log("Fetching Gateway API info...");
const info = await gatewayClient.info();
for (const domain of info.domains) {
  console.log(
    `  - ${domain.chain} ${domain.network}`,
    `(wallet: ${"walletContract" in domain}, minter: ${"minterContract" in domain})`,
  );
}

// Check the account's balances with the Gateway API
console.log(`Checking balances...`);
const { balances } = await gatewayClient.balances("USDC", account.address);
for (const balance of balances) {
  console.log(`  - ${GatewayClient.CHAINS[balance.domain]}:`, `${balance.balance} USDC`);
}

// These are the amounts we intent on transferring from each chain we deposited on
const fromEthereumAmount = 2;
const fromAvalancheAmount = 3;

// Check to see if Gateway has picked up the Avalanche deposit yet
// Since Avalanche has instant finality, this should be quick
const avalancheBalance = balances.find((b) => b.domain === GatewayClient.DOMAINS.avalanche).balance;
if (parseFloat(avalancheBalance) < fromAvalancheAmount) {
  console.error("Gateway deposit not yet picked up on Avalanche, wait until finalization");
  process.exit(1);
} else {
  console.error("Gateway deposit picked up on Avalanche!");
}

// Check to see if Gateway has picked up the Ethereum deposit yet
// Ethereum takes about 20 minutes to finalize blocks, so you may need to wait a bit
const ethereumBalance = balances.find((b) => b.domain === GatewayClient.DOMAINS.ethereum).balance;
if (parseFloat(ethereumBalance) < fromEthereumAmount) {
  console.error("Gateway deposit not yet picked up on Ethereum, wait until finalization");
  process.exit(1);
} else {
  console.error("Gateway deposit picked up on Ethereum!");
}

// Construct the burn intents
console.log("Constructing burn intent set...");
const burnIntents = [
  burnIntent({
    account,
    from: ethereum,
    to: base,
    amount: fromEthereumAmount,
    recipient: account.address,
  }),
  burnIntent({
    account,
    from: avalanche,
    to: base,
    amount: fromAvalancheAmount,
    recipient: account.address,
  }),
];

// Sign the burn intents
console.log("Signing burn intents...");
const request = await Promise.all(
  burnIntents.map(async (intent) => {
    const typedData = burnIntentTypedData(intent);
    const signature = await account.signTypedData(typedData);
    return { burnIntent: typedData.message, signature };
  }),
);

// Request the attestation
console.log("Requesting attestation from Gateway API...");
const start = performance.now();
const response = await gatewayClient.transfer(request);
const end = performance.now();
if (response.success === false) {
  console.error("Error from Gateway API:", response.message);
  process.exit(1);
}
console.log("Received attestation from Gateway API in", (end - start).toFixed(2), "ms");

// Mint the funds on Base
console.log("Minting funds on Base...");
const { attestation, signature } = response;
const mintTx = await base.gatewayMinter.write.gatewayMint([attestation, signature]);
await base.client.waitForTransactionReceipt({ hash: mintTx });
console.log("Done! Transaction hash:", mintTx);
process.exit(0);
