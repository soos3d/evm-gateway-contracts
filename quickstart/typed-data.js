import { randomBytes } from "node:crypto";
import { pad, zeroAddress, maxUint256 } from "viem";

///////////////////////////////////////////////////////////////////////////////
// EIP-712 typed data utils for burn intents and burn intent sets

const domain = { name: "GatewayWallet", version: "1" };

const EIP712Domain = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
];

const TransferSpec = [
  { name: "version", type: "uint32" },
  { name: "sourceDomain", type: "uint32" },
  { name: "destinationDomain", type: "uint32" },
  { name: "sourceContract", type: "bytes32" },
  { name: "destinationContract", type: "bytes32" },
  { name: "sourceToken", type: "bytes32" },
  { name: "destinationToken", type: "bytes32" },
  { name: "sourceDepositor", type: "bytes32" },
  { name: "destinationRecipient", type: "bytes32" },
  { name: "sourceSigner", type: "bytes32" },
  { name: "destinationCaller", type: "bytes32" },
  { name: "value", type: "uint256" },
  { name: "salt", type: "bytes32" },
  { name: "hookData", type: "bytes" },
];

const BurnIntent = [
  { name: "maxBlockHeight", type: "uint256" },
  { name: "maxFee", type: "uint256" },
  { name: "spec", type: "TransferSpec" },
];

const BurnIntentSet = [{ name: "intents", type: "BurnIntent[]" }];

function addressToBytes32(address) {
  return pad(address.toLowerCase(), { size: 32 });
}

export function burnIntent({ account, from, to, amount, recipient }) {
  return {
    // Needs to be at least 7 days in the future
    maxBlockHeight: maxUint256,
    // 1.01 USDC will cover the fee for any chain. In the future, there will be an estimation endpoint for this purpose.
    maxFee: 1_010000n,
    // The details of the transfer
    spec: {
      version: 1,
      sourceDomain: from.domain,
      destinationDomain: to.domain,
      sourceContract: from.gatewayWallet.address,
      destinationContract: to.gatewayMinter.address,
      sourceToken: from.usdc.address,
      destinationToken: to.usdc.address,
      sourceDepositor: account.address,
      destinationRecipient: recipient || account.address,
      sourceSigner: account.address,
      destinationCaller: zeroAddress, // Anyone can use the attestation
      value: BigInt(Math.floor(amount * 1e6)), // Convert the amount string to USDC atomic units
      salt: "0x" + randomBytes(32).toString("hex"),
      hookData: "0x", // No hook data for now
    },
  };
}

export function burnIntentTypedData(burnIntent) {
  return {
    types: { EIP712Domain, TransferSpec, BurnIntent },
    domain,
    primaryType: "BurnIntent",
    message: {
      ...burnIntent,
      spec: {
        ...burnIntent.spec,
        sourceContract: addressToBytes32(burnIntent.spec.sourceContract),
        destinationContract: addressToBytes32(burnIntent.spec.destinationContract),
        sourceToken: addressToBytes32(burnIntent.spec.sourceToken),
        destinationToken: addressToBytes32(burnIntent.spec.destinationToken),
        sourceDepositor: addressToBytes32(burnIntent.spec.sourceDepositor),
        destinationRecipient: addressToBytes32(burnIntent.spec.destinationRecipient),
        sourceSigner: addressToBytes32(burnIntent.spec.sourceSigner),
        destinationCaller: addressToBytes32(burnIntent.spec.destinationCaller ?? zeroAddress),
      },
    },
  };
}

export function burnIntentSetTypedData({ intents }) {
  return {
    types: { EIP712Domain, TransferSpec, BurnIntent, BurnIntentSet },
    domain,
    primaryType: "BurnIntentSet",
    message: {
      intents: intents.map((intent) => burnIntentTypedData(intent).message),
    },
  };
}
