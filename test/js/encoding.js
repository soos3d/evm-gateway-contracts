import {
  encodePacked,
  toHex,
  toBytes,
  pad,
  getAddress,
  hexToBytes,
  isHex
} from 'viem';

const BURN_INTENT_MAGIC = '0x070afbc2';
const BURN_INTENT_SET_MAGIC = '0xe999239b';
const TRANSFER_SPEC_MAGIC = '0xca85def7';

export function encodeBurnIntent(intent) {
  const specBytes = encodeTransferSpec(intent.spec);
  const specBytesLength = hexToBytes(specBytes).length;

  const encoded = encodePacked(
    ['bytes4', 'uint256', 'uint256', 'uint32', 'bytes'],
    [
      BURN_INTENT_MAGIC,
      intent.maxBlockHeight,
      intent.maxFee,
      specBytesLength,
      specBytes
    ]
  );

  return toHex(hexToBytes(encoded));
}

export function encodeBurnIntentSet(intentSet) {
  const numIntents = intentSet.intents.length;

  let totalSize = 0;
  const encodedIntents = [];

  for (const intent of intentSet.intents) {
    const encodedAuth = encodeBurnIntent(intent);
    const encodedBytes = hexToBytes(encodedAuth);
    encodedIntents.push(encodedBytes);
    totalSize += encodedBytes.length;
  }

  const header = encodePacked(
    ['bytes4', 'uint32'],
    [BURN_INTENT_SET_MAGIC, numIntents]
  );
  const headerBytes = hexToBytes(header);

  const result = new Uint8Array(headerBytes.length + totalSize);
  result.set(headerBytes, 0);

  let position = headerBytes.length;
  for (const intent of encodedIntents) {
    result.set(intent, position);
    position += intent.length;
  }

  return toHex(result);
}

export function encodeTransferSpec(spec) {
  const hookDataBytes = hexToBytes(spec.hookData);

  return encodePacked(
    [
      'bytes4',
      'uint32',
      'uint32',
      'uint32',
      'bytes32',
      'bytes32',
      'bytes32',
      'bytes32',
      'bytes32',
      'bytes32',
      'bytes32',
      'bytes32',
      'uint256',
      'bytes32',
      'uint32',
      'bytes'
    ],
    [
      TRANSFER_SPEC_MAGIC,
      spec.version,
      spec.sourceDomain,
      spec.destinationDomain,
      addressToBytes32(spec.sourceContract),
      addressToBytes32(spec.destinationContract),
      addressToBytes32(spec.sourceToken),
      addressToBytes32(spec.destinationToken),
      addressToBytes32(spec.sourceDepositor),
      addressToBytes32(spec.destinationRecipient),
      addressToBytes32(spec.sourceSigner),
      addressToBytes32(spec.destinationCaller),
      spec.value,
      toBytes32(spec.salt),
      hookDataBytes.length,
      spec.hookData
    ]
  );
}

export function addressToBytes32(address) {
  if (isHex(address) && address.length === 66) {
    return address;
  }

  const padded = pad(getAddress(address), { size: 32 });
  return padded;
}

export function toBytes32(input) {
  const padded = pad(toBytes(input), { size: 32 });
  return toHex(padded);
}
