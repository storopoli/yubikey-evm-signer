# yubikey-evm-signer

Sign Ethereum transactions using YubiKey's secp256r1 (P-256) keys via WebUSB.

[![npm version](https://badge.fury.io/js/yubikey-evm-signer.svg)](https://www.npmjs.com/package/yubikey-evm-signer)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Features

- **Hardware Security**: Private keys never leave the YubiKey
- **EIP-7951 Compatible**: Native secp256r1 signature verification on EVM
- **WebUSB**: Direct browser-to-YubiKey communication
- **Full Signing Support**: EIP-1559 transactions, EIP-712 typed data, EIP-191 messages
- **TypeScript**: Full type definitions included

## Browser Support

| Browser | Supported |
|---------|-----------|
| Chrome  | Yes       |
| Edge    | Yes       |
| Opera   | Yes       |
| Brave   | Yes       |
| Firefox | No        |
| Safari  | No        |

> WebUSB requires Chromium-based browsers.

## Security Requirements

- **HTTPS**: WebUSB only works in secure contexts
- **User Gesture**: Device connection must be triggered by user action (click)
- **Permission**: User must approve USB device access via browser dialog

## Installation

```bash
npm install yubikey-evm-signer
```

## Quick Start

```javascript
import init, { YubiKeyDevice, isWebUsbSupported } from 'yubikey-evm-signer';

// 1. Initialize WASM module (required once)
await init();

// 2. Check browser support
if (!isWebUsbSupported()) {
  throw new Error('WebUSB not supported');
}

// 3. Connect to YubiKey (must be in click handler)
document.getElementById('connect').onclick = async () => {
  const device = await YubiKeyDevice.connect();

  // 4. Generate key or get existing address
  const address = await device.generateKey('123456');
  console.log('Address:', address);

  // 5. Sign a message
  const signature = await device.signMessage('123456', 'Hello Ethereum!');
  console.log('Signature:', signature);

  // 6. Disconnect when done
  await device.disconnect();
};
```

## API Reference

### Module Functions

#### `init(): Promise<void>`

Initialize the WASM module. **Must be called before any other function.**

#### `isWebUsbSupported(): boolean`

Check if WebUSB is available in the current browser.

#### `getVersion(): string`

Get the library version.

### YubiKeyDevice Class

#### `static connect(): Promise<YubiKeyDevice>`

Connect to a YubiKey device. Must be called from a user gesture (click/tap).

**Throws:**

- `WebUSB is not supported` - Browser doesn't support WebUSB
- `No YubiKey device found` - User cancelled or no device available
- `Failed to open device` - USB communication error

#### `verifyPin(pin: string): Promise<void>`

Verify the PIN. Called automatically by signing methods.

**Parameters:**

- `pin` - 6-8 digit PIN string

**Throws:**

- `Invalid PIN` - Wrong PIN entered
- `PIN is locked` - Too many failed attempts (3 tries)

#### `generateKey(pin: string): Promise<string>`

Generate a new P-256 key pair in the YubiKey.

**Returns:** Checksummed Ethereum address (e.g., `0x742d35Cc6634C0532925a3b844Bc9e7595f2bD20`)

**Warning:** This overwrites any existing key in the slot!

#### `getAddress(): Promise<string>`

Get the Ethereum address for the current key.

**Returns:** Checksummed Ethereum address

#### `signHash(pin: string, hash: string): Promise<string>`

Sign a raw 32-byte hash.

**Parameters:**

- `pin` - PIN string
- `hash` - 32-byte hash as hex (with or without `0x` prefix)

**Returns:** 65-byte signature as hex (`r || s || v`)

#### `signTransaction(pin: string, txJson: string): Promise<string>`

Sign an Ethereum transaction.

**Parameters:**

- `pin` - PIN string
- `txJson` - Transaction as JSON string (see Transaction Format below)

**Returns:** 65-byte signature as hex

#### `signTypedData(pin: string, typedDataJson: string): Promise<string>`

Sign EIP-712 typed data.

**Parameters:**

- `pin` - PIN string
- `typedDataJson` - EIP-712 typed data as JSON string

**Returns:** 65-byte signature as hex

#### `signMessage(pin: string, message: string): Promise<string>`

Sign a personal message (EIP-191).

**Parameters:**

- `pin` - PIN string
- `message` - Message string (will be prefixed with `\x19Ethereum Signed Message:\n`)

**Returns:** 65-byte signature as hex

#### `disconnect(): Promise<void>`

Disconnect from the YubiKey and release USB interface.

#### `isConnected(): boolean`

Check if still connected to the device.

## Transaction Format

```typescript
interface Transaction {
  // Required
  type: 'legacy' | 'eip2930' | 'eip1559' | 'eip4844';
  chain_id: number;
  nonce: number;
  gas_limit: number;
  to: string;        // Ethereum address (0x...)
  value: string;     // Wei as decimal string
  input: string;     // Hex data (0x...)

  // Legacy & EIP-2930
  gas_price?: string;

  // EIP-1559 & EIP-4844
  max_priority_fee_per_gas?: string;
  max_fee_per_gas?: string;

  // EIP-2930, EIP-1559, EIP-4844
  access_list?: Array<{
    address: string;
    storage_keys: string[];
  }>;

  // EIP-4844 only
  max_fee_per_blob_gas?: string;
  blob_versioned_hashes?: string[];
}
```

### Example: EIP-1559 Transaction

```javascript
const tx = JSON.stringify({
  type: 'eip1559',
  chain_id: 1,
  nonce: 0,
  max_priority_fee_per_gas: '1000000000',     // 1 gwei
  max_fee_per_gas: '20000000000',             // 20 gwei
  gas_limit: 21000,
  to: '0x742d35Cc6634C0532925a3b844Bc9e7595f2bD20',
  value: '1000000000000000000',               // 1 ETH
  input: '0x'
});

const signature = await device.signTransaction(pin, tx);
```

## EIP-712 Typed Data Format

```javascript
const typedData = JSON.stringify({
  types: {
    EIP712Domain: [
      { name: 'name', type: 'string' },
      { name: 'version', type: 'string' },
      { name: 'chainId', type: 'uint256' },
      { name: 'verifyingContract', type: 'address' }
    ],
    Mail: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'contents', type: 'string' }
    ]
  },
  primaryType: 'Mail',
  domain: {
    name: 'Ether Mail',
    version: '1',
    chainId: 1,
    verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC'
  },
  message: {
    from: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
    to: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
    contents: 'Hello!'
  }
});

const signature = await device.signTypedData(pin, typedData);
```

## Error Handling

All async methods throw JavaScript `Error` objects:

```javascript
try {
  const device = await YubiKeyDevice.connect();
} catch (error) {
  switch (true) {
    case error.message.includes('WebUSB is not supported'):
      // Show browser compatibility message
      break;
    case error.message.includes('No YubiKey device found'):
      // User cancelled device selection
      break;
    case error.message.includes('Invalid PIN'):
      // Wrong PIN - warn about remaining attempts
      break;
    case error.message.includes('PIN is locked'):
      // PIN locked after 3 failed attempts
      break;
    default:
      console.error('Unexpected error:', error);
  }
}
```

### Error Types

| Error Message | Cause |
|---------------|-------|
| `WebUSB is not supported` | Browser lacks WebUSB API |
| `No YubiKey device found` | No device selected or cancelled |
| `Failed to open device` | USB permission denied |
| `Failed to claim interface` | Device in use by another app |
| `Invalid PIN` | Wrong PIN entered |
| `PIN is locked` | 3 consecutive wrong PINs |
| `Key generation failed` | Hardware error during keygen |
| `Signing failed` | Hardware error during signing |
| `Invalid transaction` | Malformed transaction JSON |
| `Invalid typed data` | Malformed EIP-712 JSON |

## EIP-7951 Compatibility

This library produces signatures compatible with [EIP-7951](https://eips.ethereum.org/EIPS/eip-7951),
which enables native secp256r1 (P-256) signature verification on the EVM via a precompile at address `0x0b`.

The signatures use the **secp256r1** curve (NIST P-256) instead of Ethereum's traditional secp256k1.

## Development

### Building from Source

```bash
# Install wasm-pack
cargo install wasm-pack

# Build the WASM package
wasm-pack build crates/signer-wasm --target web --release --out-dir ../../packages/npm/dist --out-name yubikey_evm_signer_wasm
```

### Running Locally

```bash
# Link the package locally
cd packages/npm
npm link

# In your project
npm link yubikey-evm-signer
```

## License

MIT OR Apache-2.0
