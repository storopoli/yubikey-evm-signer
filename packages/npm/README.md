# yubikey-evm-signer

Sign Ethereum transactions, EIP-712 typed data, and EIP-191 messages using a YubiKey's PIV secp256r1 (P-256) keys for [EIP-7951](https://eips.ethereum.org/EIPS/eip-7951) verification.

[![npm version](https://badge.fury.io/js/yubikey-evm-signer.svg)](https://www.npmjs.com/package/yubikey-evm-signer)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/storopoli/yubikey-evm-signer)

## Features

- **Hardware Security**: Private keys never leave the YubiKey PIV applet
- **EIP-7951 Compatible**: Native secp256r1 (P-256) low-S ECDSA signatures (`P256VERIFY` precompile at `0x100`)
- **Cross-Browser Local PC/SC Bridge**: Works with real YubiKeys across macOS, Linux, and Windows in Chrome, Firefox, Safari, Edge, and Brave
- **Full Signing Support**: EIP-155 legacy & EIP-1559 transactions, EIP-712 typed data, EIP-191 personal messages, and raw 32-byte digests
- **Full PIV Support**: Slot selection (`9a`, `9c`, `9d`, `9e`), NIST SP 800-73-4 mutual management key auth (`AES-192`, `3DES`, `AES-128`, `AES-256`), and strict X.509 certificate parsing
- **TypeScript**: Full `.d.ts` type definitions included

## Browser & Transport Support (Chromium WebUSB Blocklist)

Standard Chromium browsers block raw WebUSB access to YubiKey PIV applets **twice** on regular web pages across all operating systems:

1. **USB Device Blocklist**: Chromium's `usb_blocklist.cc` hard-blocks Yubico VID `0x1050` (PIDs `0x0010`–`0x0410`).
2. **Protected Smart Card Interface Class**: Chromium enforces USB Smart Card class `0x0B` (CCID) as a WICG Protected Interface Class on regular `https://` and `http://localhost` pages.

| Transport | OS Support | Browser Support | Status |
|-----------|------------|-----------------|--------|
| **Local PC/SC Bridge (`connectBridge`)** | macOS, Linux, Windows | Chrome, Firefox, Safari, Edge, Brave | **Recommended** |
| **Raw WebUSB (`connect`)** | Non-blocklisted CCID tokens / Chromium Isolated Web Apps | Chromium only | Experimental |

### Running the Local PC/SC Bridge

Start the hardened loopback bridge locally (from the repository root):

```bash
just cli-bridge
# or directly:
cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- bridge --port 8765
```

The bridge binds strictly to loopback (`127.0.0.1`), validates the `Host` header (DNS rebinding defense) and exact `Origin` allowlist, requires a per-session 256-bit Bearer token checked in constant time, and enforces a strict PIV-only APDU allowlist.

## Installation

```bash
npm install yubikey-evm-signer
```

## Quick Start

```javascript
import init, { YubiKeyDevice } from 'yubikey-evm-signer';

// 1. Initialize WASM module (required once)
await init();

// 2. Connect via the hardened local PC/SC bridge
const device = await YubiKeyDevice.connectBridge(
  'http://127.0.0.1:8765',
  '<session-bearer-token>'
);

// 3. Read existing Ethereum address (non-destructive; requires a PIV certificate in the slot)
const address = await device.getAddress();
console.log('Address:', address);

// 4. Sign a personal message (EIP-191)
const signature = await device.signMessage('<your-pin>', 'Hello Ethereum!');
console.log('Signature (r || s || v):', signature);

// 5. Disconnect when done
await device.disconnect();
```

> **Warning**: Avoid calling `generateKey()` unless you intend to **permanently overwrite** any existing key in the selected PIV slot. Generating a key also requires prior management key authentication via `authenticateManagementKey()`.

## API Reference

### Module Functions

#### `init(): Promise<void>`

Initialize the WASM module. **Must be called before any other function.**

#### `isWebUsbSupported(): boolean`

Returns `true` if the current browser is in a secure context and exposes `navigator.usb`. Note that Chromium still blocks YubiKey VID `0x1050` and CCID class `0x0B` on standard web pages.

#### `getVersion(): string`

Get the library version string.

### `YubiKeyDevice` Class

#### `static connectBridge(url: string, token: string): Promise<YubiKeyDevice>`

Connect to a YubiKey via the local PC/SC loopback bridge. `url` must be a loopback HTTP URL (`http://127.0.0.1:<port>`, `http://localhost:<port>`, or `http://[::1]:<port>`).

#### `static connect(): Promise<YubiKeyDevice>`

Connect to a CCID smart card directly via WebUSB (experimental; requires a secure context and user gesture, and is blocked for YubiKey on standard Chromium pages).

#### `setSlot(slot: string): void`

Select the active PIV slot (`'9a'`, `'9c'`, `'9d'`, or `'9e'`, case-insensitive). Changing the slot invalidates any cached public key.

#### `getSlot(): string`

Return the currently active PIV slot (`'9a'`, `'9c'`, `'9d'`, or `'9e'`).

#### `authenticateManagementKey(keyHex: string, algorithm?: string): Promise<void>`

Perform NIST SP 800-73-4 mutual management key authentication (required before `generateKey()`).

- `keyHex`: raw management key as hex (with optional `0x` prefix)
- `algorithm`: `'aes192'` (default for YubiKey 5.7+), `'tdes'` (default for YubiKey `< 5.7`), `'aes128'`, or `'aes256'`

#### `verifyPin(pin: string): Promise<void>`

Verify the PIV PIN (6–8 bytes). Signing methods also validate and verify the provided PIN automatically.

#### `generateKey(pin?: string): Promise<string>`

Generate a new P-256 key pair in the active PIV slot and return its checksummed Ethereum address. Requires prior `authenticateManagementKey()`.

**Warning:** Permanently overwrites any existing key in the active slot!

#### `getAddress(): Promise<string>`

Read and strictly validate the X.509 P-256 certificate in the active slot and return its checksummed Ethereum address.

#### `signHash(pin: string, hash: string): Promise<string>`

Sign a raw 32-byte digest (`0x`-prefixed or plain 64-char hex). Returns a 65-byte low-S signature (`r || s || v`) as hex.

#### `signTransaction(pin: string, txJson: string): Promise<string>`

Sign an Ethereum EIP-155 legacy or EIP-1559 transaction JSON string. Returns a 65-byte low-S signature (`r || s || v`) as hex.

#### `signTypedData(pin: string, typedDataJson: string): Promise<string>`

Sign EIP-712 typed structured data JSON. Returns a 65-byte low-S signature (`r || s || v`) as hex.

#### `signMessage(pin: string, message: string): Promise<string>`

Sign a personal message using EIP-191 (`personal_sign`). Returns a 65-byte low-S signature (`r || s || v`) as hex.

#### `disconnect(): Promise<void>`

Disconnect from the YubiKey and clear cached session state.

#### `isConnected(): boolean`

Check whether the device transport is currently connected.

## Transaction Format

```typescript
interface AccessListEntry {
  address: string;
  storage_keys: string[];
}

interface LegacyTransaction {
  type: 'legacy';
  chain_id: number;
  nonce: number;
  gas_price: string;          // Wei as decimal or 0x hex string
  gas_limit: number;
  to?: string | null;         // 20-byte Ethereum address, or null/omitted for contract creation
  value: string;              // Wei as decimal or 0x hex string
  data?: string;              // Hex calldata (0x...), alias: `input`
  input?: string;             // Alias for `data`
}

interface Eip1559Transaction {
  type: 'eip1559';
  chain_id: number;
  nonce: number;
  max_priority_fee_per_gas: string; // Wei as decimal or 0x hex string
  max_fee_per_gas: string;          // Wei as decimal or 0x hex string
  gas_limit: number;
  to?: string | null;               // 20-byte Ethereum address, or null/omitted for contract creation
  value: string;                    // Wei as decimal or 0x hex string
  data?: string;                    // Hex calldata (0x...), alias: `input`
  input?: string;                   // Alias for `data`
  access_list?: AccessListEntry[];  // Optional, defaults to []
}

type Transaction = LegacyTransaction | Eip1559Transaction;
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

const signature = await device.signTransaction('<your-pin>', tx);
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

const signature = await device.signTypedData('<your-pin>', typedData);
```

## Error Handling

All async methods throw JavaScript `Error` objects:

| Error Message | Cause |
|---------------|-------|
| `WebUSB is not supported` | Browser lacks WebUSB or insecure context |
| `No YubiKey device found` | No device selected, cancelled, or blocked by Chromium WebUSB policy |
| `Bridge error` | Local PC/SC bridge unreachable, non-loopback URL, bad token, or blocked APDU/Origin |
| `Failed to claim interface` | Protected CCID class or device claimed by OS PC/SC driver |
| `Invalid PIN` | Wrong PIN entered (includes remaining attempts when reported) |
| `PIN is locked` | PIN locked after consecutive failed attempts |
| `Security status not satisfied` | Missing PIN, management key authentication, or touch confirmation |
| `Management key authentication failed` | Wrong management key or algorithm |
| `Invalid hash` | Malformed or non-32-byte hash hex string |
| `Invalid transaction` | Malformed transaction JSON |
| `Invalid typed data` | Malformed EIP-712 JSON |

## EIP-7951 Compatibility

This library produces low-S signatures compatible with [EIP-7951](https://eips.ethereum.org/EIPS/eip-7951), which enables native secp256r1 (P-256) signature verification on the EVM via the `P256VERIFY` precompile at address **`0x100`**.

## Development

### Building from Source

```bash
# Install wasm-pack
cargo install wasm-pack

# Build the WASM package (--no-opt required for Rust 2024 bulk-memory ops)
wasm-pack build crates/signer-wasm --target web --release --no-opt \
  --out-dir ../../packages/npm/dist --out-name yubikey_evm_signer_wasm

# Remove wasm-pack metadata files that would interfere with npm packaging
rm -f packages/npm/dist/.gitignore packages/npm/dist/package.json
```

### Running Locally

```bash
cd packages/npm
npm link
```

## License

MIT OR Apache-2.0
