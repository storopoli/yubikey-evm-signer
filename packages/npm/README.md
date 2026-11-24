# yubikey-evm-signer

Sign Ethereum transaction hashes, EIP-712 typed data, and EIP-191 messages using a YubiKey's PIV secp256r1 (P-256) keys, for verifiers that check P-256 signatures with the [EIP-7951](https://eips.ethereum.org/EIPS/eip-7951) `P256VERIFY` precompile.

[![npm version](https://badge.fury.io/js/yubikey-evm-signer.svg)](https://www.npmjs.com/package/yubikey-evm-signer)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/storopoli/yubikey-evm-signer)

## Features

- **Hardware Security**: Private keys never leave the YubiKey PIV applet
- **EIP-7951 Compatible**: Native secp256r1 (P-256) low-S ECDSA signatures (`P256VERIFY` precompile at `0x100`)
- **Cross-Browser Local PC/SC Bridge**: Works with real YubiKeys across macOS, Linux, and Windows in Chrome, Firefox, Safari, Edge, and Brave
- **Full Signing Support**: EIP-155 legacy & EIP-1559 transactions, EIP-712 typed data, EIP-191 personal messages, and raw 32-byte digests
- **Full PIV Support**: Slot selection (`9a`, `9c`, `9d`, `9e`), NIST SP 800-73-4 mutual management key auth (`AES-192`, `3DES`, `AES-128`, `AES-256`), public key lookup from slot metadata (firmware 5.3+) with strict X.509 certificate fallback
- **TypeScript**: Full `.d.ts` type definitions included

## Addresses, accounts, and who can verify these signatures

> **Warning**: The address derived from a YubiKey P-256 key is not an Ethereum account you can spend from. Do not send ETH or tokens to it on Ethereum mainnet or any other chain that validates transactions with secp256k1: no key you hold can sign for that address there, so anything sent to it cannot be recovered.

The YubiKey holds a P-256 (secp256r1) key. `getAddress()` and `generateKey()` return `keccak256(X‖Y)[12..]` of its public key, computed the way Ethereum derives an address from a secp256k1 key. It is a stable identifier of the P-256 key, not a secp256k1 externally owned account (EOA).

Ethereum mainnet and standard EVM chains validate transaction signatures with secp256k1 `ecrecover`. EIP-7951 does not change that; it adds the `P256VERIFY` precompile that contracts can call to verify P-256 signatures. As a result:

- A transaction signed with `signTransaction()` is not accepted by a standard node as a transaction from the derived address.
- `P256VERIFY` takes the public key `(qx, qy)` as input. Neither the signature nor the transaction carries it, so a verifier must already know it.

The signatures are meant for verifiers that call `P256VERIFY` with a known public key: smart accounts (for example ERC-4337 accounts with P-256 signature validation), contracts implementing ERC-1271 `isValidSignature`, or chains that validate transactions with P-256 natively. Register the public key with your verifier and use it, not the derived address, to identify the signer: `getPublicKey()` returns it as `0x04‖X‖Y` (65 bytes, hex), where `X` and `Y` are the `qx` and `qy` inputs of `P256VERIFY`.

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

The bridge prints its URL (`http://127.0.0.1:<port>`) and a random 256-bit bearer token, which stays valid until the bridge process stops. It binds only to `127.0.0.1` and accepts only requests whose `Host` is exactly `127.0.0.1:<port>` (`localhost` and `[::1]` are rejected; port `80` is refused because browsers omit it from `Host`), requires an exact `Origin` from its allowlist and the bearer token (checked in constant time), and forwards only allowlisted PIV commands, each as one PC/SC transaction.

- `--allow-origin <origin>` adds an allowed page origin (repeatable). The defaults are `http://localhost:8000`, `http://127.0.0.1:8000`, and `https://storopoli.github.io`.
- `--allow-generate` permits management key authentication, key generation, and certificate deletion. Without it, `authenticateManagementKey()` fails with a `403` error that names the flag, so `generateKey()` cannot be used.
- `--idle-timeout <seconds>` (default `120`) closes an idle YubiKey session and resets the card; the next call then fails with a `Disconnected:` error and you must connect again.
- Ctrl+C or SIGTERM stops the bridge gracefully, closing the session and resetting the card.

See the [repository README](https://github.com/storopoli/yubikey-evm-signer#local-pcsc-bridge) for the APDU allowlist and HTTP protocol.

## Installation

```bash
npm install yubikey-evm-signer
```

## Quick Start

```javascript
import init, { YubiKeyDevice } from 'yubikey-evm-signer';

// 1. Initialize WASM module (required once)
await init();

// 2. Connect via the hardened local PC/SC bridge (only http://127.0.0.1:<port>)
const device = await YubiKeyDevice.connectBridge(
  'http://127.0.0.1:8765',
  '<bearer-token-printed-by-the-bridge>'
);

// 3. Read the slot's P-256 public key (register it with your verifier) and its
//    derived address identifier (not a secp256k1 account); both are read-only
const publicKey = await device.getPublicKey();
const address = await device.getAddress();
console.log('Public key (0x04 || X || Y):', publicKey);
console.log('Derived address:', address);

// 4. Sign a personal message (EIP-191)
const signature = await device.signMessage('<your-pin>', 'Hello Ethereum!');
console.log('Signature (r || s || v):', signature);

// 5. Disconnect when done
await device.disconnect();
```

Await each call before starting the next one: a `YubiKeyDevice` handles one call at a time (see [Usage rules](#usage-rules)).

> **Warning**: Avoid calling `generateKey()` unless you intend to **permanently overwrite** any existing key in the selected PIV slot. Generating a key also requires prior management key authentication via `authenticateManagementKey()` and, over the bridge, a bridge started with `--allow-generate`.

## Usage rules

- **One call at a time.** A `YubiKeyDevice` handles one call at a time. While a call is pending (for example a signature waiting for a touch), any other call on the same object, including `getSlot()`, `setSlot()`, `hasStaleCertificate()`, and `isConnected()`, throws synchronously with `recursive use of an object detected which would lead to unsafe aliasing in rust`; the pending call is unaffected. Await each call, or route all calls through one queue.
- **Lost sessions.** When a call fails with an error starting with `Disconnected:` or with the card-reset error (`YubiKey was reset by another application; …`), the device discards its verified PIN, management key authentication, and cached public key, and `isConnected()` returns `false`. Create a new device with `connectBridge()` or `connect()` to continue.
- **PINs.** Prompt for the PIN at runtime and pass it to each signing call; never hardcode it or keep it in browser storage.

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

Connect to a YubiKey via the local PC/SC loopback bridge and select the PIV applet.

- `url`: must be `http://127.0.0.1:<port>` (an optional trailing `/` is allowed). `localhost`, `[::1]`, `https://`, other hosts, port `80` (browsers omit it from the `Host` header the bridge checks), and URLs with a path, query, or credentials are rejected before any request is sent.
- `token`: the bearer token printed by `yubikey-cli bridge`, at least 32 visible ASCII characters with no spaces (surrounding whitespace is ignored).

If the bridge cannot be reached, the error says so and suggests restarting the bridge with `--allow-origin <origin>` for this page's origin: a bridge that refuses the page's origin answers without CORS headers, so the browser reports it exactly like a bridge that is not running.

#### `static connect(): Promise<YubiKeyDevice>`

Connect to a CCID smart card directly via WebUSB (experimental; requires a secure context and user gesture, and is blocked for YubiKey on standard Chromium pages).

#### `setSlot(slot: string): void`

Select the active PIV slot (`'9a'`, `'9c'`, `'9d'`, or `'9e'`, case-insensitive). Changing the slot invalidates the cached public key and resets `hasStaleCertificate()`.

#### `getSlot(): string`

Return the currently active PIV slot (`'9a'`, `'9c'`, `'9d'`, or `'9e'`).

#### `authenticateManagementKey(keyHex: string, algorithm?: string): Promise<void>`

Perform NIST SP 800-73-4 mutual management key authentication (required before `generateKey()`). Over the bridge this requires `yubikey-cli bridge --allow-generate`.

- `keyHex`: raw management key as hex (with optional `0x` prefix)
- `algorithm`: `'aes192'` (default for YubiKey 5.7+), `'tdes'` (default for YubiKey `< 5.7`), `'aes128'`, or `'aes256'`

#### `verifyPin(pin: string): Promise<void>`

Verify the PIV PIN (6–8 bytes). Signing methods verify the PIN they are given themselves, so calling this first is not required.

#### `generateKey(pin?: string): Promise<string>`

Generate a new P-256 key pair in the active PIV slot and return the checksummed address identifier of the new key (not a secp256k1 account; use `getPublicKey()` for the key itself). Requires prior `authenticateManagementKey()`; a non-empty `pin` is verified first.

After generating the key, the slot's certificate, which described the destroyed key, is deleted. If that deletion fails, the call still succeeds with the new key and `hasStaleCertificate()` returns `true`; remove or replace the old certificate before any other software relies on it.

**Warning:** Permanently overwrites any existing key in the active slot!

#### `getAddress(): Promise<string>`

Return the checksummed address identifier, `keccak256(X‖Y)[12..]`, of the P-256 key in the active slot. It is not a secp256k1 account (see [Addresses, accounts, and who can verify these signatures](#addresses-accounts-and-who-can-verify-these-signatures)).

The key is read from the YubiKey's slot metadata on firmware 5.3 and newer, which always describes the key currently in the slot. The slot's X.509 certificate is used only when metadata is unavailable (older firmware), and is then parsed and validated strictly. A certificate holding a different key is ignored and reported by `hasStaleCertificate()`. The key is cached until the slot changes or the session ends. Throws if the slot holds no key or a non-P-256 key, or, without metadata, has no certificate with a P-256 key.

#### `getPublicKey(): Promise<string>`

Return the P-256 public key of the active slot as uncompressed SEC1 hex, `0x04‖X‖Y` (65 bytes, lowercase, `0x`-prefixed). `X` and `Y` are the `qx` and `qy` inputs of `P256VERIFY`. Uses the same lookup and cache as `getAddress()`.

#### `hasStaleCertificate(): boolean`

Return `true` if the active slot's certificate is known not to describe the slot's key: the last `getAddress()` / `getPublicKey()` lookup found a certificate with a different (or unreadable) key, or the last `generateKey()` could not delete the old certificate. The returned address and public key always describe the actual key. Returns `false` before any lookup, after `setSlot()` changes the slot, and whenever no stale certificate was found. Without slot metadata (firmware older than 5.3), a lookup cannot detect a stale certificate.

#### `signHash(pin: string, hash: string): Promise<string>`

Sign a raw 32-byte digest (`0x`-prefixed or plain 64-char hex). Returns a 65-byte low-S signature (`r || s || v`) as `0x`-prefixed hex, where `v` is the P-256 recovery parameter.

All signing methods first read (or reuse the cached) public key of the slot, so a slot without a usable key fails before a PIN attempt is spent. They then verify the PIN when the slot requires one (every slot except `9e`) or a non-empty PIN is given, and sign immediately afterwards. Because `VERIFY` directly precedes the signature, slot `9c`, which requires the PIN for every signature, works without extra steps.

#### `signTransaction(pin: string, txJson: string): Promise<string>`

Sign the signing hash of an EIP-155 legacy or EIP-1559 transaction given as JSON (see [Transaction Format](#transaction-format)). Returns a 65-byte low-S signature (`r || s || v`) as hex. This is a P-256 signature for EIP-7951 verifiers; standard EVM nodes do not accept it as a transaction signature.

#### `signTypedData(pin: string, typedDataJson: string): Promise<string>`

Sign EIP-712 typed structured data JSON (see [EIP-712 Typed Data Format](#eip-712-typed-data-format)). Returns a 65-byte low-S signature (`r || s || v`) as hex.

#### `signMessage(pin: string, message: string): Promise<string>`

Sign a personal message using EIP-191 (`personal_sign`). Returns a 65-byte low-S signature (`r || s || v`) as hex.

#### `disconnect(): Promise<void>`

Disconnect from the YubiKey (over the bridge, this ends the bridge session, which resets the card) and clear the cached PIN, management key, and public key state.

#### `isConnected(): boolean`

Check whether the device transport is currently connected. Becomes `false` after `disconnect()`, after a session-ending error (see [Usage rules](#usage-rules)), and, for WebUSB, when the browser reports the YubiKey unplugged.

## Transaction Format

```typescript
// Wei amounts: a decimal digit string, a 0x/0X hex string, or a JSON unsigned
// integer (use strings for values above Number.MAX_SAFE_INTEGER).
type Wei = string | number;

interface AccessListEntry {
  address: string;
  storage_keys: string[];       // 32-byte hex strings
}

interface LegacyTransaction {
  type: 'legacy';
  chain_id: number;             // Must be non-zero
  nonce: number;
  gas_price: Wei;
  gas_limit: number;
  to: string | null;            // Required: 20-byte address, or null for contract creation
  value: Wei;
  data?: string;                // Hex calldata (0x...), alias: `input`
  input?: string;               // Alias for `data`
}

interface Eip1559Transaction {
  type: 'eip1559';
  chain_id: number;             // Must be non-zero
  nonce: number;
  max_priority_fee_per_gas: Wei;
  max_fee_per_gas: Wei;
  gas_limit: number;
  to: string | null;            // Required: 20-byte address, or null for contract creation
  value: Wei;
  data?: string;                // Hex calldata (0x...), alias: `input`
  input?: string;               // Alias for `data`
  access_list?: AccessListEntry[]; // Optional, defaults to []
}

type Transaction = LegacyTransaction | Eip1559Transaction;
```

Parsing is strict and fails with `Invalid transaction: …`:

- Unknown keys are rejected, including camelCase spellings such as `accessList` or `chainId` and unknown keys inside access-list entries.
- `to` must be present; omitting it is an error. Use `null` for contract creation.
- Amounts with signs, whitespace, separators, decimals, or other prefixes are rejected.
- `chain_id: 0` is rejected.

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

Typed data is validated strictly and fails with `Invalid typed data: …`:

- `domain` accepts only `name`, `version`, `chainId`, `verifyingContract`, and `salt`. `chainId` is an unsigned integer, decimal string, or `0x` hex string; `salt` must be `0x` followed by exactly 32 bytes of hex.
- If `types.EIP712Domain` is declared, it may only list those standard fields with their standard types (`string`, `string`, `uint256`, `address`, `bytes32`), and it must declare every field that is set in `domain`.
- Type names and field names must be identifiers (`[A-Za-z_$][A-Za-z0-9_$]*`), field names must be unique within a type, and a type may not be named after a primitive type such as `address` or `uint256`.
- `bytesN` values must be `0x` followed by exactly N bytes of hex; `bytes` values must start with `0x`.
- A message may be nested at most 64 levels deep (each nested struct and each array dimension adds a level).

## Error Handling

Methods throw JavaScript `Error` objects (async methods reject). The message starts with one of these prefixes; `…` stands for details:

| Error message | Cause |
|---------------|-------|
| `WebUSB is not supported in this browser or requires a secure context (HTTPS/localhost)` | `connect()` without WebUSB or outside a secure context |
| `No YubiKey device found (note: …)` | No device selected, selection cancelled, or blocked by Chromium's WebUSB policy |
| `Failed to open device: …` / `Failed to claim interface: …` / `USB error: …` | WebUSB could not open or claim the device (for example the protected CCID class or the OS smart card driver), or another WebUSB call failed |
| `Bridge error: Bridge URL must be http://127.0.0.1:<port> with a port other than 80 (localhost and [::1] are not accepted)` | `connectBridge()` URL rejected before any request |
| `Bridge error: Bridge bearer token must be at least 32 visible ASCII characters …` | `connectBridge()` token rejected before any request |
| `Bridge error: Failed to reach the local PC/SC bridge at …` | The bridge is not running, or it does not allow this page's origin; the message names the `yubikey-cli bridge --allow-origin <origin>` command to use |
| `Bridge error: Bridge authentication failed (401 Unauthorized): …` | Wrong bearer token |
| `Bridge error: Bridge refused the request (403 Forbidden): …` | The bridge refused a command. Key generation commands without `--allow-generate` get a message naming that flag |
| `Bridge error: Bridge found no YubiKey (404): …` | No YubiKey available to the local PC/SC daemon |
| `Bridge error: Bridge timed out reading the request (408 Request Timeout): …` | The request did not reach the bridge in time; retry |
| `Bridge error: Bridge rejected an oversized request (413 Payload Too Large): …` / `Bridge error: Bridge request failed (HTTP …): …` | Other bridge HTTP errors |
| `Disconnected: bridge session ended (409 Conflict): …` | The bridge session expired after the idle timeout, was replaced by another connection, or was closed because another PC/SC client reset the card. Ends the session |
| `Disconnected: bridge lost the YubiKey or is shutting down (503 Service Unavailable): …` | YubiKey or reader removed, or the bridge is stopping. Ends the session |
| `Disconnected: …` (other) | The YubiKey was unplugged, the session was already closed, or the WebUSB connection was closed after an unrecoverable CCID error or timeout. Ends the session |
| `YubiKey was reset by another application; reconnect and verify the PIN again` | Another PC/SC client reset the card. Ends the session |
| `Failed to select PIV applet: …` | `connect()` could not select the PIV applet |
| `PIN verification required before this operation` | The operation needs a verified PIN |
| `Invalid PIN (N attempts remaining)` / `Invalid PIN` | Wrong PIN, or a PIN outside 6–8 bytes |
| `PIN is locked` | PIN locked after consecutive failed attempts |
| `Security status not satisfied (PIN, management key authentication, or touch confirmation required)` | Missing PIN verification, management key authentication, or touch confirmation |
| `Management key authentication failed` | Wrong management key, key length, or algorithm |
| `Invalid PIV slot '…' (expected one of: 9a, 9c, 9d, 9e)` | Bad `setSlot()` argument |
| `Key generation failed: …` | The card rejected or returned an invalid response to key generation |
| `Signing failed: …` | The card returned an invalid signature response |
| `Invalid hash: …` | Malformed or non-32-byte hash hex string |
| `Invalid transaction: …` | Transaction JSON rejected (see [Transaction Format](#transaction-format)) |
| `Invalid typed data: …` | EIP-712 JSON rejected (see [EIP-712 Typed Data Format](#eip-712-typed-data-format)) |
| `Core error: …` | Other library errors, such as an empty slot (`PIV slot 0x9a is empty`) or a non-P-256 key |
| `JavaScript error: …` | A browser API threw |
| `recursive use of an object detected which would lead to unsafe aliasing in rust` | A call was made while another call on the same `YubiKeyDevice` was pending (thrown by wasm-bindgen) |

Errors marked "Ends the session" clear the device's PIN, management key, and cached key state and make `isConnected()` return `false`; connect again to continue.

## EIP-7951 Compatibility

This library produces low-S signatures compatible with [EIP-7951](https://eips.ethereum.org/EIPS/eip-7951), which enables native secp256r1 (P-256) signature verification on the EVM via the `P256VERIFY` precompile at address **`0x100`**. The precompile takes the message hash, `r`, `s`, and the public key (`qx`, `qy` from `getPublicKey()`); it does not use `v`.

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

# Copy the license files into the package (`just npm-licenses`)
cp LICENSE-MIT LICENSE-APACHE packages/npm/

# Check the package layout and exported API
node scripts/verify-demo.mjs --check-wasm
```

`just wasm-build-release` runs these steps except the final check.

### Running Locally

```bash
cd packages/npm
npm link
```

## License

MIT OR Apache-2.0
