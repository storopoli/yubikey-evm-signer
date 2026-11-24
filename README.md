# YubiKey EVM Signer

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache-blue.svg)](https://opensource.org/licenses/apache-2-0)
[![ci](https://github.com/storopoli/yubikey-evm-signer/actions/workflows/lint.yml/badge.svg?event=push)](https://github.com/storopoli/yubikey-evm-signer/actions)

| Crate | crates.io | docs.rs |
|-------|-----------|---------|
| yubikey-evm-signer-core | [![crates.io](https://img.shields.io/crates/v/yubikey-evm-signer-core.svg)](https://crates.io/crates/yubikey-evm-signer-core) | [![docs.rs](https://docs.rs/yubikey-evm-signer-core/badge.svg)](https://docs.rs/yubikey-evm-signer-core) |
| yubikey-evm-signer-wasm | [![crates.io](https://img.shields.io/crates/v/yubikey-evm-signer-wasm.svg)](https://crates.io/crates/yubikey-evm-signer-wasm) | [![docs.rs](https://docs.rs/yubikey-evm-signer-wasm/badge.svg)](https://docs.rs/yubikey-evm-signer-wasm) |

| Package | npm |
|---------|-----|
| yubikey-evm-signer | [![npm](https://img.shields.io/npm/v/yubikey-evm-signer.svg)](https://www.npmjs.com/package/yubikey-evm-signer) |

Sign Ethereum transaction hashes, EIP-712 typed structured data, EIP-191 personal messages, and raw 32-byte hashes using a YubiKey's PIV applet with secp256r1 (P-256) ECDSA, for verifiers that check P-256 signatures (see [the section below](#addresses-accounts-and-who-can-verify-these-signatures) before using the derived address). Signatures target [EIP-7951](https://eips.ethereum.org/EIPS/eip-7951), which adds native secp256r1 verification on the EVM through the `P256VERIFY` precompile at address `0x100`. The verifier passes all 781 EIP-7951 test vectors.

Private keys never leave the YubiKey hardware. The signer supports EIP-155 legacy and EIP-1559 transactions, normalizes every signature to low-S form, and computes the P-256 recovery ID (`v`).

## Addresses, accounts, and who can verify these signatures

> [!WARNING]
> The address derived from a YubiKey P-256 key is not an Ethereum account you can spend from. Do not send ETH or tokens to it on Ethereum mainnet or any other chain that validates transactions with secp256k1: no key you hold can sign for that address there, so anything sent to it cannot be recovered.

The YubiKey holds a P-256 (secp256r1) key. The "address" this project shows for it is computed the way Ethereum derives an address from a secp256k1 key, `keccak256(X‖Y)[12..]` of the public key, and serves as a stable identifier of the P-256 key. It is not a secp256k1 externally owned account (EOA).

Ethereum mainnet and standard EVM chains validate transaction signatures with secp256k1 `ecrecover`. EIP-7951 does not change that; it adds the `P256VERIFY` precompile that contracts can call to verify P-256 signatures. As a result:

- A legacy or EIP-1559 transaction signed here (`signTransaction`, `signed_rlp`, `yubikey-cli sign-tx`) is not accepted by a standard node as a transaction from the derived address.
- `P256VERIFY` takes the public key `(qx, qy)` as input. Neither the signature nor the transaction carries it, so a verifier must already know it.

The signatures are meant for verifiers that call `P256VERIFY` with a known public key: smart accounts (for example ERC-4337 accounts with P-256 signature validation), contracts implementing ERC-1271 `isValidSignature`, or chains that validate transactions with P-256 natively. Register the public key with your verifier and use that key, not the derived address, to identify the signer. In JavaScript, `getPublicKey()` returns it as `0x04‖X‖Y` (65 bytes); `yubikey-cli address` prints the same uncompressed public key.

## Rust usage

Use `yubikey-evm-signer-core` to build Ethereum signing payloads, hash messages, and drive PIV sessions from Rust:

```rust
use yubikey_evm_signer_core::{
    Address, Eip1559Transaction, Result, Transaction, U256, eip191_hash,
};

fn main() -> Result<()> {
    let tx = Transaction::Eip1559(Eip1559Transaction {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: U256::from(1_000_000_000u64),
        max_fee_per_gas: U256::from(100_000_000_000u64),
        gas_limit: 21000,
        to: Some(Address::zero()),
        value: U256::from(1_000_000_000_000_000_000u128),
        data: vec![],
        access_list: vec![],
    });

    // Fails with `Error::InvalidChainId` when `chain_id` is 0
    let tx_hash = tx.signing_hash()?;
    let msg_hash = eip191_hash(b"Hello, Ethereum!");
    Ok(())
}
```

Transaction and EIP-712 input is validated strictly: input that does not follow the rules in [Input formats](#input-formats) is rejected by `Transaction::from_json` / `TypedData::from_json` or, at the latest, by `signing_hash()`. The workspace requires Rust 1.90 or newer.

Enable the optional `pcsc` feature for native smart card access through `yubikey::PcscTransport` and the `yubikey-cli` example. `PivSession::exclusive` runs a sequence of PIV operations (for example select, verify PIN, sign) as one PC/SC transaction, and `PivSession::get_slot_public_key` reads a slot's key from the YubiKey's slot metadata (firmware 5.3+), falling back to the slot certificate on older firmware. On non-WASM targets, the crate also includes the `bridge` module (`BridgeConfig`, `BridgeServer`, and `validate_bridge_apdu`) for running the local loopback HTTP bridge over any `Transport`.

The `yubikey-evm-signer-wasm` crate uses unstable `web-sys` WebUSB APIs, so every build that compiles it, including a project that depends on it from crates.io, must pass `--cfg=web_sys_unstable_apis` to `rustc`. Add this to the depending project's `.cargo/config.toml` (or include the flag in `RUSTFLAGS`, which replaces these settings when set):

```toml
[build]
rustflags = ["--cfg=web_sys_unstable_apis"]

[target.wasm32-unknown-unknown]
rustflags = ["--cfg=web_sys_unstable_apis"]
```

## Browser and JavaScript usage

Install the `yubikey-evm-signer` npm package or try the live demo at [storopoli.github.io/yubikey-evm-signer](https://storopoli.github.io/yubikey-evm-signer/). The full JavaScript API reference is in [`packages/npm/README.md`](packages/npm/README.md).

Chromium blocks raw WebUSB access to YubiKey PIV applets on standard web pages across all operating systems. Yubico's vendor ID (`0x1050`) is listed in Chromium's `usb_blocklist.cc` and the WICG `blocklist.txt`, and Chromium restricts USB Smart Card (CCID, class `0x0B`) interfaces as a protected interface class.

Connect through the local PC/SC bridge instead. Start the bridge locally with `just cli-bridge`, then pass the printed URL and bearer token to `YubiKeyDevice.connectBridge(url, token)`. The URL must be exactly `http://127.0.0.1:<port>`; `localhost`, `[::1]`, and port `80` are rejected. Because native PC/SC handles smart card communication, the bridge works in Chrome, Firefox, Safari, Edge, and Brave on macOS, Linux, and Windows. See [Local PC/SC bridge](#local-pcsc-bridge) for its security controls and protocol.

```javascript
import init, { YubiKeyDevice } from "yubikey-evm-signer";

await init();

// Start the local PC/SC bridge first with `just cli-bridge`
const device = await YubiKeyDevice.connectBridge(
    "http://127.0.0.1:8765",
    "<BEARER_TOKEN_PRINTED_BY_THE_BRIDGE>"
);

// The slot 9a P-256 public key (0x04 || X || Y) to register with your verifier,
// and its keccak256-derived address identifier (not a secp256k1 account)
const publicKey = await device.getPublicKey();
const address = await device.getAddress();

// Prompt the user for their PIN at runtime; never hardcode credentials
const pin = "<PIN_FROM_USER_INPUT>";
const signature = await device.signTransaction(pin, JSON.stringify({
    type: "eip1559",
    chain_id: 1,
    nonce: 0,
    max_priority_fee_per_gas: "1000000000",
    max_fee_per_gas: "20000000000",
    gas_limit: 21000,
    to: "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD20",
    value: "1000000000000000000",
    input: "0x"
}));

await device.disconnect();
```

A `YubiKeyDevice` handles one call at a time: await each call before starting the next, or the second call throws. If a call fails because the session or device is gone (an error starting with `Disconnected:`, or the card-reset error; over the bridge this includes a bridge that stopped answering or was restarted with a new token), the device discards its PIN and management key state, `isConnected()` returns `false`, and you must connect again.

`getAddress()` and `getPublicKey()` read the key from the slot metadata on YubiKey firmware 5.3 and newer, so no certificate is needed there; older firmware needs a certificate in the slot. After `generateKey()` on older firmware, read the new key from `lastGeneratedPublicKey()`, which needs no session, and store a certificate for that key (see [`packages/npm/README.md`](packages/npm/README.md#generatekeypin-string-promisestring)). If the slot's certificate belongs to a different key, it is ignored and `hasStaleCertificate()` returns `true`.

Use `signTypedData`, `signMessage`, and `signHash` for EIP-712 typed data, EIP-191 personal messages, and raw 32-byte digests.

Calling `generateKey(pin?)` permanently overwrites any existing private key in the selected PIV slot (slot `9a` by default) and then deletes the slot's certificate, which described the old key. It requires prior management key authentication via `authenticateManagementKey(keyHex, algorithm?)`, and over the bridge it requires starting the bridge with `--allow-generate`. Only call it when you intend to replace the key in that slot.

`YubiKeyDevice.connect()` is still available for direct WebUSB. It filters specifically for Yubico (`0x1050`) devices, so it only works in environments where Chromium's Yubico WebUSB blocklist and Smart Card interface class restriction do not apply, such as custom browser builds or Isolated Web Apps with unrestricted USB permissions.

## Input formats

Transaction JSON (`signTransaction`, `Transaction::from_json`):

- `type` is `"legacy"` or `"eip1559"`. Keys are snake_case; unknown keys are rejected, including camelCase spellings such as `accessList` and unknown keys inside access-list entries.
- `chain_id` must be non-zero.
- `to` is required: an address, or `null` for contract creation. Omitting it is an error.
- Amounts (`value`, `gas_price`, `max_fee_per_gas`, `max_priority_fee_per_gas`) accept a JSON unsigned integer, a decimal digit string, or a `0x`/`0X` hex string. Signs, whitespace, separators, and floats are rejected.
- Calldata goes in `data` or its alias `input` as a hex string.

EIP-712 typed data JSON (`signTypedData`, `TypedData::from_json`):

- `domain` accepts only `name`, `version`, `chainId`, `verifyingContract`, and `salt`. `chainId` follows the amount rules above, and `salt` must be `0x` followed by exactly 32 bytes of hex.
- If `types.EIP712Domain` is declared, it may only list those standard fields with their standard types, and it must declare every field that is set in `domain`.
- Struct type names and field names must be identifiers (`[A-Za-z_$][A-Za-z0-9_$]*`), field names must be unique within a struct, and a struct may not use a primitive type name such as `address`.
- `bytesN` values must be `0x` followed by exactly N bytes of hex; `bytes` values must start with `0x`.
- A message value may be nested at most 64 levels deep. The primary struct is level 0, and each nested struct value and each array dimension adds one level.

## Native CLI

The `yubikey-cli` example talks to a YubiKey over native PC/SC on macOS, Linux, and Windows. Run it with the recipes in [`.justfile`](.justfile):

```bash
# List connected YubiKeys
just cli-list

# Check PIV applet connection status
just cli-info

# Generate a new P-256 key in slot 9a (overwrites any existing key) and save its PEM
just cli-generate --pubkey-out pubkey.pem

# Only on firmware older than 5.3: store a certificate so the key can be read back
ykman piv certificates generate -s "CN=YubiKey EVM Signer" 9a pubkey.pem

# Show the slot 9a P-256 public key and its derived address
just cli-address

# Sign a sample EIP-1559 transaction hash
just cli-sign-tx

# Sign a custom 32-byte hash
just cli-sign 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Start the local PC/SC bridge for browser apps (default port 8765)
just cli-bridge
```

You can also invoke the example directly with Cargo:

```bash
cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- <command>
```

`address`, `sign`, and `sign-tx` read the slot's public key from the slot metadata on firmware 5.3 and newer and fall back to the slot certificate on older firmware. If the certificate belongs to a different key, the CLI prints a warning and ignores it. `sign` and `sign-tx` read the key before prompting for the PIN, then select the PIV applet, check that the key has not changed, verify the PIN, and sign in one PC/SC transaction.

`just cli-generate` shows what slot `9a` currently holds and asks you to type the slot id (`9a`) to confirm; `generate --force` skips that confirmation. It then prompts for the management key algorithm and key, generates the key, and deletes the slot's old certificate in one PC/SC transaction, printing a warning if the certificate could not be deleted. It prints the new public key as uncompressed hex and as a `-----BEGIN PUBLIC KEY-----` PEM; `--pubkey-out <path>` also writes the PEM to a new file. The path is checked before the prompts and the file is created after them, right before the card is changed, so an existing file is never replaced, an unusable path fails before the card is changed, and interrupting a prompt leaves no file behind. Once the card has generated the key, the file is written and synced before anything is printed, and if standard output fails the key is printed to standard error instead. An interrupt (Ctrl+C, `SIGTERM`, `SIGHUP`) while the card is being changed is deferred: the command stops before generating the key if it still can (exit status 130), and otherwise finishes and reports the new key; a second interrupt quits at once and can lose a key generated by then. The exit status is 0 only if the key was generated and every output was written; it is 1 if anything failed, including an output after the key was generated. Firmware older than 5.3 needs a certificate for that PEM, as shown above. Because the old certificate is deleted, `ykman piv keys export 9a` can recover the PEM later only on firmware 4.3 and newer. YubiKey firmware 5.7 and newer defaults to an AES-192 management key, older firmware defaults to 3DES, and the CLI also supports AES-128 and AES-256 management keys.

If another PC/SC application resets the YubiKey during an operation, the CLI reports that the card was reset; run the command again. Command-line arguments must be valid UTF-8.

### Local PC/SC bridge

`yubikey-cli bridge` (or `just cli-bridge [options]`) serves the YubiKey to browser pages over HTTP on `127.0.0.1`. It prints the URL, the allowed origins, and a random 256-bit bearer token. The token is valid until the bridge process stops.

| Option | Default | Effect |
|--------|---------|--------|
| `--port <port>` | `8765` | TCP port on `127.0.0.1` |
| `--allow-origin <origin>` | `http://localhost:8000`, `http://127.0.0.1:8000`, `https://storopoli.github.io` | Adds an exact browser `Origin` to the allowlist (repeatable) |
| `--idle-timeout <seconds>` | `120` | Closes the YubiKey session and resets the card after this many idle seconds (10 to 3600) |
| `--allow-generate` | off | Permits management key authentication, key generation, and certificate deletion |

Security controls:

- The bridge binds only to `127.0.0.1` and accepts a request only if its `Host` header is exactly `127.0.0.1:<port>`; `localhost` and `[::1]` are rejected, as a DNS rebinding defense. Port `80` is refused, because browsers omit the default HTTP port from `Host`, so that check could never pass.
- Every request must carry an `Origin` from the exact allowlist (wildcards are refused) and, except for CORS preflights, `Authorization: Bearer <token>`, compared in constant time. A token passed to `BridgeConfig` must be at least 32 visible ASCII characters.
- Each APDU must pass the allowlist below. Each forwarded command, including its wrong-`Le` retry and its whole `GET RESPONSE` chain, runs as one PC/SC transaction; the bridge collects chained responses itself and returns the complete response.
- One hardware session exists at a time; a new `/v1/connect` closes the previous one. A session ends after the idle timeout, when another PC/SC client resets the card, and when the bridge stops. Ending a session releases the card handle and resets the card, which clears the verified PIN and management key authentication.
- Ctrl+C or SIGTERM shuts the bridge down gracefully, closing the session and resetting the card; a second signal exits immediately.
- Requests are limited to 8 KiB of headers and 16 KiB of body and must arrive within a 10 second deadline. Header syntax is parsed strictly and `Transfer-Encoding` is refused.

APDU allowlist (`validate_bridge_apdu`; `CLA` must be `00`, slots are `9A`, `9C`, `9D`, `9E`):

| Command | INS | Constraint | Needs `--allow-generate` |
|---------|-----|------------|--------------------------|
| `SELECT` | `A4` | `P1=04 P2=00`, data = PIV AID | No |
| `VERIFY` (PIN) | `20` | `P1=00 P2=80`, no data (retry query) or 8 bytes | No |
| `GENERAL AUTHENTICATE` (sign) | `87` | `P1=11` (P-256), `P2` = slot, data = `7C 24 82 00 81 20` + 32-byte digest | No |
| `GET METADATA` | `F7` | `P1=00`, `P2` = slot, no data | No |
| `GET DATA` | `CB` | `P1=3F P2=FF`, data = `5C 03` + a slot certificate object ID | No |
| `GENERAL AUTHENTICATE` (management key) | `87` | `P2=9B`, `P1` = `03`, `08`, `0A`, or `0C` | Yes |
| `GENERATE ASYMMETRIC` | `47` | `P1=00`, `P2` = slot, data = `AC 03 80 01 11` (P-256) | Yes |
| `PUT DATA` (delete certificate) | `DB` | exactly `00 DB 3F FF 07 5C 03 <slot object ID> 53 00` | Yes |

Everything else is refused, including `GET RESPONSE`, PIN and PUK changes, `SET MANAGEMENT KEY`, `RESET`, and `SELECT` of other applets.

Endpoints: `GET /v1/health`, `POST /v1/connect` (body `{}`, returns `{"session_id": …}`), `POST /v1/transmit` (`{"session_id", "apdu"}` in hex, returns `{"response"}` as hex data followed by the status word), and `POST /v1/disconnect` (`{"session_id"}`). `POST` bodies must be `Content-Type: application/json`. Errors return `{"error": "<message>"}` with these status codes:

| Status | Meaning |
|--------|---------|
| `400` | Malformed request, JSON body, or APDU hex |
| `401` | Missing or wrong bearer token |
| `403` | APDU not on the allowlist (key generation commands name `--allow-generate`), or `Host`/`Origin` rejected |
| `404` | No YubiKey found on `/v1/connect`, or unknown endpoint |
| `405` / `415` | Wrong method / wrong `Content-Type` |
| `408` | Request not received within the deadline |
| `409` | Session unknown, replaced, expired, or closed because another PC/SC client reset the card; connect again |
| `413` / `431` | Body / header block too large |
| `500` | Internal bridge error |
| `502` | PC/SC or card communication error |
| `503` | YubiKey or reader lost, bridge shutting down, or too many connections; connect again |

Readable error responses carry CORS headers. Requests rejected before the `Host` and `Origin` checks pass (including the `403` for those checks) get no CORS headers, so the browser reports them as a failed `fetch()`; the JavaScript error then suggests restarting the bridge with `--allow-origin <origin>`. CORS preflights from an allowed origin are answered with `204` and, when requested, `Access-Control-Allow-Private-Network: true`.

### Platform requirements

| Platform | Requirements |
|----------|--------------|
| macOS | Works with the built-in smart card daemon |
| Linux | `pcscd` running, `libpcsclite-dev` for building, and [udev rules](https://developers.yubico.com/yubikey-manager/Device_Permissions.html) if needed |
| Windows | Works with the built-in smart card service |

### Default PIV credentials

| Credential | Factory default |
|------------|-----------------|
| PIN | `123456` |
| PUK | `12345678` |
| Management key | `010203040506070801020304050607080102030405060708` (AES-192 on YubiKey 5.7+, 3DES on earlier firmware) |

Change factory credentials with `ykman piv access` before using a YubiKey key for anything of value.

## Development and testing

Common checks are defined in [`.justfile`](.justfile):

- `just test` runs unit tests with `cargo-nextest` and Rust doc tests.
- `just lints` checks TOML formatting and linting (`taplo`), `cargo fmt`, and `clippy` for both native and WASM targets.
- `just check-github-actions-security` runs `zizmor` against the GitHub Actions workflows.
- `node scripts/verify-demo.mjs` checks the demo HTML and JavaScript wiring (element IDs, links, Content-Security-Policy, no inline scripts or handlers) and that the WASM crate exports every API `demo/app.js` uses. Add `--check-wasm` after `just wasm-build` to check the generated package in `packages/npm/dist/` (including the npm package layout and license files), or `--check-wasm --wasm-dir <path>` for another output directory such as `demo/wasm`.
- `just npm-licenses` copies the license files into `packages/npm/`; the `wasm-build` recipes run it automatically.

## Contributing

Contributions are welcome. Open an issue to discuss larger changes before sending a pull request so work is not duplicated. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Do not open public issues for security vulnerabilities. Report them following [SECURITY.md](SECURITY.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
