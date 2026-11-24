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

Sign Ethereum transactions, EIP-712 typed structured data, EIP-191 personal messages, and raw 32-byte hashes using a YubiKey's PIV applet with secp256r1 (P-256) ECDSA. Signatures target [EIP-7951](https://eips.ethereum.org/EIPS/eip-7951), which adds native secp256r1 verification on the EVM through the `P256VERIFY` precompile at address `0x100`. The verifier passes all 781 EIP-7951 test vectors.

Private keys never leave the YubiKey hardware. The signer supports EIP-155 legacy and EIP-1559 transactions, normalizes every signature to low-S form, and computes the P-256 recovery ID (`v`).

## Rust usage

Use `yubikey-evm-signer-core` to build Ethereum signing payloads, hash messages, and drive PIV sessions from Rust:

```rust
use yubikey_evm_signer_core::{
    Address, Eip1559Transaction, Transaction, U256, eip191_hash,
};

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

let tx_hash = tx.signing_hash();
let msg_hash = eip191_hash(b"Hello, Ethereum!");
```

Enable the optional `pcsc` feature for native smart card access through `yubikey::PcscTransport` and the `yubikey-cli` example. On non-WASM targets, the crate also includes the `bridge` module (`BridgeConfig`, `BridgeServer`, and `validate_bridge_apdu`) for running the local loopback HTTP bridge over any `Transport`.

## Browser and JavaScript usage

Install the `yubikey-evm-signer` npm package or try the live demo at [storopoli.github.io/yubikey-evm-signer](https://storopoli.github.io/yubikey-evm-signer/).

Chromium blocks raw WebUSB access to YubiKey PIV applets on standard web pages across all operating systems. Yubico's vendor ID (`0x1050`) is listed in Chromium's `usb_blocklist.cc` and the WICG `blocklist.txt`, and Chromium restricts USB Smart Card (CCID, class `0x0B`) interfaces as a protected interface class.

Connect through the local PC/SC bridge instead. Start the bridge locally with `just cli-bridge`, then pass the loopback URL and printed session token to `YubiKeyDevice.connectBridge(url, token)`. The bridge binds only to `127.0.0.1`, validates the `Host` header against DNS rebinding, enforces an exact `Origin` allowlist, checks a per-session 256-bit Bearer token in constant time, and permits only PIV APDU commands. Because native PC/SC handles smart card communication, the bridge works in Chrome, Firefox, Safari, Edge, and Brave on macOS, Linux, and Windows.

```javascript
import init, { YubiKeyDevice } from "yubikey-evm-signer";

await init();

// Start the local PC/SC bridge first with `just cli-bridge`
const device = await YubiKeyDevice.connectBridge(
    "http://127.0.0.1:8765",
    "<SESSION_BEARER_TOKEN>"
);

// Read the existing address from slot 9a (requires a PIV certificate)
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

Transaction JSON accepts either `data` or `input` for hex calldata. Use `signTypedData`, `signMessage`, and `signHash` for EIP-712 typed data, EIP-191 personal messages, and raw 32-byte digests.

Calling `generateKey(pin?)` permanently overwrites any existing private key in the selected PIV slot (slot `9a` by default). It requires prior management key authentication via `authenticateManagementKey(keyHex, algorithm?)`. Only call it when you intend to replace the key in that slot.

`YubiKeyDevice.connect()` is still available for direct WebUSB. It filters specifically for Yubico (`0x1050`) devices, so it only works in environments where Chromium's Yubico WebUSB blocklist and Smart Card interface class restriction do not apply, such as custom browser builds or Isolated Web Apps with unrestricted USB permissions.

## Native CLI

The `yubikey-cli` example talks to a YubiKey over native PC/SC on macOS, Linux, and Windows. Run it with the recipes in [`.justfile`](.justfile):

```bash
# List connected YubiKeys
just cli-list

# Check PIV applet connection status
just cli-info

# Generate a new P-256 key in slot 9a (overwrites any existing key)
just cli-generate

# Export the public key and store a certificate (required for address lookup)
ykman piv keys export 9a /tmp/pubkey.pem
ykman piv certificates generate -s "CN=YubiKey EVM Signer" 9a /tmp/pubkey.pem

# Read the Ethereum address from slot 9a
just cli-address

# Sign a sample EIP-1559 transaction
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

Pass `--port <port>` or repeatable `--allow-origin <origin>` flags to `bridge` when connecting from a custom browser origin.

`just cli-generate` prompts for management key authentication before overwriting slot `9a`. YubiKey firmware 5.7 and newer defaults to AES-192, older firmware defaults to 3DES, and the CLI also supports AES-128 and AES-256 management keys.

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

Change factory credentials with `ykman piv access` before using a YubiKey for real funds.

## Development and testing

Common checks are defined in [`.justfile`](.justfile):

- `just test` runs unit tests with `cargo-nextest` and Rust doc tests.
- `just lints` checks TOML formatting and linting (`taplo`), `cargo fmt`, and `clippy` for both native and WASM targets.
- `just check-github-actions-security` runs `zizmor` against the GitHub Actions workflows.
- `node scripts/verify-demo.mjs` checks the demo HTML and JavaScript wiring (add `--check-wasm` after building the WASM package to check `packages/npm/dist/`).

## Contributing

Contributions are welcome. Open an issue to discuss larger changes before sending a pull request so work is not duplicated. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Do not open public issues for security vulnerabilities. Report them following [SECURITY.md](SECURITY.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
