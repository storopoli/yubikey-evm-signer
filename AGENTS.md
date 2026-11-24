# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

YubiKey EVM Signer signs Ethereum transaction hashes, EIP-712 typed data, and EIP-191 messages using a YubiKey's PIV applet with secp256r1 (P-256) ECDSA, targeting EIP-7951 (`P256VERIFY` precompile at `0x100`) for P-256 signature verification on the EVM.

The address derived from a P-256 key (`keccak256(X‖Y)[12..]`) is an identifier, not a secp256k1 EOA: standard EVM chains validate transactions with secp256k1 `ecrecover`, so the signed transactions are only useful to P-256-aware verifiers (smart accounts, ERC-1271) that know the public key. Keep docs, rustdoc, CLI output, and the demo consistent with this.

There's a justfile that provides a set of build commands and testing commands.
See `.justfile` for more details.

## Build Commands

```bash
# Build all crates (excludes WASM)
cargo build --workspace --exclude yubikey-evm-signer-wasm

# Build WASM crate (requires wasm32-unknown-unknown target)
cargo build -p yubikey-evm-signer-wasm --target wasm32-unknown-unknown

# Build WASM package for npm
wasm-pack build crates/signer-wasm --target web --release --no-opt --out-dir ../../packages/npm/dist --out-name yubikey_evm_signer_wasm
```

## Testing

```bash
# Run all tests with nextest
cargo nextest run --all-features --workspace

# Run a single test
cargo nextest run --all-features test_name

# Run doc tests
cargo test --doc --all-features --workspace

# Verify demo HTML/JS integrity (DOM IDs, links, CSP, no inline code) and that the
# WASM crate exports every API demo/app.js uses
node scripts/verify-demo.mjs

# Also check a built package: packages/npm/dist by default (layout and license
# files too), or another output directory such as demo/wasm
node scripts/verify-demo.mjs --check-wasm
node scripts/verify-demo.mjs --check-wasm --wasm-dir demo/wasm
```

`just test` runs nextest and doc tests; `just lints` runs taplo, rustfmt, and both clippy recipes.

## Linting

```bash
# Format code
cargo fmt --all

# Check formatting
cargo fmt --all --check

# Clippy for non-WASM crates (as in CI)
RUSTFLAGS="-D warnings" cargo clippy --workspace --exclude yubikey-evm-signer-wasm --examples --tests --benches --all-features --all-targets --locked

# Clippy for WASM crate (requires special flags)
RUSTFLAGS="-D warnings --cfg=web_sys_unstable_apis" cargo clippy -p yubikey-evm-signer-wasm --target wasm32-unknown-unknown --all-features --locked

# Rustdoc warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features -p yubikey-evm-signer-core --locked

# TOML linting (requires taplo)
taplo lint && taplo fmt --check
```

## Architecture

Two-crate workspace with native and browser transports:

- **signer-core** (`yubikey-evm-signer-core`): Platform-agnostic core library
  - `transaction.rs`: EIP-155 legacy and EIP-1559 transaction types; strict JSON (unknown keys rejected, `to` required, strict amounts); `signing_hash()` returns `Result` and rejects `chain_id == 0`
  - `eip712.rs`: EIP-712 typed data hashing with strict domain, type-name, and value validation (`MAX_RECURSION_DEPTH`)
  - `crypto.rs`: P-256 DER parsing, low-S normalization, recovery ID calculation, EIP-7951 `p256_verify`, and EIP-191 hashing
  - `address.rs`: keccak-derived address identifiers of P-256 public keys (not secp256k1 accounts)
  - `signature.rs`: Signature types with low-S normalization
  - `error.rs`: Core `Error` enum (including `CardReset` and `PinRequired`)
  - `bridge.rs`: Hardened `127.0.0.1`-only HTTP/1.1 PC/SC bridge server (non-WASM targets): exact `Host`/`Origin` checks, process-lifetime bearer token, idle session timeout, opt-in key generation, APDU allowlist in `validate_bridge_apdu`, one PC/SC transaction per forwarded command
  - `yubikey/`: PIV applet communication
    - `Transport` trait for synchronous native/mock transports, with `exclusive` scopes (PC/SC transactions; `PcscTransport` behind the optional `pcsc` feature maps card resets to `Error::CardReset`)
    - `PivSession` / `PivExclusive` and sans-IO PIV APDU builders/parsers in `piv.rs`; slot public keys come from Yubico `GET METADATA` (firmware 5.3+) with certificate fallback and stale-certificate detection; `generate_key` returns `GeneratedKey` and deletes the slot certificate
    - `Slot` enum for PIV slot management
    - `Apdu` for command encoding
  - `examples/yubikey-cli.rs`: Native PC/SC CLI (`list`, `info`, `address`, `generate [--force]`, `sign`, `sign-tx`, `bridge [--port] [--allow-origin]... [--idle-timeout] [--allow-generate]`)

- **signer-wasm** (`yubikey-evm-signer-wasm`): Browser WASM bindings
  - `device.rs`: `YubiKeyDevice` class exposed to JavaScript (`connectBridge`, `connect`, `getPublicKey`, `getAddress`, `hasStaleCertificate`, signing methods); one call at a time; session-ending errors clear PIN/management state
  - `bridge_transport.rs`: Async `BridgeTransport` connecting to `yubikey-cli bridge` over `fetch()`; accepts only `http://127.0.0.1:<port>` (port `80` excluded) and tokens of at least 32 visible ASCII characters; maps `409`/`503`, and on an established session an unreachable bridge or `401`/`500`, to `Disconnected`
  - `transport.rs`: Async `WebUsbTransport` (browser async CCID transport; does not implement core's synchronous `Transport` trait; closes itself after an unrecoverable CCID error) and shared `AsyncApduTransport` retry/chaining helpers
  - `error.rs`: `WasmError`, whose `Display` strings are the JavaScript error messages documented in `packages/npm/README.md`
  - Built with wasm-pack, outputs to `packages/npm/dist/` (`just wasm-build` also runs `just npm-licenses`)

- **demo/**: Static demo page (`index.html` with a CSP meta tag, `app.js` routing every device call through one in-flight guard); checked by `scripts/verify-demo.mjs`

## Key Technical Details

- Uses Rust 2024 edition; MSRV is `rust-version = "1.90"`
- Workspace lints enforce `missing_docs`, `unused_crate_dependencies`, and strict warnings
- WASM build requires `--no-opt` flag (wasm-opt doesn't support Rust 2024 bulk-memory ops)
- WASM crate needs `web_sys_unstable_apis` cfg flag for WebUSB features (set in `.cargo/config.toml` here; crates.io consumers must set it themselves, see `crates/signer-wasm/src/lib.rs`)
- Native tests need the system PC/SC library (`libpcsclite-dev` on Linux) because `--all-features` enables `pcsc`
- The release workflow checks the tag against the Cargo workspace and npm versions and runs the tests before publishing
- All signatures normalized to low-S form for malleability prevention
