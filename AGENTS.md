# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

YubiKey EVM Signer enables signing Ethereum transactions using a YubiKey's PIV applet with secp256r1 (P-256) ECDSA, leveraging EIP-7951 for native secp256r1 signature verification on the EVM.

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
cargo test --doc --all-features
```

## Linting

```bash
# Format code
cargo fmt --all

# Check formatting
cargo fmt --all --check

# Clippy for non-WASM crates
cargo clippy --workspace --exclude yubikey-evm-signer-wasm --all-features --all-targets

# Clippy for WASM crate (requires special flags)
RUSTFLAGS="--cfg=web_sys_unstable_apis" cargo clippy -p yubikey-evm-signer-wasm --target wasm32-unknown-unknown --all-features

# TOML linting (requires taplo)
taplo lint && taplo fmt --check
```

## Architecture

Two-crate workspace with transport abstraction:

- **signer-core** (`yubikey-evm-signer-core`): Platform-agnostic core library
  - `transaction.rs`: EIP-155 legacy and EIP-1559 transaction types
  - `eip712.rs`: EIP-712 typed data hashing
  - `address.rs`: Ethereum address derivation from P-256 public keys
  - `signature.rs`: Signature types with low-S normalization
  - `yubikey/`: PIV applet communication
    - `Transport` trait for platform abstraction (CCID or WebUSB)
    - `PivSession` for key operations and signing
    - `Slot` enum for PIV slot management
    - `Apdu` for command encoding

- **signer-wasm** (`yubikey-evm-signer-wasm`): Browser WASM bindings
  - `device.rs`: `YubiKeyDevice` class exposed to JavaScript
  - `transport.rs`: `WebUsbTransport` implementing core `Transport` trait
  - Built with wasm-pack, outputs to `packages/npm/dist/`

## Key Technical Details

- Uses Rust 2024 edition
- Workspace lints enforce `missing_docs`, `unused_crate_dependencies`, and strict warnings
- WASM build requires `--no-opt` flag (wasm-opt doesn't support Rust 2024 bulk-memory ops)
- WASM crate needs `web_sys_unstable_apis` cfg flag for WebUSB features
- All signatures normalized to low-S form for malleability prevention
