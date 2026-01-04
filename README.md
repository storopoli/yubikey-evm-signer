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

Sign Ethereum transactions using a YubiKey's PIV applet with secp256r1 (P-256) ECDSA. Leverages [EIP-7951](https://eips.ethereum.org/EIPS/eip-7951) for native secp256r1 signature verification on the EVM. Passes all 781 EIP-7951 test vectors.

## Features

- **EIP-7951 Compatible**: Native secp256r1 signatures without curve conversion
- **Transaction Support**: EIP-155 legacy and EIP-1559 transactions
- **EIP-712**: Typed structured data signing
- **EIP-191**: Personal message signing
- **Hardware Security**: Private keys never leave the YubiKey
- **Cross-Platform**: Native (CCID) and browser (WebUSB) support

## Usage

### Rust

```rust
use yubikey_evm_signer_core::{Transaction, Eip1559Transaction, Address};
use alloy_primitives::U256;

// Create an EIP-1559 transaction
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

// Get the hash to sign
let hash = tx.signing_hash();
```

### JavaScript/TypeScript (Browser)

**Live Demo**: [storopoli.github.io/yubikey-evm-signer](https://storopoli.github.io/yubikey-evm-signer/)

```javascript
import init, { YubiKeyDevice } from 'yubikey-evm-signer';

await init();

// Connect to YubiKey (requires user gesture)
const device = await YubiKeyDevice.connect();

// Generate a new key
const address = await device.generateKey("123456");

// Sign a transaction
const signature = await device.signTransaction("123456", JSON.stringify({
    type: "eip1559",
    chain_id: 1,
    nonce: 0,
    max_priority_fee_per_gas: "1000000000",
    max_fee_per_gas: "20000000000",
    gas_limit: 21000,
    to: "0x...",
    value: "1000000000000000000",
    input: "0x"
}));

await device.disconnect();
```

> **Note**: WebUSB is only supported in Chromium-based browsers (Chrome, Edge, Opera, Brave) and requires HTTPS.
> WebUSB does **not** work on macOS due to kernel driver conflicts. Use the native CLI instead.

### Native CLI (macOS/Linux/Windows)

For native access via PC/SC (smart card interface), use the CLI example:

```bash
# List connected YubiKeys
just cli-list

# Generate a new P-256 key in slot 9a
just cli-generate

# Create a certificate (required for address retrieval)
ykman piv keys export 9a /tmp/pubkey.pem
ykman piv certificates generate -P 123456 \
  -m 010203040506070801020304050607080102030405060708 \
  -s "CN=YubiKey EVM Signer" 9a /tmp/pubkey.pem

# Get Ethereum address
just cli-address

# Sign a sample EIP-1559 transaction
just cli-sign-tx

# Sign a custom 32-byte hash
just cli-sign 0x0123456789abcdef...
```

Or run directly with cargo:

```bash
cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- <command>
```

#### Platform Requirements

| Platform | Requirements |
|----------|--------------|
| macOS | Works out of the box (built-in smart card daemon) |
| Linux | `pcscd` service running, may need [udev rules](https://developers.yubico.com/yubikey-manager/Device_Permissions.html) |
| Windows | Works out of the box (built-in smart card service) |

#### Default PIV Credentials

| Credential | Default Value |
|------------|---------------|
| PIN | `123456` |
| PUK | `12345678` |
| Management Key | `010203040506070801020304050607080102030405060708` |

> **Security**: Change default credentials for production use with `ykman piv access`.

## Contributing

Contributions are generally welcome.
If you intend to make larger changes please discuss them in an issue
before opening a PR to avoid duplicate work and architectural mismatches.

For more information please see [`CONTRIBUTING.md`](/CONTRIBUTING.md).

## License

This work is dual-licensed under MIT and Apache 2.0.
You can choose between one of them if you use this work.
