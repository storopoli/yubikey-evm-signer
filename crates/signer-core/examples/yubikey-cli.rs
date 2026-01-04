//! YubiKey EVM Signer CLI Example
//!
//! This example demonstrates how to use the YubiKey EVM signer library
//! with native PC/SC transport on macOS, Linux, and Windows.
//!
//! # Prerequisites
//!
//! - A YubiKey with PIV support (YubiKey 5 series recommended)
//! - PC/SC daemon running (built-in on macOS/Windows, `pcscd` on Linux)
//! - Default PIV credentials (or know your custom ones):
//!   - PIN: `123456`
//!   - Management Key: `010203040506070801020304050607080102030405060708`
//!
//! # Quick Start
//!
//! ```bash
//! # Using justfile (recommended)
//! just cli-list          # List connected YubiKeys
//! just cli-generate      # Generate a new P-256 key in slot 9a
//! just cli-address       # Get Ethereum address (requires certificate)
//! just cli-sign-tx       # Sign a sample EIP-1559 transaction
//!
//! # Using cargo directly
//! cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- list
//! cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- generate
//! ```
//!
//! # Workflow
//!
//! 1. **Generate a key** (overwrites existing key in slot 9a):
//!    ```bash
//!    just cli-generate
//!    # Enter PIN when prompted (default: 123456)
//!    ```
//!
//! 2. **Create a certificate** (required for address retrieval):
//!    ```bash
//!    ykman piv keys export 9a /tmp/pubkey.pem
//!    ykman piv certificates generate -P 123456 \
//!      -m 010203040506070801020304050607080102030405060708 \
//!      -s "CN=YubiKey EVM Signer" 9a /tmp/pubkey.pem
//!    ```
//!
//! 3. **Get your Ethereum address**:
//!    ```bash
//!    just cli-address
//!    ```
//!
//! 4. **Sign transactions**:
//!    ```bash
//!    just cli-sign-tx
//!    # Or sign a custom hash:
//!    just cli-sign 0x0123456789abcdef...  # 32-byte hash
//!    ```
//!
//! # Commands
//!
//! | Command | Description |
//! |---------|-------------|
//! | `list` | List available YubiKey devices |
//! | `info` | Show YubiKey connection info |
//! | `address` | Get Ethereum address from slot 9a |
//! | `generate` | Generate new P-256 key in slot 9a |
//! | `sign <hash>` | Sign a 32-byte hash |
//! | `sign-tx` | Sign a sample EIP-1559 transaction |
//!
//! # Platform Notes
//!
//! - **macOS**: Works out of the box with the built-in smart card daemon.
//!   Note that WebUSB does NOT work on macOS due to kernel driver conflicts.
//! - **Linux**: Requires `pcscd` service running (`sudo systemctl start pcscd`).
//!   May need udev rules for non-root access.
//! - **Windows**: Works with the built-in smart card service.
//!
//! # Security Notes
//!
//! - Private keys never leave the YubiKey
//! - PIN is required for signing operations
//! - Management key is required for key generation
//! - Consider changing default PIN/PUK/management key for production use

#![expect(unused_crate_dependencies, reason = "needed for CLI example")]

use std::env;
use std::io::{self, Write};

use yubikey_evm_signer_core::crypto::{create_ethereum_signature, parse_der_signature};
use yubikey_evm_signer_core::yubikey::{PcscTransport, PivSession, Slot};
use yubikey_evm_signer_core::{Address, Eip1559Transaction, Transaction, U256};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        return;
    }

    match args[1].as_str() {
        "list" => cmd_list(),
        "info" => cmd_info(),
        "address" => cmd_address(),
        "generate" => cmd_generate(),
        "sign" => cmd_sign(&args[2..]),
        "sign-tx" => cmd_sign_tx(),
        "--help" | "-h" | "help" => print_help(),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_help();
        }
    }
}

fn print_help() {
    println!(
        r#"YubiKey EVM Signer CLI

USAGE:
    yubikey-cli <COMMAND>

COMMANDS:
    list        List available YubiKey devices
    info        Show YubiKey connection info
    address     Get Ethereum address from slot 9a
    generate    Generate a new P-256 key in slot 9a (requires PIN)
    sign <hex>  Sign a 32-byte hash (requires PIN)
    sign-tx     Sign a sample EIP-1559 transaction (requires PIN)
    help        Show this help message

EXAMPLES:
    cargo run --example yubikey-cli --features pcsc -- list
    cargo run --example yubikey-cli --features pcsc -- address
    cargo run --example yubikey-cli --features pcsc -- sign 0x$(printf '00%.0s' {{1..32}})
"#
    );
}

fn cmd_list() {
    println!("Searching for YubiKey devices...\n");

    match PcscTransport::list_readers() {
        Ok(readers) => {
            if readers.is_empty() {
                println!("No YubiKey devices found.");
                println!("\nMake sure:");
                println!("  - Your YubiKey is plugged in");
                println!("  - The PC/SC daemon is running");
                println!("    - macOS: launchctl list | grep pcscd");
                println!("    - Linux: systemctl status pcscd");
            } else {
                println!("Found {} YubiKey device(s):\n", readers.len());
                for (i, reader) in readers.iter().enumerate() {
                    println!("  [{}] {}", i + 1, reader);
                }
            }
        }
        Err(e) => {
            eprintln!("Error listing devices: {e}");
        }
    }
}

fn cmd_info() {
    println!("Connecting to YubiKey...\n");

    match PcscTransport::connect() {
        Ok(transport) => {
            let mut session = PivSession::new(Box::new(transport));

            match session.select() {
                Ok(()) => {
                    println!("Successfully connected to YubiKey PIV applet!");
                    println!(
                        "Connection status: {}",
                        if session.is_connected() {
                            "Connected"
                        } else {
                            "Disconnected"
                        }
                    );
                }
                Err(e) => {
                    eprintln!("Failed to select PIV applet: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to connect: {e}");
        }
    }
}

fn cmd_address() {
    println!("Getting Ethereum address from slot 9a...\n");

    let transport = match PcscTransport::connect() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to connect: {e}");
            return;
        }
    };

    let mut session = PivSession::new(Box::new(transport));

    if let Err(e) = session.select() {
        eprintln!("Failed to select PIV applet: {e}");
        return;
    }

    match session.get_public_key(Slot::Authentication) {
        Ok(public_key) => {
            let address = Address::from_public_key(&public_key);
            println!("Public Key (uncompressed):");
            let encoded = public_key.to_encoded_point(false);
            println!("  {}", hex::encode(encoded.as_bytes()));
            println!();
            println!("Ethereum Address:");
            println!("  {}", address);
        }
        Err(_) => {
            eprintln!("No certificate found in slot 9a.");
            eprintln!();
            eprintln!("After generating a key, you need to create a certificate:");
            eprintln!("  ykman piv certificates generate -a ECCP256 9a /dev/null");
            eprintln!();
            eprintln!("Or use 'generate' command which shows the address directly.");
        }
    }
}

fn cmd_generate() {
    println!("Generating new P-256 key in slot 9a...\n");
    println!("WARNING: This will overwrite any existing key in slot 9a!");
    println!();

    let pin = prompt_pin();

    let transport = match PcscTransport::connect() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to connect: {e}");
            return;
        }
    };

    let mut session = PivSession::new(Box::new(transport));

    if let Err(e) = session.select() {
        eprintln!("Failed to select PIV applet: {e}");
        return;
    }

    if let Err(e) = session.verify_pin(&pin) {
        eprintln!("PIN verification failed: {e}");
        return;
    }

    println!("PIN verified. Generating key...");

    println!("Authenticating with management key...");

    match session.generate_key(Slot::Authentication) {
        Ok(public_key) => {
            let address = Address::from_public_key(&public_key);
            println!();
            println!("Key generated successfully!");
            println!();
            println!("Public Key (uncompressed):");
            let encoded = public_key.to_encoded_point(false);
            println!("  {}", hex::encode(encoded.as_bytes()));
            println!();
            println!("Ethereum Address:");
            println!("  {}", address);
        }
        Err(e) => {
            eprintln!("Failed to generate key: {e}");
            eprintln!();
            eprintln!("Note: Key generation requires management key authentication.");
            eprintln!("If you've changed the default management key, this will fail.");
            eprintln!("Use 'ykman piv access change-management-key' to reset it.");
        }
    }
}

fn cmd_sign(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: sign <32-byte-hash-hex>");
        eprintln!(
            "Example: sign 0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        return;
    }

    let hash_hex = args[0].strip_prefix("0x").unwrap_or(&args[0]);
    let hash_bytes = match hex::decode(hash_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Invalid hex: {e}");
            return;
        }
    };

    if hash_bytes.len() != 32 {
        eprintln!("Hash must be exactly 32 bytes, got {}", hash_bytes.len());
        return;
    }

    let hash: [u8; 32] = hash_bytes.try_into().unwrap();

    println!("Signing hash: 0x{}\n", hex::encode(hash));

    let pin = prompt_pin();

    let transport = match PcscTransport::connect() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to connect: {e}");
            return;
        }
    };

    let mut session = PivSession::new(Box::new(transport));

    if let Err(e) = session.select() {
        eprintln!("Failed to select PIV applet: {e}");
        return;
    }

    if let Err(e) = session.verify_pin(&pin) {
        eprintln!("PIN verification failed: {e}");
        return;
    }

    // Get the public key first for signature creation
    let public_key = match session.get_public_key(Slot::Authentication) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("Failed to get public key: {e}");
            return;
        }
    };

    println!("PIN verified. Signing (touch YubiKey if required)...");

    match session.sign(Slot::Authentication, &hash) {
        Ok(der_signature) => {
            println!();
            println!("DER Signature:");
            println!("  {}", hex::encode(&der_signature));

            // Parse and normalize signature
            match parse_der_signature(&der_signature) {
                Ok((r, s)) => {
                    println!();
                    println!("Signature Components:");
                    println!("  r: 0x{}", hex::encode(r));
                    println!("  s: 0x{}", hex::encode(s));

                    // Create Ethereum signature with recovery parameter
                    match create_ethereum_signature(&der_signature, &hash, &public_key) {
                        Ok(eth_sig) => {
                            println!();
                            println!("Ethereum Signature (r || s || v):");
                            println!("  {}", eth_sig);
                        }
                        Err(e) => {
                            eprintln!("Warning: Could not create full Ethereum signature: {e}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Could not parse DER signature: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("Signing failed: {e}");
        }
    }
}

fn cmd_sign_tx() {
    println!("Creating and signing a sample EIP-1559 transaction...\n");

    let pin = prompt_pin();

    let transport = match PcscTransport::connect() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to connect: {e}");
            return;
        }
    };

    let mut session = PivSession::new(Box::new(transport));

    if let Err(e) = session.select() {
        eprintln!("Failed to select PIV applet: {e}");
        return;
    }

    if let Err(e) = session.verify_pin(&pin) {
        eprintln!("PIN verification failed: {e}");
        return;
    }

    // Get the public key
    let public_key = match session.get_public_key(Slot::Authentication) {
        Ok(pk) => pk,
        Err(_) => {
            eprintln!("No certificate found in slot 9a.");
            eprintln!();
            eprintln!("After generating a key, create a certificate first:");
            eprintln!("  ykman piv certificates generate -a ECCP256 9a /dev/null");
            return;
        }
    };

    let address = Address::from_public_key(&public_key);
    println!("Signing from: {}\n", address);

    // Create a sample transaction
    let tx = Transaction::Eip1559(Eip1559Transaction {
        chain_id: 1, // Mainnet
        nonce: 0,
        max_priority_fee_per_gas: U256::from(1_000_000_000u64), // 1 gwei
        max_fee_per_gas: U256::from(50_000_000_000u64),         // 50 gwei
        gas_limit: 21000,
        to: Some(Address::zero()), // Send to zero address (example)
        value: U256::from(1_000_000_000_000_000u64), // 0.001 ETH
        data: vec![],
        access_list: vec![],
    });

    println!("Transaction Details:");
    println!("  Chain ID: 1 (Mainnet)");
    println!("  Nonce: 0");
    println!("  To: 0x0000...0000");
    println!("  Value: 0.001 ETH");
    println!("  Gas Limit: 21000");
    println!();

    // Get the signing hash
    let signing_hash = tx.signing_hash();
    let hash_bytes: [u8; 32] = signing_hash.into();
    println!("Signing Hash: 0x{}", hex::encode(hash_bytes));
    println!();

    println!("Signing (touch YubiKey if required)...");

    match session.sign(Slot::Authentication, &hash_bytes) {
        Ok(der_signature) => {
            match create_ethereum_signature(&der_signature, &hash_bytes, &public_key) {
                Ok(eth_sig) => {
                    println!();
                    println!("Transaction signed successfully!");
                    println!();
                    println!("Signature:");
                    println!("  r: 0x{}", hex::encode(eth_sig.r()));
                    println!("  s: 0x{}", hex::encode(eth_sig.s()));
                    println!("  v: {}", eth_sig.v());
                    println!();
                    println!("Full Signature (65 bytes):");
                    println!("  {}", eth_sig);
                }
                Err(e) => {
                    eprintln!("Failed to create Ethereum signature: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("Signing failed: {e}");
        }
    }
}

fn prompt_pin() -> String {
    print!("Enter PIN: ");
    io::stdout().flush().unwrap();

    let mut pin = String::new();
    io::stdin().read_line(&mut pin).unwrap();
    pin.trim().to_string()
}
