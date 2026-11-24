//! YubiKey EVM Signer CLI Example
//!
//! This example demonstrates how to use the YubiKey EVM signer library
//! with native PC/SC transport on macOS, Linux, and Windows.
//!
//! # Prerequisites
//!
//! - A YubiKey with PIV support (YubiKey 5 series recommended)
//! - PC/SC daemon running (built-in on macOS/Windows, `pcscd` on Linux)
//! - PIV credentials (defaults on factory YubiKey: PIN `123456`; management key
//!   `010203040506070801020304050607080102030405060708`, algorithm AES-192 on
//!   firmware 5.7+ or 3DES on earlier firmware)
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
//!    # Select management key algorithm and enter management key when prompted
//!    ```
//!
//! 2. **Create a certificate** (required for address retrieval):
//!    ```bash
//!    ykman piv keys export 9a /tmp/pubkey.pem
//!    ykman piv certificates generate -s "CN=YubiKey EVM Signer" 9a /tmp/pubkey.pem
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

#![allow(unused_crate_dependencies)]

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use yubikey_evm_signer_core::crypto::create_ethereum_signature;
use yubikey_evm_signer_core::yubikey::{ManagementKeyAlgorithm, PcscTransport, PivSession, Slot};
use yubikey_evm_signer_core::{Address, Eip1559Transaction, Transaction, U256};
use zeroize::Zeroize;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        return ExitCode::SUCCESS;
    }

    match args[1].as_str() {
        "list" => cmd_list(),
        "info" => cmd_info(),
        "address" => cmd_address(),
        "generate" => cmd_generate(),
        "sign" => cmd_sign(&args[2..]),
        "sign-tx" => cmd_sign_tx(),
        "--help" | "-h" | "help" => {
            print_help();
            ExitCode::SUCCESS
        }
        unknown => {
            eprintln!("Unknown command: {unknown}");
            print_help();
            ExitCode::FAILURE
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
    generate    Generate a new P-256 key in slot 9a (requires management key)
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

fn print_certificate_guidance() {
    eprintln!("No valid P-256 certificate found in slot 9a.");
    eprintln!();
    eprintln!("After generating a key, export the public key and generate a certificate:");
    eprintln!("  ykman piv keys export 9a /tmp/pubkey.pem");
    eprintln!("  ykman piv certificates generate -s \"CN=YubiKey EVM Signer\" 9a /tmp/pubkey.pem");
}

fn cmd_list() -> ExitCode {
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
                    println!("  [{}] {reader}", i + 1);
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error listing devices: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_info() -> ExitCode {
    println!("Connecting to YubiKey...\n");

    let transport = match PcscTransport::connect() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to connect: {e}");
            return ExitCode::FAILURE;
        }
    };

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
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Failed to select PIV applet: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_address() -> ExitCode {
    println!("Getting Ethereum address from slot 9a...\n");

    let transport = match PcscTransport::connect() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to connect: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut session = PivSession::new(Box::new(transport));

    if let Err(e) = session.select() {
        eprintln!("Failed to select PIV applet: {e}");
        return ExitCode::FAILURE;
    }

    match session.get_public_key(Slot::Authentication) {
        Ok(public_key) => {
            let address = Address::from_public_key(&public_key);
            println!("Public Key (uncompressed):");
            let encoded = public_key.to_sec1_point(false);
            println!("  {}", hex::encode(encoded.as_bytes()));
            println!();
            println!("Ethereum Address:");
            println!("  {address}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Failed to read public key: {e}");
            eprintln!();
            print_certificate_guidance();
            ExitCode::FAILURE
        }
    }
}

fn cmd_generate() -> ExitCode {
    println!("Generating new P-256 key in slot 9a...\n");
    println!("WARNING: This will overwrite any existing key in slot 9a!");
    println!();

    // Connect and select before prompting for sensitive credentials
    let transport = match PcscTransport::connect() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to connect: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut session = PivSession::new(Box::new(transport));

    if let Err(e) = session.select() {
        eprintln!("Failed to select PIV applet: {e}");
        return ExitCode::FAILURE;
    }

    let alg = match prompt_management_key_algorithm() {
        Ok(alg) => alg,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let mut mgmt_key = match prompt_management_key(alg) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    println!("Authenticating with management key ({alg:?})...");
    let auth_result = session.authenticate_management_key_with(&mgmt_key, alg);
    mgmt_key.zeroize();

    if let Err(e) = auth_result {
        eprintln!("Management key authentication failed: {e}");
        eprintln!();
        eprintln!(
            "Note: YubiKey firmware 5.7+ defaults to AES-192, while older firmware defaults to 3DES."
        );
        return ExitCode::FAILURE;
    }

    println!("Management key authenticated. Generating P-256 key in slot 9a...");

    match session.generate_key(Slot::Authentication) {
        Ok(public_key) => {
            let address = Address::from_public_key(&public_key);
            println!();
            println!("Key generated successfully!");
            println!();
            println!("Public Key (uncompressed):");
            let encoded = public_key.to_sec1_point(false);
            println!("  {}", hex::encode(encoded.as_bytes()));
            println!();
            println!("Ethereum Address:");
            println!("  {address}");
            println!();
            println!("To retrieve this address later with `address`, store a certificate:");
            println!("  ykman piv keys export 9a /tmp/pubkey.pem");
            println!(
                "  ykman piv certificates generate -s \"CN=YubiKey EVM Signer\" 9a /tmp/pubkey.pem"
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Failed to generate key: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_sign(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("Usage: sign <32-byte-hash-hex>");
        eprintln!(
            "Example: sign 0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        return ExitCode::FAILURE;
    }

    let hash_hex = args[0]
        .strip_prefix("0x")
        .or_else(|| args[0].strip_prefix("0X"))
        .unwrap_or(&args[0]);
    let hash_bytes = match hex::decode(hash_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Invalid hex: {e}");
            return ExitCode::FAILURE;
        }
    };

    let hash: [u8; 32] = match hash_bytes.try_into() {
        Ok(h) => h,
        Err(bytes) => {
            eprintln!("Hash must be exactly 32 bytes, got {}", bytes.len());
            return ExitCode::FAILURE;
        }
    };

    println!("Signing hash: 0x{}\n", hex::encode(hash));

    // Connect and select before prompting for PIN
    let transport = match PcscTransport::connect() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to connect: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut session = PivSession::new(Box::new(transport));

    if let Err(e) = session.select() {
        eprintln!("Failed to select PIV applet: {e}");
        return ExitCode::FAILURE;
    }

    // Retrieve the public key before prompting for PIN
    let public_key = match session.get_public_key(Slot::Authentication) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("Failed to get public key: {e}");
            eprintln!();
            print_certificate_guidance();
            return ExitCode::FAILURE;
        }
    };

    let mut pin = match prompt_pin() {
        Ok(pin) => pin,
        Err(e) => {
            eprintln!("Failed to read PIN: {e}");
            return ExitCode::FAILURE;
        }
    };

    let pin_result = session.verify_pin(&pin);
    pin.zeroize();

    if let Err(e) = pin_result {
        eprintln!("PIN verification failed: {e}");
        return ExitCode::FAILURE;
    }

    println!("PIN verified. Signing (touch YubiKey if required)...");

    match session.sign(Slot::Authentication, &hash) {
        Ok(der_signature) => {
            println!();
            println!("DER Signature:");
            println!("  {}", hex::encode(&der_signature));

            match create_ethereum_signature(&der_signature, &hash, &public_key) {
                Ok(eth_sig) => {
                    println!();
                    println!("Normalized Signature Components (low-S):");
                    println!("  r: 0x{}", hex::encode(eth_sig.r()));
                    println!("  s: 0x{}", hex::encode(eth_sig.s()));
                    println!("  v: {}", eth_sig.v());
                    println!();
                    println!("Ethereum Signature (r || s || v):");
                    println!("  {eth_sig}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Failed to create Ethereum signature: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("Signing failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_sign_tx() -> ExitCode {
    println!("Creating and signing a sample EIP-1559 transaction...\n");

    // Connect and select before prompting for PIN
    let transport = match PcscTransport::connect() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to connect: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut session = PivSession::new(Box::new(transport));

    if let Err(e) = session.select() {
        eprintln!("Failed to select PIV applet: {e}");
        return ExitCode::FAILURE;
    }

    let public_key = match session.get_public_key(Slot::Authentication) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("Failed to get public key: {e}");
            eprintln!();
            print_certificate_guidance();
            return ExitCode::FAILURE;
        }
    };

    let mut pin = match prompt_pin() {
        Ok(pin) => pin,
        Err(e) => {
            eprintln!("Failed to read PIN: {e}");
            return ExitCode::FAILURE;
        }
    };

    let pin_result = session.verify_pin(&pin);
    pin.zeroize();

    if let Err(e) = pin_result {
        eprintln!("PIN verification failed: {e}");
        return ExitCode::FAILURE;
    }

    let address = Address::from_public_key(&public_key);
    println!("Signing from: {address}\n");

    let tx = Transaction::Eip1559(Eip1559Transaction {
        chain_id: 1, // Mainnet
        nonce: 0,
        max_priority_fee_per_gas: U256::from(1_000_000_000u64), // 1 gwei
        max_fee_per_gas: U256::from(50_000_000_000u64),         // 50 gwei
        gas_limit: 21000,
        to: Some(Address::zero()),
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
                    println!("Signature (low-S):");
                    println!("  r: 0x{}", hex::encode(eth_sig.r()));
                    println!("  s: 0x{}", hex::encode(eth_sig.s()));
                    println!("  v: {}", eth_sig.v());
                    println!();
                    println!("Full Signature (65 bytes):");
                    println!("  {eth_sig}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Failed to create Ethereum signature: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("Signing failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn prompt_pin() -> io::Result<String> {
    rpassword::prompt_password("Enter PIN: ")
}

fn prompt_management_key_algorithm() -> Result<ManagementKeyAlgorithm, String> {
    print!(
        "Management key algorithm [tdes/aes128/aes192/aes256] (default: aes192 on YubiKey 5.7+, tdes on older): "
    );
    io::stdout()
        .flush()
        .map_err(|e| format!("failed to flush stdout: {e}"))?;

    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("failed to read algorithm selection: {e}"))?;

    match line.trim().to_ascii_lowercase().as_str() {
        "" | "aes192" => Ok(ManagementKeyAlgorithm::Aes192),
        "tdes" | "3des" => Ok(ManagementKeyAlgorithm::Tdes),
        "aes128" => Ok(ManagementKeyAlgorithm::Aes128),
        "aes256" => Ok(ManagementKeyAlgorithm::Aes256),
        other => Err(format!(
            "Unsupported management key algorithm '{other}'. Expected tdes, aes128, aes192, or aes256."
        )),
    }
}

fn prompt_management_key(alg: ManagementKeyAlgorithm) -> Result<Vec<u8>, String> {
    let expected_hex_chars = alg.key_len() * 2;
    let prompt = format!(
        "Enter management key ({} bytes / {expected_hex_chars} hex chars): ",
        alg.key_len()
    );
    let mut input = rpassword::prompt_password(prompt)
        .map_err(|e| format!("failed to read management key: {e}"))?;

    let trimmed = input.trim();
    let hex_str = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    let decoded = hex::decode(hex_str).map_err(|e| format!("invalid management key hex: {e}"));
    input.zeroize();

    let mut key = decoded?;
    if key.len() != alg.key_len() {
        let got = key.len();
        key.zeroize();
        return Err(format!(
            "Invalid management key length for {alg:?}: expected {} bytes, got {got}",
            alg.key_len()
        ));
    }

    Ok(key)
}
