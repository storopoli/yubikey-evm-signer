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
//! just cli-address       # Get Ethereum address
//! just cli-sign-tx       # Sign a sample EIP-1559 transaction
//!
//! # Using cargo directly
//! cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- list
//! cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- generate
//! ```
//!
//! # Workflow
//!
//! 1. **Generate a key** (replaces and destroys any existing key in slot 9a):
//!    ```bash
//!    just cli-generate
//!    # Shows what slot 9a currently holds, asks you to type `9a` to confirm
//!    # (`generate --force` skips this), then prompts for the management key
//!    # algorithm and management key. The slot's old certificate is deleted.
//!    ```
//!
//! 2. **Create a certificate** (only needed on firmware older than 5.3, where the
//!    key can only be read back through a certificate):
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
use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use yubikey_evm_signer_core::Error;
use yubikey_evm_signer_core::bridge::{BridgeConfig, BridgeServer, DEFAULT_BRIDGE_PORT};
use yubikey_evm_signer_core::crypto::create_ethereum_signature;
use yubikey_evm_signer_core::yubikey::{
    ManagementKeyAlgorithm, PcscTransport, PivSession, PublicKeySource, Slot, SlotPublicKey,
    Transport,
};
use yubikey_evm_signer_core::{Address, Eip1559Transaction, Transaction, U256};
use zeroize::{Zeroize, Zeroizing};

fn main() -> ExitCode {
    let args: Vec<String> = match env::args_os()
        .skip(1)
        .map(OsString::into_string)
        .collect::<Result<_, _>>()
    {
        Ok(args) => args,
        Err(_) => {
            eprintln!("Error: command-line arguments must be valid UTF-8.");
            eprintln!("Run `yubikey-cli help` for usage.");
            return ExitCode::FAILURE;
        }
    };

    let Some(command) = args.first() else {
        print_help();
        return ExitCode::SUCCESS;
    };

    match command.as_str() {
        "list" => cmd_list(),
        "info" => cmd_info(),
        "address" => cmd_address(),
        "generate" => cmd_generate(&args[1..]),
        "sign" => cmd_sign(&args[1..]),
        "sign-tx" => cmd_sign_tx(),
        "bridge" => cmd_bridge(&args[1..]),
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
    bridge      Start hardened local PC/SC HTTP bridge for browser apps
    help        Show this help message

GENERATE OPTIONS:
    --force     Skip the typed slot confirmation (for scripted use)

BRIDGE OPTIONS:
    --port <port>             Loopback TCP port (default: {DEFAULT_BRIDGE_PORT})
    --allow-origin <origin>   Additional allowed browser Origin (repeatable)

EXAMPLES:
    cargo run --example yubikey-cli --features pcsc -- list
    cargo run --example yubikey-cli --features pcsc -- address
    cargo run --example yubikey-cli --features pcsc -- generate
    cargo run --example yubikey-cli --features pcsc -- bridge --port 8765
    cargo run --example yubikey-cli --features pcsc -- sign 0x$(printf '00%.0s' {{1..32}})
"#
    );
}

fn print_certificate_guidance() {
    eprintln!("No valid P-256 public key could be read from slot 9a.");
    eprintln!();
    eprintln!("On YubiKey firmware 5.3 or later the key is read directly from the slot;");
    eprintln!("if the slot is empty, create a key with `generate`.");
    eprintln!();
    eprintln!("Older firmware can only report the key through a certificate. After");
    eprintln!("generating a key, export the public key and store a certificate:");
    eprintln!("  ykman piv keys export 9a /tmp/pubkey.pem");
    eprintln!("  ykman piv certificates generate -s \"CN=YubiKey EVM Signer\" 9a /tmp/pubkey.pem");
}

/// Prints a one-line warning when the slot's certificate describes another key.
fn warn_if_stale_certificate(info: &SlotPublicKey) {
    if info.stale_certificate {
        eprintln!(
            "Warning: the certificate in slot 9a does not match the slot's key; ignoring the stale certificate."
        );
    }
}

/// Connects to the first YubiKey and wraps it in a PIV session.
fn connect_session() -> Option<PivSession> {
    match PcscTransport::connect() {
        Ok(transport) => Some(PivSession::new(Box::new(transport))),
        Err(e) => {
            eprintln!("Failed to connect: {e}");
            None
        }
    }
}

/// Selects the PIV applet and reads slot 9a's public key in one PC/SC transaction.
fn read_slot_public_key(session: &mut PivSession) -> Result<SlotPublicKey, Error> {
    session.exclusive(|piv| {
        piv.select()?;
        piv.get_slot_public_key(Slot::Authentication)
    })
}

/// Selects the PIV applet, checks that slot 9a still holds `expected`, verifies the
/// PIN, and signs `hash`, all in one PC/SC transaction.
fn sign_in_one_transaction(
    session: &mut PivSession,
    expected: &SlotPublicKey,
    pin: &str,
    hash: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    session.exclusive(|piv| {
        piv.select()?;
        // Fail before spending a PIN attempt if the key was replaced meanwhile.
        if piv.get_public_key(Slot::Authentication)? != expected.public_key {
            return Err(Error::InvalidPublicKey(
                "the key in slot 9a changed since it was read; aborting before PIN verification"
                    .to_string(),
            ));
        }
        piv.verify_pin_and_sign(pin, Slot::Authentication, hash)
    })
}

/// Reports a failure from [`sign_in_one_transaction`].
fn report_sign_error(e: &Error) {
    match e {
        Error::InvalidPin { .. } | Error::PinLocked => {
            eprintln!("PIN verification failed: {e}");
        }
        other => eprintln!("Signing failed: {other}"),
    }
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

    let Some(mut session) = connect_session() else {
        return ExitCode::FAILURE;
    };

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

    let Some(mut session) = connect_session() else {
        return ExitCode::FAILURE;
    };

    match read_slot_public_key(&mut session) {
        Ok(info) => {
            warn_if_stale_certificate(&info);
            let address = Address::from_public_key(&info.public_key);
            println!("Public Key (uncompressed):");
            let encoded = info.public_key.to_sec1_point(false);
            println!("  {}", hex::encode(encoded.as_bytes()));
            println!(
                "  (read from {})",
                match info.source {
                    PublicKeySource::Metadata => "the key slot",
                    PublicKeySource::Certificate => "the slot's certificate",
                }
            );
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

fn cmd_generate(args: &[String]) -> ExitCode {
    const USAGE: &str = "Usage: yubikey-cli generate [--force]";

    let mut force = false;
    for arg in args {
        match arg.as_str() {
            "--force" => force = true,
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            unknown => {
                eprintln!("Unknown generate option: {unknown}");
                eprintln!("{USAGE}");
                return ExitCode::FAILURE;
            }
        }
    }

    println!("Generating new P-256 key in slot 9a...\n");

    // Connect and inspect the slot before prompting for sensitive credentials
    let Some(mut session) = connect_session() else {
        return ExitCode::FAILURE;
    };

    match read_slot_public_key(&mut session) {
        Ok(info) => {
            warn_if_stale_certificate(&info);
            println!("Slot 9a already holds a P-256 key:");
            println!(
                "  Ethereum Address: {}",
                Address::from_public_key(&info.public_key)
            );
        }
        Err(Error::SlotEmpty(_)) => {
            println!("Slot 9a appears to be empty.");
            println!(
                "(On firmware older than 5.3 a key without a certificate cannot be detected.)"
            );
        }
        Err(Error::InvalidKeyType(_)) => {
            println!("Slot 9a holds a key or certificate that is not P-256.");
        }
        Err(e) => {
            eprintln!("Failed to inspect slot 9a: {e}");
            eprintln!("Aborting; no changes were made.");
            return ExitCode::FAILURE;
        }
    }

    println!();
    println!("WARNING: This replaces any existing key in slot 9a. The old private key is");
    println!("destroyed and cannot be recovered; funds held by its address become inaccessible.");
    println!();

    if !force {
        match confirm_slot("9a") {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("Confirmation did not match; aborting. No changes were made.");
                return ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let alg = match prompt_management_key_algorithm() {
        Ok(alg) => alg,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let mgmt_key = match prompt_management_key(alg) {
        Ok(key) => Zeroizing::new(key),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "Authenticating with management key ({alg:?}) and generating a P-256 key in slot 9a..."
    );

    // SELECT -> management key auth -> GENERATE -> certificate delete in one PC/SC transaction
    let outcome = session.exclusive(|piv| {
        piv.select()?;
        if let Err(auth_error) = piv.authenticate_management_key_with(&mgmt_key, alg) {
            return Ok(Err(auth_error));
        }
        piv.generate_key(Slot::Authentication).map(Ok)
    });
    drop(mgmt_key);

    match outcome {
        Ok(Ok(generated)) => {
            let address = Address::from_public_key(&generated.public_key);
            println!();
            println!("Key generated successfully!");
            println!();
            println!("Public Key (uncompressed):");
            let encoded = generated.public_key.to_sec1_point(false);
            println!("  {}", hex::encode(encoded.as_bytes()));
            println!();
            println!("Ethereum Address:");
            println!("  {address}");
            println!();
            if let Some(e) = &generated.certificate_delete_error {
                eprintln!(
                    "Warning: the old certificate in slot 9a could not be removed ({e}). It describes the previous key; delete or replace it (e.g. `ykman piv certificates delete 9a`)."
                );
                eprintln!();
            }
            println!(
                "On YubiKey firmware 5.3 or later, `address` reads this key directly from the slot."
            );
            println!("On older firmware, store a certificate so that `address` can find it:");
            println!("  ykman piv keys export 9a /tmp/pubkey.pem");
            println!(
                "  ykman piv certificates generate -s \"CN=YubiKey EVM Signer\" 9a /tmp/pubkey.pem"
            );
            ExitCode::SUCCESS
        }
        Ok(Err(auth_error)) => {
            eprintln!("Management key authentication failed: {auth_error}");
            eprintln!();
            eprintln!(
                "Note: YubiKey firmware 5.7+ defaults to AES-192, while older firmware defaults to 3DES."
            );
            ExitCode::FAILURE
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

    // Connect and read the public key before prompting for PIN
    let Some(mut session) = connect_session() else {
        return ExitCode::FAILURE;
    };

    let key_info = match read_slot_public_key(&mut session) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("Failed to get public key: {e}");
            eprintln!();
            print_certificate_guidance();
            return ExitCode::FAILURE;
        }
    };
    warn_if_stale_certificate(&key_info);

    let pin = match prompt_pin() {
        Ok(pin) => Zeroizing::new(pin),
        Err(e) => {
            eprintln!("Failed to read PIN: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("Verifying PIN and signing (touch YubiKey if required)...");

    let sign_result = sign_in_one_transaction(&mut session, &key_info, &pin, &hash);
    drop(pin);

    match sign_result {
        Ok(der_signature) => {
            println!();
            println!("DER Signature:");
            println!("  {}", hex::encode(&der_signature));

            match create_ethereum_signature(&der_signature, &hash, &key_info.public_key) {
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
            report_sign_error(&e);
            ExitCode::FAILURE
        }
    }
}

fn cmd_sign_tx() -> ExitCode {
    println!("Creating and signing a sample EIP-1559 transaction...\n");

    // Connect and read the public key before prompting for PIN
    let Some(mut session) = connect_session() else {
        return ExitCode::FAILURE;
    };

    let key_info = match read_slot_public_key(&mut session) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("Failed to get public key: {e}");
            eprintln!();
            print_certificate_guidance();
            return ExitCode::FAILURE;
        }
    };
    warn_if_stale_certificate(&key_info);

    let address = Address::from_public_key(&key_info.public_key);
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

    let signing_hash = match tx.signing_hash() {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("Failed to compute signing hash: {e}");
            return ExitCode::FAILURE;
        }
    };
    let hash_bytes: [u8; 32] = signing_hash.into();
    println!("Signing Hash: 0x{}", hex::encode(hash_bytes));
    println!();

    let pin = match prompt_pin() {
        Ok(pin) => Zeroizing::new(pin),
        Err(e) => {
            eprintln!("Failed to read PIN: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("Verifying PIN and signing (touch YubiKey if required)...");

    let sign_result = sign_in_one_transaction(&mut session, &key_info, &pin, &hash_bytes);
    drop(pin);

    match sign_result {
        Ok(der_signature) => {
            match create_ethereum_signature(&der_signature, &hash_bytes, &key_info.public_key) {
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
            report_sign_error(&e);
            ExitCode::FAILURE
        }
    }
}

fn cmd_bridge(args: &[String]) -> ExitCode {
    let mut port = DEFAULT_BRIDGE_PORT;
    let mut extra_origins: Vec<String> = Vec::new();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                let Some(port_str) = args.get(i) else {
                    eprintln!("Error: --port requires a port number");
                    return ExitCode::FAILURE;
                };
                match port_str.parse::<u16>() {
                    Ok(parsed) => port = parsed,
                    Err(e) => {
                        eprintln!("Error: invalid port '{port_str}': {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--allow-origin" => {
                i += 1;
                let Some(origin) = args.get(i) else {
                    eprintln!("Error: --allow-origin requires an Origin URL");
                    return ExitCode::FAILURE;
                };
                extra_origins.push(origin.clone());
            }
            "--help" | "-h" => {
                println!("Usage: yubikey-cli bridge [--port <port>] [--allow-origin <origin>]...");
                return ExitCode::SUCCESS;
            }
            unknown => {
                eprintln!("Unknown bridge option: {unknown}");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }

    let mut config = match BridgeConfig::loopback(port) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to initialize bridge config: {e}");
            return ExitCode::FAILURE;
        }
    };

    for origin in extra_origins {
        if let Err(e) = config.add_allowed_origin(origin) {
            eprintln!("Invalid --allow-origin value: {e}");
            return ExitCode::FAILURE;
        }
    }

    let handle = match BridgeServer::start(config, || {
        let transport = PcscTransport::connect()?;
        let boxed: Box<dyn Transport + Send> = Box::new(transport);
        Ok(boxed)
    }) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("Failed to start local PC/SC bridge: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("YubiKey Local PC/SC Bridge listening on {}", handle.url());
    println!();
    println!("Allowed Origins:");
    for origin in handle.allowed_origins() {
        println!("  - {origin}");
    }
    println!();
    println!("Session Bearer Token (paste into browser demo):");
    println!("  {}", handle.token());
    println!();
    println!("Security: loopback-only, exact Origin allowlist, PIV-only APDU allowlist.");
    println!("Press Ctrl+C to stop the bridge.");

    let _keep_alive = handle;
    loop {
        std::thread::park();
    }
}

fn prompt_pin() -> io::Result<String> {
    rpassword::prompt_password("Enter PIN: ")
}

/// Asks the user to type `slot_id`; returns `Ok(true)` only on an exact
/// (case-insensitive) match. End of input counts as a mismatch.
fn confirm_slot(slot_id: &str) -> Result<bool, String> {
    print!("Type the slot id ({slot_id}) to confirm replacing its key: ");
    io::stdout()
        .flush()
        .map_err(|e| format!("failed to flush stdout: {e}"))?;

    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("failed to read confirmation: {e}"))?;

    Ok(line.trim().eq_ignore_ascii_case(slot_id))
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
