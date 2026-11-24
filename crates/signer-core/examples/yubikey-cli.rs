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
//! just cli-address       # Show the P-256 public key and derived address
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
//!    just cli-generate --pubkey-out pubkey.pem
//!    # Shows what slot 9a currently holds, asks you to type `9a` to confirm
//!    # (`generate --force` skips this), then prompts for the management key
//!    # algorithm and management key. The slot's old certificate is deleted.
//!    # The new public key is printed (hex and PEM) and, with `--pubkey-out`,
//!    # also written as PEM to a new file.
//!    ```
//!
//! 2. **Create a certificate** (only needed on firmware older than 5.3, where the
//!    key can only be read back through a certificate):
//!    ```bash
//!    ykman piv certificates generate -s "CN=YubiKey EVM Signer" 9a pubkey.pem
//!    ```
//!    On firmware 4.3 or later, `ykman piv keys export 9a pubkey.pem` can also
//!    recover the PEM.
//!
//! 3. **Show the public key and derived address**:
//!    ```bash
//!    just cli-address
//!    ```
//!    The address is `keccak256(X‖Y)[12..]` of the P-256 key, not a secp256k1
//!    account: do not send funds to it on chains that validate transactions with
//!    secp256k1. Register the printed public key with an EIP-7951 verifier.
//!
//! 4. **Sign transaction hashes** (P-256 signatures for EIP-7951 verifiers):
//!    ```bash
//!    just cli-sign-tx
//!    # Or sign a custom hash:
//!    just cli-sign 0x0123456789abcdef...  # 32-byte hash
//!    ```

#![allow(unused_crate_dependencies)]

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use p256::ecdsa::VerifyingKey;
use p256::pkcs8::{EncodePublicKey, LineEnding};
use yubikey_evm_signer_core::Error;
use yubikey_evm_signer_core::bridge::{
    BridgeConfig, BridgeServer, DEFAULT_BRIDGE_PORT, DEFAULT_IDLE_TIMEOUT,
};
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
    let default_idle = DEFAULT_IDLE_TIMEOUT.as_secs();
    println!(
        r#"YubiKey EVM Signer CLI

USAGE:
    yubikey-cli <COMMAND>

COMMANDS:
    list        List available YubiKey devices
    info        Show YubiKey connection info
    address     Show slot 9a's P-256 public key and derived address
    generate    Generate a new P-256 key in slot 9a (requires management key)
    sign <hex>  Sign a 32-byte hash (requires PIN)
    sign-tx     Sign a sample EIP-1559 transaction hash (requires PIN)
    bridge      Start hardened local PC/SC HTTP bridge for browser apps
    help        Show this help message

GENERATE OPTIONS:
    --force               Skip the typed slot confirmation (for scripted use)
    --pubkey-out <path>   Also write the new public key as PEM to <path>, which
                          must not exist yet (checked before the card is changed)

BRIDGE OPTIONS:
    --port <port>             TCP port on 127.0.0.1 (default: {DEFAULT_BRIDGE_PORT})
    --allow-origin <origin>   Additional allowed browser Origin (repeatable)
    --idle-timeout <seconds>  Close an idle YubiKey session and reset the card after
                              this many seconds ({MIN_IDLE_TIMEOUT_SECS}-{MAX_IDLE_TIMEOUT_SECS}, default: {default_idle})
    --allow-generate          Allow browser pages to generate keys (overwrites slots;
                              disabled by default)

EXAMPLES:
    cargo run --example yubikey-cli --features pcsc -- list
    cargo run --example yubikey-cli --features pcsc -- address
    cargo run --example yubikey-cli --features pcsc -- generate
    cargo run --example yubikey-cli --features pcsc -- bridge --port 8765
    cargo run --example yubikey-cli --features pcsc -- bridge --idle-timeout 300 --allow-generate
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
    eprintln!("Older firmware can only report the key through a certificate. Store one");
    eprintln!("for the PEM that `generate` printed (or saved with `--pubkey-out`):");
    eprintln!("  ykman piv certificates generate -s \"CN=YubiKey EVM Signer\" 9a pubkey.pem");
    eprintln!("On firmware 4.3 or later, `ykman piv keys export 9a pubkey.pem` also works.");
}

/// Prints a one-line warning when the slot's certificate describes another key.
fn warn_if_stale_certificate(info: &SlotPublicKey) {
    if info.stale_certificate {
        eprintln!(
            "Warning: the certificate in slot 9a does not match the slot's key; ignoring the stale certificate."
        );
    }
}

/// Label printed above the keccak-derived address of the P-256 key.
const ADDRESS_LABEL: &str = "Derived Address (keccak256 of the P-256 key; not a secp256k1 account)";

/// One-line explanation printed after the derived address.
const ADDRESS_NOTE: &str = "Do not send funds to this address on chains that validate transactions with \
     secp256k1; register the public key with an EIP-7951 (P256VERIFY) verifier instead.";

/// Prints the slot 9a key that is about to sign, before the PIN prompt.
fn print_signing_key(info: &SlotPublicKey) {
    println!("Signing with the slot 9a P-256 key:");
    println!(
        "  Public Key: {}",
        hex::encode(info.public_key.to_sec1_point(false).as_bytes())
    );
    println!(
        "  Derived Address: {}",
        Address::from_public_key(&info.public_key)
    );
    println!();
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
    println!("Reading the P-256 public key of slot 9a...\n");

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
            println!("{ADDRESS_LABEL}:");
            println!("  {address}");
            println!();
            println!("{ADDRESS_NOTE}");
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

const GENERATE_USAGE: &str = "Usage: yubikey-cli generate [--force] [--pubkey-out <path>]";

/// What `yubikey-cli generate` was asked to do.
#[derive(Debug, PartialEq, Eq)]
enum GenerateCommand {
    /// Print the usage line.
    Help,
    /// Generate a key.
    Run {
        /// Skip the typed slot confirmation.
        force: bool,
        /// New file to write the public key PEM to.
        pubkey_out: Option<PathBuf>,
    },
}

/// Parses the arguments that follow `generate`.
fn parse_generate_args(args: &[String]) -> Result<GenerateCommand, String> {
    let mut force = false;
    let mut pubkey_out = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--force" => force = true,
            "--pubkey-out" => {
                let path = match args.next() {
                    Some(path) if !path.is_empty() && !path.starts_with('-') => path,
                    _ => return Err("Error: --pubkey-out requires a file path".to_string()),
                };
                if pubkey_out.replace(PathBuf::from(path)).is_some() {
                    return Err("Error: --pubkey-out given more than once".to_string());
                }
            }
            "--help" | "-h" => return Ok(GenerateCommand::Help),
            unknown => return Err(format!("Unknown generate option: {unknown}")),
        }
    }
    Ok(GenerateCommand::Run { force, pubkey_out })
}

/// Encodes `key` as a SubjectPublicKeyInfo PEM (`-----BEGIN PUBLIC KEY-----`).
fn public_key_pem(key: &VerifyingKey) -> Result<String, String> {
    key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("failed to encode the public key as PEM: {e}"))
}

/// The `--pubkey-out` file, created before the card is touched.
///
/// The file is created exclusively (an existing file or symlink is never
/// replaced) and is removed again when dropped unless [`Self::write_pem`]
/// succeeded, so an aborted or failed run leaves no empty or partial file.
#[derive(Debug)]
struct PubkeyOutFile {
    path: PathBuf,
    file: File,
    written: bool,
}

impl PubkeyOutFile {
    /// Creates `path`, failing if it already exists or cannot be created.
    fn create(path: PathBuf) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o644);
        let file = options.open(&path)?;
        Ok(Self {
            path,
            file,
            written: false,
        })
    }

    /// Writes `pem` to the file and flushes it to disk.
    fn write_pem(&mut self, pem: &str) -> io::Result<()> {
        self.file.write_all(pem.as_bytes())?;
        self.file.sync_all()?;
        self.written = true;
        Ok(())
    }
}

impl Drop for PubkeyOutFile {
    fn drop(&mut self) {
        if !self.written {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn cmd_generate(args: &[String]) -> ExitCode {
    let (force, pubkey_out) = match parse_generate_args(args) {
        Ok(GenerateCommand::Run { force, pubkey_out }) => (force, pubkey_out),
        Ok(GenerateCommand::Help) => {
            println!("{GENERATE_USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("{e}");
            eprintln!("{GENERATE_USAGE}");
            return ExitCode::FAILURE;
        }
    };

    // Claim the output file before anything else, so an unusable path fails
    // while the slot is still untouched.
    let mut pubkey_file = match pubkey_out {
        Some(path) => match PubkeyOutFile::create(path.clone()) {
            Ok(file) => Some(file),
            Err(e) => {
                eprintln!(
                    "Error: cannot create {} for --pubkey-out: {e}. It must be a new file in an \
                     existing, writable directory. No changes were made.",
                    path.display()
                );
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

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
                "  Public Key: {}",
                hex::encode(info.public_key.to_sec1_point(false).as_bytes())
            );
            println!(
                "  Derived Address: {}",
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
    println!("destroyed and cannot be recovered; anything that relies on it (for example a");
    println!("smart account that registered its public key) can no longer be signed for.");
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
            // The key now exists on the card: print it before anything that can
            // fail, so it is never lost.
            let address = Address::from_public_key(&generated.public_key);
            println!();
            println!("Key generated successfully!");
            println!();
            println!("Public Key (uncompressed):");
            let encoded = generated.public_key.to_sec1_point(false);
            println!("  {}", hex::encode(encoded.as_bytes()));
            println!();
            let pem = match public_key_pem(&generated.public_key) {
                Ok(pem) => {
                    println!("Public Key (PEM):");
                    print!("{pem}");
                    Some(pem)
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    None
                }
            };
            println!();
            println!("{ADDRESS_LABEL}:");
            println!("  {address}");
            println!();
            println!("{ADDRESS_NOTE}");
            println!();
            if let Some(e) = &generated.certificate_delete_error {
                eprintln!(
                    "Warning: the old certificate in slot 9a could not be removed ({e}). It describes the previous key; delete or replace it (e.g. `ykman piv certificates delete 9a`)."
                );
                eprintln!();
            }

            let mut status = if pem.is_some() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
            let mut pem_path = None;
            if let Some(file) = pubkey_file.as_mut() {
                match pem.as_deref().map(|pem| file.write_pem(pem)) {
                    Some(Ok(())) => {
                        println!("Public key PEM written to {}", file.path.display());
                        println!();
                        pem_path = Some(file.path.display().to_string());
                    }
                    Some(Err(e)) => {
                        eprintln!(
                            "Error: the key WAS generated, but writing {} failed: {e}. Save the \
                             public key printed above; the incomplete file is removed.",
                            file.path.display()
                        );
                        eprintln!();
                        status = ExitCode::FAILURE;
                    }
                    None => {}
                }
            }

            println!(
                "On YubiKey firmware 5.3 or later, `address` reads this key directly from the slot."
            );
            println!("On older firmware, store a certificate so that `address` can find it:");
            match pem_path {
                Some(path) => println!(
                    "  ykman piv certificates generate -s \"CN=YubiKey EVM Signer\" 9a {path}"
                ),
                None => {
                    println!("  (save the PEM above as pubkey.pem first)");
                    println!(
                        "  ykman piv certificates generate -s \"CN=YubiKey EVM Signer\" 9a pubkey.pem"
                    );
                }
            }
            status
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
    print_signing_key(&key_info);

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
                    println!("Signature (r || s || v):");
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
    println!("Creating and signing a sample EIP-1559 transaction hash...\n");

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
    print_signing_key(&key_info);

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
                    println!("Transaction hash signed successfully!");
                    println!();
                    println!("Signature (low-S):");
                    println!("  r: 0x{}", hex::encode(eth_sig.r()));
                    println!("  s: 0x{}", hex::encode(eth_sig.s()));
                    println!("  v: {}", eth_sig.v());
                    println!();
                    println!("Full Signature (65 bytes):");
                    println!("  {eth_sig}");
                    println!();
                    println!(
                        "This is a P-256 signature for EIP-7951 (P256VERIFY) verifiers; standard EVM nodes"
                    );
                    println!("do not accept it as a transaction signature.");
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

/// Smallest `--idle-timeout` accepted by the CLI, in seconds.
const MIN_IDLE_TIMEOUT_SECS: u64 = 10;

/// Largest `--idle-timeout` accepted by the CLI, in seconds.
const MAX_IDLE_TIMEOUT_SECS: u64 = 3600;

const BRIDGE_USAGE: &str = "Usage: yubikey-cli bridge [--port <port>] [--allow-origin <origin>]... \
     [--idle-timeout <seconds>] [--allow-generate]";

fn cmd_bridge(args: &[String]) -> ExitCode {
    let mut port = DEFAULT_BRIDGE_PORT;
    let mut extra_origins: Vec<String> = Vec::new();
    let mut idle_timeout = DEFAULT_IDLE_TIMEOUT;
    let mut allow_generate = false;
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
            "--idle-timeout" => {
                i += 1;
                let Some(secs_str) = args.get(i) else {
                    eprintln!("Error: --idle-timeout requires a number of seconds");
                    return ExitCode::FAILURE;
                };
                match secs_str.parse::<u64>() {
                    Ok(secs) if (MIN_IDLE_TIMEOUT_SECS..=MAX_IDLE_TIMEOUT_SECS).contains(&secs) => {
                        idle_timeout = Duration::from_secs(secs);
                    }
                    _ => {
                        eprintln!(
                            "Error: --idle-timeout must be a whole number of seconds between \
                             {MIN_IDLE_TIMEOUT_SECS} and {MAX_IDLE_TIMEOUT_SECS}, got '{secs_str}'"
                        );
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--allow-generate" => allow_generate = true,
            "--help" | "-h" => {
                println!("{BRIDGE_USAGE}");
                return ExitCode::SUCCESS;
            }
            unknown => {
                eprintln!("Unknown bridge option: {unknown}");
                eprintln!("{BRIDGE_USAGE}");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }

    let config = BridgeConfig::loopback(port)
        .and_then(|config| config.with_idle_timeout(idle_timeout))
        .map(|config| config.with_allow_key_generation(allow_generate));
    let mut config = match config {
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

    // Install the SIGINT/SIGTERM (and SIGHUP) handler before the bridge exists,
    // so a signal always leads to a graceful shutdown that resets the card. A
    // second signal while shutting down exits immediately.
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let signalled = AtomicBool::new(false);
    if let Err(e) = ctrlc::set_handler(move || {
        if signalled.swap(true, Ordering::SeqCst) {
            std::process::exit(130);
        }
        let _ = stop_tx.send(());
    }) {
        eprintln!("Failed to install the signal handler: {e}");
        return ExitCode::FAILURE;
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
    println!("(use exactly this URL; localhost and [::1] are rejected)");
    println!();
    println!("Allowed Origins:");
    for origin in handle.allowed_origins() {
        println!("  - {origin}");
    }
    println!();
    println!("Bearer Token (valid until the bridge stops; paste into the browser page):");
    println!("  {}", handle.token());
    println!();
    if handle.allow_key_generation() {
        println!(
            "Key generation: ENABLED (--allow-generate): pages holding the token and the \
             management key can overwrite PIV keys."
        );
    } else {
        println!("Key generation: disabled (start with --allow-generate to enable it).");
    }
    println!(
        "Idle timeout: {} s (an idle session is closed and the card reset).",
        handle.idle_timeout().as_secs()
    );
    println!("Security: 127.0.0.1 only, exact Origin allowlist, PIV-only APDU allowlist.");
    println!("Press Ctrl+C to stop the bridge.");

    let _ = stop_rx.recv();
    println!();
    println!("Stopping the bridge...");
    handle.shutdown();
    println!("Bridge stopped; the YubiKey session was closed.");
    ExitCode::SUCCESS
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
        "Management key algorithm [tdes/aes128/aes192/aes256] (default: aes192; factory default is tdes before firmware 5.7): "
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    /// A fresh, empty directory removed when dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = env::temp_dir().join(format!("yubikey-cli-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn public_key_pem_matches_openssl() {
        // The P-256 base point G (private key 1). Expected value produced by
        // `openssl pkey -pubin -inform DER` from the SubjectPublicKeyInfo DER.
        let point = hex::decode(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
             4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
        .unwrap();
        let key = VerifyingKey::from_sec1_bytes(&point).unwrap();
        assert_eq!(
            public_key_pem(&key).unwrap(),
            "-----BEGIN PUBLIC KEY-----\n\
             MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt\n\
             6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==\n\
             -----END PUBLIC KEY-----\n"
        );
    }

    #[test]
    fn parse_generate_args_accepts_options() {
        assert_eq!(
            parse_generate_args(&[]),
            Ok(GenerateCommand::Run {
                force: false,
                pubkey_out: None
            })
        );
        assert_eq!(
            parse_generate_args(&args(&["--pubkey-out", "out/key.pem", "--force"])),
            Ok(GenerateCommand::Run {
                force: true,
                pubkey_out: Some(PathBuf::from("out/key.pem"))
            })
        );
        assert_eq!(
            parse_generate_args(&args(&["--force", "--help"])),
            Ok(GenerateCommand::Help)
        );
    }

    #[test]
    fn parse_generate_args_rejects_bad_pubkey_out() {
        for bad in [
            &["--pubkey-out"][..],
            &["--pubkey-out", ""],
            &["--pubkey-out", "--force"],
            &["--pubkey-out", "-"],
        ] {
            assert_eq!(
                parse_generate_args(&args(bad)),
                Err("Error: --pubkey-out requires a file path".to_string()),
                "{bad:?}"
            );
        }
        assert_eq!(
            parse_generate_args(&args(&["--pubkey-out", "a.pem", "--pubkey-out", "b.pem"])),
            Err("Error: --pubkey-out given more than once".to_string())
        );
        assert_eq!(
            parse_generate_args(&args(&["--pubkey-out=a.pem"])),
            Err("Unknown generate option: --pubkey-out=a.pem".to_string())
        );
    }

    #[test]
    fn pubkey_out_file_refuses_unusable_paths() {
        let dir = TempDir::new("unusable");
        let existing = dir.0.join("existing.pem");
        fs::write(&existing, "keep me").unwrap();

        let err = PubkeyOutFile::create(existing.clone()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&existing).unwrap(), "keep me");

        assert!(PubkeyOutFile::create(dir.0.join("missing").join("key.pem")).is_err());
    }

    #[test]
    fn pubkey_out_file_is_removed_unless_written() {
        let dir = TempDir::new("cleanup");
        let path = dir.0.join("key.pem");

        drop(PubkeyOutFile::create(path.clone()).unwrap());
        assert!(!path.exists(), "an unwritten file must be removed");

        let mut file = PubkeyOutFile::create(path.clone()).unwrap();
        file.write_pem("PEM\n").unwrap();
        drop(file);
        assert_eq!(fs::read_to_string(&path).unwrap(), "PEM\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode & !0o644, 0, "mode {mode:o}");
        }
    }
}
