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
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::time::Duration;

use p256::ecdsa::VerifyingKey;
use p256::pkcs8::{EncodePublicKey, LineEnding};
use yubikey_evm_signer_core::Error;
use yubikey_evm_signer_core::bridge::{
    BridgeConfig, BridgeServer, DEFAULT_BRIDGE_PORT, DEFAULT_IDLE_TIMEOUT,
};
use yubikey_evm_signer_core::crypto::create_ethereum_signature;
use yubikey_evm_signer_core::yubikey::{
    GeneratedKey, ManagementKeyAlgorithm, PcscTransport, PivSession, PublicKeySource, Slot,
    SlotPublicKey, Transport,
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
                          must not exist yet (checked before the prompts; the
                          file is created after them, before the card is changed)

GENERATE EXIT STATUS:
    0    Key generated; its public key was printed (and written to --pubkey-out)
    1    Failed, or the key was generated but an output (standard output or
         error, or the --pubkey-out file) could not be written; see the messages
    130  Interrupted. An interrupt while slot 9a is being changed is deferred:
         the command stops before the key is generated if it still can (130),
         and otherwise finishes, reports the new key and exits 0 or 1 as above.
         A second interrupt quits at once (130) and can lose a key generated
         by then.

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
/// Returns `false` if the warning was needed but could not be written.
fn warn_if_stale_certificate(info: &SlotPublicKey) -> bool {
    !info.stale_certificate
        || writeln!(
            io::stderr(),
            "Warning: the certificate in slot 9a does not match the slot's key; ignoring the stale certificate."
        )
        .is_ok()
}

/// Writes `text` to standard output without panicking.
///
/// For output that follows an operation that cannot simply be repeated (a
/// signature that used a PIN verification): if standard output fails, the
/// error and `fallback` are written to standard error instead. Returns whether
/// standard output received `text`.
fn print_result(text: &str, fallback: &str) -> bool {
    let mut out = io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => true,
        Err(e) => {
            let _ = writeln!(
                io::stderr(),
                "Error: cannot write to standard output ({e}).\n{fallback}"
            );
            false
        }
    }
}

/// Quotes `arg` as a single POSIX shell word, so a printed command line can be
/// copied safely.
///
/// `arg` is returned unchanged if it is non-empty, does not start with `-`, and
/// consists only of ASCII letters, digits and `_ . / + , : @ -`; otherwise it is
/// wrapped in single quotes, with each `'` written as `'\''`.
fn shell_quote(arg: &str) -> String {
    let plain = !arg.is_empty()
        && !arg.starts_with('-')
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./+,:@-".contains(&b));
    if plain {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
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

/// Connects to the first YubiKey in shared mode and wraps it in a PIV session.
fn connect_session() -> Option<PivSession> {
    match PcscTransport::connect() {
        Ok(transport) => Some(PivSession::new(Box::new(transport))),
        Err(e) => {
            let _ = writeln!(io::stderr(), "Failed to connect: {e}");
            None
        }
    }
}

/// Connects to the first YubiKey with exclusive PC/SC access and wraps it in a PIV session.
///
/// Used for operations that verify a PIN or authenticate the management key so
/// no other local PC/SC client can use that card state before the session drops
/// and resets the card.
fn connect_exclusive_session() -> Option<PivSession> {
    match PcscTransport::connect_exclusive() {
        Ok(transport) => Some(PivSession::new(Box::new(transport))),
        Err(e) => {
            let _ = writeln!(io::stderr(), "Failed to connect: {e}");
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

/// Checks that `path` can become the `--pubkey-out` file, without creating it:
/// nothing (not even a dangling symlink) exists there yet, and its parent is an
/// existing directory.
///
/// This only gives an early, clear error before the prompts.
/// [`PubkeyOutFile::create`] repeats the existence check atomically when it
/// creates the file, right before the card is changed.
fn check_pubkey_out_path(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "it already exists",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if fs::metadata(parent)?.is_dir() {
        Ok(())
    } else {
        Err(io::Error::other("its parent is not a directory"))
    }
}

/// Reports that `path` cannot be used for `--pubkey-out` (nothing was changed).
fn report_unusable_pubkey_out(path: &Path, e: &io::Error) {
    let _ = writeln!(
        io::stderr(),
        "Error: cannot create {} for --pubkey-out: {e}. It must be a new file in an \
         existing, writable directory. No changes were made.",
        path.display()
    );
}

/// Who may remove the `--pubkey-out` file, shared between the main thread and
/// the `generate` signal handler without any lock, so the handler can never
/// wait for a main thread that is stuck writing to a stalled console.
///
/// States (`state`), and who moves between them:
///
/// - [`Self::NO_FILE`]: no file was created. Nobody removes anything.
/// - [`Self::EMPTY`]: the file exists and holds nothing yet; `path` is set.
///   The main thread or the handler may remove it, but only after winning the
///   compare-and-swap `EMPTY` → [`Self::GONE`] ([`Self::remove_if_empty`]), so
///   exactly one of them does.
/// - [`Self::MAIN`]: the main thread won `EMPTY` → `MAIN`
///   ([`Self::claim_for_writing`]) to write the PEM. From then on only the main
///   thread touches the file: it keeps it once written and removes it if the
///   write failed. The handler leaves it alone.
/// - [`Self::GONE`]: removed by whoever won `EMPTY` → `GONE`. Nobody touches
///   the path again (it may already belong to someone else).
#[derive(Debug, Default)]
struct PubkeyOutReservation {
    path: OnceLock<PathBuf>,
    state: AtomicU8,
}

impl PubkeyOutReservation {
    const NO_FILE: u8 = 0;
    const EMPTY: u8 = 1;
    const MAIN: u8 = 2;
    const GONE: u8 = 3;

    /// Records that `path` was just created and is empty (`NO_FILE` → `EMPTY`).
    /// Does nothing if a path was already recorded.
    fn created(&self, path: PathBuf) {
        if self.path.set(path).is_ok() {
            let _ = self.state.compare_exchange(
                Self::NO_FILE,
                Self::EMPTY,
                Ordering::Release,
                Ordering::Relaxed,
            );
        }
    }

    /// `EMPTY` → `to`; returns whether this call made the transition.
    fn take_empty(&self, to: u8) -> bool {
        self.state
            .compare_exchange(Self::EMPTY, to, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Removes the file if it is still empty and unclaimed (`EMPTY` → `GONE`).
    /// Never waits for the other thread. Returns whether this call removed it.
    fn remove_if_empty(&self) -> bool {
        if !self.take_empty(Self::GONE) {
            return false;
        }
        if let Some(path) = self.path.get() {
            let _ = fs::remove_file(path);
        }
        true
    }

    /// Claims the empty file for the main thread to write (`EMPTY` → `MAIN`).
    /// Returns `false` if it was already removed.
    fn claim_for_writing(&self) -> bool {
        self.take_empty(Self::MAIN)
    }
}

/// The `--pubkey-out` file, created right before the card is changed.
///
/// The file is created exclusively (an existing file or symlink is never
/// replaced) and is removed again when dropped unless [`Self::write_pem`]
/// succeeded, so a failed run leaves no empty or partial file. `reservation`
/// lets the signal handler remove it too while it is still empty.
#[derive(Debug)]
struct PubkeyOutFile {
    path: PathBuf,
    file: File,
    reservation: Arc<PubkeyOutReservation>,
    /// Whether [`PubkeyOutReservation::claim_for_writing`] succeeded.
    claimed: bool,
    written: bool,
}

impl PubkeyOutFile {
    /// Creates `path`, failing if it already exists or cannot be created, and
    /// records it in `reservation`.
    fn create(path: PathBuf, reservation: Arc<PubkeyOutReservation>) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o644);
        let file = options.open(&path)?;
        reservation.created(path.clone());
        Ok(Self {
            path,
            file,
            reservation,
            claimed: false,
            written: false,
        })
    }

    /// Claims the file, writes `pem` to it and flushes it to disk. Fails without
    /// writing if an interrupt already removed the file.
    fn write_pem(&mut self, pem: &str) -> io::Result<()> {
        if !self.claimed {
            if !self.reservation.claim_for_writing() {
                return Err(io::Error::other("an interrupt removed it"));
            }
            self.claimed = true;
        }
        self.file.write_all(pem.as_bytes())?;
        self.file.sync_all()?;
        self.written = true;
        Ok(())
    }
}

impl Drop for PubkeyOutFile {
    fn drop(&mut self) {
        if self.claimed {
            if !self.written {
                let _ = fs::remove_file(&self.path);
            }
        } else {
            self.reservation.remove_if_empty();
        }
    }
}

/// Handles one SIGINT/SIGTERM/SIGHUP during `generate`; returns whether the
/// process must exit now (status 130).
///
/// The first signal only sets `interrupted`, which the main thread checks
/// before GENERATE. A later one removes the `--pubkey-out` file if it is still
/// empty. This touches only atomics and the file system, never a lock or the
/// console, so it cannot wait for the main thread.
fn generate_interrupt(interrupted: &AtomicBool, pubkey_out: &PubkeyOutReservation) -> bool {
    if !interrupted.swap(true, Ordering::SeqCst) {
        return false;
    }
    pubkey_out.remove_if_empty();
    true
}

/// Which outputs received the public key of a newly generated key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeyDelivery {
    /// Whether the key could be encoded as PEM.
    pem: bool,
    /// `None` without `--pubkey-out`; otherwise whether the PEM was written to
    /// the file and synced.
    file: Option<bool>,
    /// Whether the whole report was written to standard output.
    stdout: bool,
    /// Whether every warning, error, fallback and interrupt note was written to
    /// standard error.
    stderr: bool,
}

impl KeyDelivery {
    /// Whether every output received everything (exit status 0).
    const fn complete(&self) -> bool {
        self.pem && !matches!(self.file, Some(false)) && self.stdout && self.stderr
    }
}

/// Delivers the public key of a key that was just generated in slot 9a.
///
/// The key now exists only on the card, and on firmware without metadata or
/// attestation it cannot be read back, so this is the only chance to hand it
/// to the user. The PEM is therefore written to `file` and synced **before**
/// anything is written to the console, and every write is fallible and
/// handled: a failed output never skips or undoes another one. If `out` fails,
/// the key is written to `err` instead. If `interrupted` is set by the time the
/// console is written, a note that the interrupt was deferred ends `err`.
fn deliver_generated_key(
    generated: &GeneratedKey,
    file: Option<&mut PubkeyOutFile>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    interrupted: &AtomicBool,
) -> KeyDelivery {
    let key_hex = hex::encode(generated.public_key.to_sec1_point(false).as_bytes());
    let pem = public_key_pem(&generated.public_key);
    let mut errors = Vec::new();
    if let Err(e) = &pem {
        errors.push(format!("Error: {e}"));
    }

    // 1. The file, before anything that can fail on the console.
    let mut saved_to = None;
    let file_written = file.map(|file| {
        let result = match &pem {
            Ok(pem) => file.write_pem(pem),
            Err(e) => Err(io::Error::other(e.clone())),
        };
        match result {
            Ok(()) => {
                saved_to = Some(file.path.clone());
                true
            }
            Err(e) => {
                errors.push(format!(
                    "Error: the key WAS generated, but writing {} failed: {e}. Save the public \
                     key printed on the console; the incomplete file is removed.",
                    file.path.display()
                ));
                false
            }
        }
    });

    if let Some(e) = &generated.certificate_delete_error {
        errors.push(format!(
            "Warning: the old certificate in slot 9a could not be removed ({e}). It describes \
             the previous key; delete or replace it (e.g. `ykman piv certificates delete 9a`)."
        ));
    }

    // 2. The console.
    let address = Address::from_public_key(&generated.public_key);
    let mut text =
        format!("\nKey generated successfully!\n\nPublic Key (uncompressed):\n  {key_hex}\n\n");
    if let Ok(pem) = &pem {
        text.push_str("Public Key (PEM):\n");
        text.push_str(pem);
        text.push('\n');
    }
    text.push_str(&format!(
        "{ADDRESS_LABEL}:\n  {address}\n\n{ADDRESS_NOTE}\n\n"
    ));
    if let Some(path) = &saved_to {
        text.push_str(&format!("Public key PEM written to {}\n\n", path.display()));
    }
    text.push_str(
        "On YubiKey firmware 5.3 or later, `address` reads this key directly from the slot.\n\
         On older firmware, store a certificate so that `address` can find it:\n",
    );
    match &saved_to {
        Some(path) => text.push_str(&format!(
            "  ykman piv certificates generate -s \"CN=YubiKey EVM Signer\" 9a {}\n",
            shell_quote(&path.to_string_lossy())
        )),
        None => text.push_str(
            "  (save the PEM above as pubkey.pem first)\n  \
             ykman piv certificates generate -s \"CN=YubiKey EVM Signer\" 9a pubkey.pem\n",
        ),
    }
    let stdout = match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => true,
        Err(e) => {
            let mut fallback = format!(
                "Error: the key WAS generated, but standard output failed ({e}). Its public \
                 key (uncompressed):\n  {key_hex}\n"
            );
            if let Ok(pem) = &pem {
                fallback.push_str(pem);
            }
            if let Some(path) = &saved_to {
                fallback.push_str(&format!(
                    "The PEM was also written to {}.\n",
                    path.display()
                ));
            }
            errors.push(fallback);
            false
        }
    };

    if interrupted.load(Ordering::SeqCst) {
        errors.push(
            "Interrupted while the key was being generated; finished so that its public key is \
             not lost."
                .to_string(),
        );
    }

    let mut stderr = true;
    for message in &errors {
        stderr &= writeln!(err, "{message}").is_ok();
    }
    stderr &= err.flush().is_ok();

    KeyDelivery {
        pem: pem.is_ok(),
        file: file_written,
        stdout,
        stderr,
    }
}

/// Writes `text` to standard output before the card is changed. On failure,
/// reports it and returns `false` so the caller can abort with nothing changed.
fn print_before_card_change(text: &str) -> bool {
    let mut out = io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => true,
        Err(e) => {
            let _ = writeln!(
                io::stderr(),
                "Error: cannot write to standard output ({e}). Aborting; no changes were made."
            );
            false
        }
    }
}

/// What the PC/SC transaction of `generate` did to slot 9a.
enum CardChange {
    /// The key was generated (the slot's old key is gone).
    Generated(GeneratedKey),
    /// Management key authentication failed; the slot is unchanged.
    AuthFailed(Error),
    /// An interrupt arrived before GENERATE was sent; the slot is unchanged.
    Interrupted,
}

/// Exit status of a `generate` that was interrupted.
const EXIT_INTERRUPTED: u8 = 130;

fn cmd_generate(args: &[String]) -> ExitCode {
    let (force, pubkey_out) = match parse_generate_args(args) {
        Ok(GenerateCommand::Run { force, pubkey_out }) => (force, pubkey_out),
        Ok(GenerateCommand::Help) => {
            return if writeln!(io::stdout(), "{GENERATE_USAGE}").is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        Err(e) => {
            let _ = writeln!(io::stderr(), "{e}\n{GENERATE_USAGE}");
            return ExitCode::FAILURE;
        }
    };

    // Check the output path first, so an unusable path fails before any prompt.
    // The file itself is created only after the prompts, right before the card
    // is changed, so interrupting a prompt leaves nothing behind.
    if let Some(path) = &pubkey_out
        && let Err(e) = check_pubkey_out_path(path)
    {
        report_unusable_pubkey_out(path, &e);
        return ExitCode::FAILURE;
    }

    if !print_before_card_change("Generating new P-256 key in slot 9a...\n\n") {
        return ExitCode::FAILURE;
    }

    // Connect and inspect the slot before prompting for sensitive credentials,
    // then release the shared handle until the user confirms and enters the key.
    let slot_report = {
        let Some(mut session) = connect_session() else {
            return ExitCode::FAILURE;
        };

        match read_slot_public_key(&mut session) {
            Ok(info) => {
                // Like the output below: abort, with nothing changed, if it fails.
                if !warn_if_stale_certificate(&info) {
                    return ExitCode::FAILURE;
                }
                format!(
                    "Slot 9a already holds a P-256 key:\n  Public Key: {}\n  Derived Address: {}\n",
                    hex::encode(info.public_key.to_sec1_point(false).as_bytes()),
                    Address::from_public_key(&info.public_key)
                )
            }
            Err(Error::SlotEmpty(_)) => "Slot 9a appears to be empty.\n\
                 (On firmware older than 5.3 a key without a certificate cannot be detected.)\n"
                .to_string(),
            Err(Error::InvalidKeyType(_)) => {
                "Slot 9a holds a key or certificate that is not P-256.\n".to_string()
            }
            Err(e) => {
                let _ = writeln!(
                    io::stderr(),
                    "Failed to inspect slot 9a: {e}\nAborting; no changes were made."
                );
                return ExitCode::FAILURE;
            }
        }
    };
    if !print_before_card_change(&format!(
        "{slot_report}\n\
         WARNING: This replaces any existing key in slot 9a. The old private key is\n\
         destroyed and cannot be recovered; anything that relies on it (for example a\n\
         smart account that registered its public key) can no longer be signed for.\n\n"
    )) {
        return ExitCode::FAILURE;
    }

    if !force {
        match confirm_slot("9a") {
            Ok(true) => {}
            Ok(false) => {
                let _ = writeln!(
                    io::stderr(),
                    "Confirmation did not match; aborting. No changes were made."
                );
                return ExitCode::FAILURE;
            }
            Err(e) => {
                let _ = writeln!(io::stderr(), "{e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let alg = match prompt_management_key_algorithm() {
        Ok(alg) => alg,
        Err(e) => {
            let _ = writeln!(io::stderr(), "{e}");
            return ExitCode::FAILURE;
        }
    };

    let mgmt_key = match prompt_management_key(alg) {
        Ok(key) => Zeroizing::new(key),
        Err(e) => {
            let _ = writeln!(io::stderr(), "{e}");
            return ExitCode::FAILURE;
        }
    };

    if !print_before_card_change(&format!(
        "Authenticating with management key ({alg:?}) and generating a P-256 key in slot 9a...\n"
    )) {
        return ExitCode::FAILURE;
    }

    // From here on, an interrupt must not kill the process between GENERATE and
    // the output of the new key; see `generate_interrupt`. The handler shares
    // only atomics with this thread, so a second interrupt quits at once even
    // while this thread is blocked writing to the console.
    let interrupted = Arc::new(AtomicBool::new(false));
    let reservation = Arc::new(PubkeyOutReservation::default());
    let handler_result = {
        let (interrupted, reservation) = (Arc::clone(&interrupted), Arc::clone(&reservation));
        ctrlc::set_handler(move || {
            if generate_interrupt(&interrupted, &reservation) {
                std::process::exit(EXIT_INTERRUPTED.into());
            }
        })
    };
    if let Err(e) = handler_result {
        let _ = writeln!(
            io::stderr(),
            "Failed to install the signal handler: {e}. No changes were made."
        );
        return ExitCode::FAILURE;
    }

    // Open an exclusive PC/SC handle before touching the output file or card so
    // no other local client can observe or use management-key authentication.
    let Some(mut session) = connect_exclusive_session() else {
        return ExitCode::FAILURE;
    };

    // Claim the output file now, after every prompt; an unusable path still
    // fails while the slot is untouched.
    let mut pubkey_file = match pubkey_out {
        Some(path) => match PubkeyOutFile::create(path.clone(), Arc::clone(&reservation)) {
            Ok(file) => Some(file),
            Err(e) => {
                report_unusable_pubkey_out(&path, &e);
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    // SELECT -> management key auth -> GENERATE -> certificate delete under exclusive ownership
    let outcome = session.exclusive(|piv| {
        piv.select()?;
        if let Err(auth_error) = piv.authenticate_management_key_with(&mgmt_key, alg) {
            return Ok(CardChange::AuthFailed(auth_error));
        }
        // The last point at which an interrupt can leave the slot untouched.
        if interrupted.load(Ordering::SeqCst) {
            return Ok(CardChange::Interrupted);
        }
        piv.generate_key(Slot::Authentication)
            .map(CardChange::Generated)
    });
    drop(mgmt_key);
    // Disconnect and reset the card immediately so management-key auth is
    // cleared before writing output files or printing to the console.
    drop(session);

    match outcome {
        Ok(CardChange::Generated(generated)) => {
            let delivery = deliver_generated_key(
                &generated,
                pubkey_file.as_mut(),
                &mut io::stdout().lock(),
                &mut io::stderr().lock(),
                &interrupted,
            );
            if delivery.complete() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Ok(CardChange::AuthFailed(auth_error)) => {
            let _ = writeln!(
                io::stderr(),
                "Management key authentication failed: {auth_error}\n\n\
                 Note: YubiKey firmware 5.7+ defaults to AES-192, while older firmware defaults to 3DES."
            );
            ExitCode::FAILURE
        }
        Ok(CardChange::Interrupted) => {
            let _ = writeln!(
                io::stderr(),
                "Interrupted before the key was generated; no changes were made."
            );
            ExitCode::from(EXIT_INTERRUPTED)
        }
        Err(e) => {
            let _ = writeln!(io::stderr(), "Failed to generate key: {e}");
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

    // Connect and read the public key before prompting for PIN, then release
    // the shared handle until signing starts.
    let key_info = {
        let Some(mut session) = connect_session() else {
            return ExitCode::FAILURE;
        };

        match read_slot_public_key(&mut session) {
            Ok(info) => info,
            Err(e) => {
                eprintln!("Failed to get public key: {e}");
                eprintln!();
                print_certificate_guidance();
                return ExitCode::FAILURE;
            }
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

    let Some(mut session) = connect_exclusive_session() else {
        return ExitCode::FAILURE;
    };
    let sign_result = sign_in_one_transaction(&mut session, &key_info, &pin, &hash);
    drop(pin);
    drop(session);

    match sign_result {
        Ok(der_signature) => {
            // The PIN verification is spent: write the result without panicking.
            let der_hex = hex::encode(&der_signature);
            let mut text = format!("\nDER Signature:\n  {der_hex}\n");
            let mut fallback = format!("DER Signature: {der_hex}");
            let eth_sig = create_ethereum_signature(&der_signature, &hash, &key_info.public_key);
            if let Ok(eth_sig) = &eth_sig {
                text.push_str(&format!(
                    "\nNormalized Signature Components (low-S):\n  r: 0x{}\n  s: 0x{}\n  v: {}\n\n\
                     Signature (r || s || v):\n  {eth_sig}\n",
                    hex::encode(eth_sig.r()),
                    hex::encode(eth_sig.s()),
                    eth_sig.v()
                ));
                fallback.push_str(&format!("\nSignature (r || s || v): {eth_sig}"));
            }
            let printed = print_result(&text, &fallback);
            match eth_sig {
                Ok(_) if printed => ExitCode::SUCCESS,
                Ok(_) => ExitCode::FAILURE,
                Err(e) => {
                    let _ = writeln!(io::stderr(), "Failed to create Ethereum signature: {e}");
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

    // Connect and read the public key before prompting for PIN, then release
    // the shared handle until signing starts.
    let key_info = {
        let Some(mut session) = connect_session() else {
            return ExitCode::FAILURE;
        };

        match read_slot_public_key(&mut session) {
            Ok(info) => info,
            Err(e) => {
                eprintln!("Failed to get public key: {e}");
                eprintln!();
                print_certificate_guidance();
                return ExitCode::FAILURE;
            }
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

    let Some(mut session) = connect_exclusive_session() else {
        return ExitCode::FAILURE;
    };
    let sign_result = sign_in_one_transaction(&mut session, &key_info, &pin, &hash_bytes);
    drop(pin);
    drop(session);

    match sign_result {
        Ok(der_signature) => {
            match create_ethereum_signature(&der_signature, &hash_bytes, &key_info.public_key) {
                Ok(eth_sig) => {
                    // The PIN verification is spent: write the result without panicking.
                    let text = format!(
                        "\nTransaction hash signed successfully!\n\n\
                         Signature (low-S):\n  r: 0x{}\n  s: 0x{}\n  v: {}\n\n\
                         Full Signature (65 bytes):\n  {eth_sig}\n\n\
                         This is a P-256 signature for EIP-7951 (P256VERIFY) verifiers; standard EVM nodes\n\
                         do not accept it as a transaction signature.\n",
                        hex::encode(eth_sig.r()),
                        hex::encode(eth_sig.s()),
                        eth_sig.v()
                    );
                    if print_result(&text, &format!("Full Signature (65 bytes): {eth_sig}")) {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
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
        let transport = PcscTransport::connect_exclusive()?;
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
    println!(
        "Security: 127.0.0.1 only, exact Origin allowlist, PIV-only APDU allowlist, \
         exclusive PC/SC session."
    );
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
    let mut out = io::stdout().lock();
    write!(
        out,
        "Type the slot id ({slot_id}) to confirm replacing its key: "
    )
    .and_then(|()| out.flush())
    .map_err(|e| format!("failed to write to stdout: {e}"))?;
    drop(out);

    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("failed to read confirmation: {e}"))?;

    Ok(line.trim().eq_ignore_ascii_case(slot_id))
}

fn prompt_management_key_algorithm() -> Result<ManagementKeyAlgorithm, String> {
    let mut out = io::stdout().lock();
    write!(
        out,
        "Management key algorithm [tdes/aes128/aes192/aes256] (default: aes192; factory default is tdes before firmware 5.7): "
    )
    .and_then(|()| out.flush())
    .map_err(|e| format!("failed to write to stdout: {e}"))?;
    drop(out);

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

    /// Creates a `--pubkey-out` file with its own reservation.
    fn create_file(path: PathBuf) -> io::Result<PubkeyOutFile> {
        PubkeyOutFile::create(path, Arc::default())
    }

    /// A newly created `--pubkey-out` file whose handle is read-only, so
    /// writing the PEM fails.
    fn read_only_file(path: &Path) -> PubkeyOutFile {
        let mut file = create_file(path.to_path_buf()).unwrap();
        file.file = File::open(path).unwrap();
        file
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

        let err = create_file(existing.clone()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&existing).unwrap(), "keep me");

        assert!(create_file(dir.0.join("missing").join("key.pem")).is_err());
    }

    #[test]
    fn check_pubkey_out_path_accepts_only_new_files_in_existing_directories() {
        let dir = TempDir::new("check");
        assert!(check_pubkey_out_path(&dir.0.join("key.pem")).is_ok());
        assert!(check_pubkey_out_path(Path::new("yubikey-cli-test-absent-key.pem")).is_ok());

        let existing = dir.0.join("existing.pem");
        fs::write(&existing, "keep me").unwrap();
        assert_eq!(
            check_pubkey_out_path(&existing).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(check_pubkey_out_path(&dir.0.join("missing").join("key.pem")).is_err());
        assert!(check_pubkey_out_path(&existing.join("key.pem")).is_err());

        #[cfg(unix)]
        {
            let link = dir.0.join("dangling.pem");
            std::os::unix::fs::symlink(dir.0.join("nowhere"), &link).unwrap();
            assert_eq!(
                check_pubkey_out_path(&link).unwrap_err().kind(),
                io::ErrorKind::AlreadyExists
            );
            assert!(create_file(link).is_err());
            assert!(!dir.0.join("nowhere").exists());
        }

        // Checking creates nothing.
        assert_eq!(
            fs::read_dir(&dir.0).unwrap().count(),
            if cfg!(unix) { 2 } else { 1 }
        );
    }

    #[test]
    fn shell_quote_produces_one_literal_word() {
        assert_eq!(shell_quote("pubkey.pem"), "pubkey.pem");
        assert_eq!(
            shell_quote("/tmp/out_dir/key-1.pem"),
            "/tmp/out_dir/key-1.pem"
        );
        assert_eq!(shell_quote("my key.pem"), "'my key.pem'");
        assert_eq!(shell_quote("it's.pem"), r"'it'\''s.pem'");
        assert_eq!(shell_quote("$HOME/k.pem"), "'$HOME/k.pem'");
        assert_eq!(shell_quote("a;rm -rf b"), "'a;rm -rf b'");
        assert_eq!(shell_quote("-key.pem"), "'-key.pem'");
        assert_eq!(shell_quote("~/k.pem"), "'~/k.pem'");
        assert_eq!(shell_quote("k\u{e9}y.pem"), "'k\u{e9}y.pem'");
        assert_eq!(shell_quote(""), "''");
    }

    /// The P-256 key with private scalar 1 (the base point).
    fn generated_key(certificate_delete_error: Option<Error>) -> GeneratedKey {
        let point = hex::decode(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
             4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
        .unwrap();
        GeneratedKey {
            public_key: VerifyingKey::from_sec1_bytes(&point).unwrap(),
            certificate_delete_error,
        }
    }

    /// A console that records what it receives, optionally checking that the
    /// `--pubkey-out` file already holds the PEM, or failing every write.
    struct Console {
        written: Vec<u8>,
        file_must_hold: Option<(PathBuf, String)>,
        fail: bool,
    }

    impl Console {
        fn new() -> Self {
            Self {
                written: Vec::new(),
                file_must_hold: None,
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::new()
            }
        }

        fn text(&self) -> String {
            String::from_utf8(self.written.clone()).unwrap()
        }
    }

    impl Write for Console {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Some((path, pem)) = &self.file_must_hold {
                assert_eq!(
                    &fs::read_to_string(path).unwrap(),
                    pem,
                    "the file must be written before the console"
                );
            }
            if self.fail {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn generated_key_is_written_to_the_file_before_the_console() {
        let dir = TempDir::new("deliver-order");
        let path = dir.0.join("my key.pem");
        let generated = generated_key(None);
        let pem = public_key_pem(&generated.public_key).unwrap();
        let mut file = create_file(path.clone()).unwrap();
        let mut out = Console::new();
        out.file_must_hold = Some((path.clone(), pem.clone()));
        let mut err = Console::new();
        err.file_must_hold = Some((path.clone(), pem.clone()));

        let delivery = deliver_generated_key(
            &generated,
            Some(&mut file),
            &mut out,
            &mut err,
            &AtomicBool::new(false),
        );
        assert_eq!(
            delivery,
            KeyDelivery {
                pem: true,
                file: Some(true),
                stdout: true,
                stderr: true
            }
        );
        assert!(delivery.complete());
        drop(file);
        assert_eq!(fs::read_to_string(&path).unwrap(), pem);

        let text = out.text();
        assert!(text.contains(&pem));
        assert!(text.contains(&format!("9a {}\n", shell_quote(&path.to_string_lossy()))));
        assert!(text.contains("'"), "the path with a space is quoted");
        assert!(err.text().is_empty());
    }

    #[test]
    fn console_failure_keeps_the_file_and_falls_back_to_stderr() {
        let dir = TempDir::new("deliver-console");
        let path = dir.0.join("key.pem");
        let generated = generated_key(None);
        let pem = public_key_pem(&generated.public_key).unwrap();
        let mut file = create_file(path.clone()).unwrap();
        let mut err = Console::new();

        let delivery = deliver_generated_key(
            &generated,
            Some(&mut file),
            &mut Console::failing(),
            &mut err,
            &AtomicBool::new(false),
        );
        assert_eq!(delivery.file, Some(true));
        assert!(!delivery.stdout);
        assert!(!delivery.complete());
        drop(file);
        assert_eq!(fs::read_to_string(&path).unwrap(), pem);
        let fallback = err.text();
        assert!(fallback.contains("WAS generated"));
        assert!(fallback.contains(&pem));
        assert!(fallback.contains(&path.display().to_string()));
    }

    #[test]
    fn file_failure_still_prints_the_key() {
        let dir = TempDir::new("deliver-file");
        let path = dir.0.join("key.pem");
        let mut file = read_only_file(&path);
        let generated = generated_key(Some(Error::SlotEmpty(0x9A)));
        let pem = public_key_pem(&generated.public_key).unwrap();
        let (mut out, mut err) = (Console::new(), Console::new());

        let delivery = deliver_generated_key(
            &generated,
            Some(&mut file),
            &mut out,
            &mut err,
            &AtomicBool::new(false),
        );
        assert_eq!(delivery.file, Some(false));
        assert!(delivery.stdout && delivery.stderr);
        assert!(!delivery.complete());
        assert!(out.text().contains(&pem));
        assert!(
            out.text()
                .contains("save the PEM above as pubkey.pem first")
        );
        assert!(err.text().contains("writing"));
        assert!(err.text().contains("old certificate"));
        drop(file);
        assert!(!path.exists(), "the incomplete file is removed");
    }

    #[test]
    fn every_output_failing_is_reported_as_failure() {
        let dir = TempDir::new("deliver-none");
        let mut file = read_only_file(&dir.0.join("key.pem"));
        let delivery = deliver_generated_key(
            &generated_key(None),
            Some(&mut file),
            &mut Console::failing(),
            &mut Console::failing(),
            &AtomicBool::new(false),
        );
        assert_eq!(
            delivery,
            KeyDelivery {
                pem: true,
                file: Some(false),
                stdout: false,
                stderr: false
            }
        );
        assert!(!delivery.complete());

        // Without --pubkey-out, a failing stdout alone is a failure too.
        let mut err = Console::new();
        let delivery = deliver_generated_key(
            &generated_key(None),
            None,
            &mut Console::failing(),
            &mut err,
            &AtomicBool::new(false),
        );
        assert_eq!(delivery.file, None);
        assert!(!delivery.complete());
        assert!(err.text().contains("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn deferred_interrupt_note_counts_toward_the_exit_status() {
        const NOTE: &str = "Interrupted while the key was being generated";
        let generated = generated_key(None);
        let pem = public_key_pem(&generated.public_key).unwrap();
        let interrupted = AtomicBool::new(true);

        // Everything delivered, including the note: success (exit status 0).
        let dir = TempDir::new("deliver-interrupted");
        let path = dir.0.join("key.pem");
        let mut file = create_file(path.clone()).unwrap();
        let (mut out, mut err) = (Console::new(), Console::new());
        let delivery = deliver_generated_key(
            &generated,
            Some(&mut file),
            &mut out,
            &mut err,
            &interrupted,
        );
        assert!(delivery.complete());
        assert!(out.text().contains(&pem));
        assert!(err.text().contains(NOTE));
        drop(file);
        assert_eq!(fs::read_to_string(&path).unwrap(), pem);

        // The note cannot be written: the key still reaches the file and
        // standard output, but the run is a failure (exit status 1).
        let path = dir.0.join("key-2.pem");
        let mut file = create_file(path.clone()).unwrap();
        let mut out = Console::new();
        let delivery = deliver_generated_key(
            &generated,
            Some(&mut file),
            &mut out,
            &mut Console::failing(),
            &interrupted,
        );
        assert_eq!(
            delivery,
            KeyDelivery {
                pem: true,
                file: Some(true),
                stdout: true,
                stderr: false
            }
        );
        assert!(!delivery.complete());
        assert!(out.text().contains(&pem));
        drop(file);
        assert_eq!(fs::read_to_string(&path).unwrap(), pem);

        // Not interrupted: no note, and nothing on standard error.
        let (mut out, mut err) = (Console::new(), Console::new());
        let delivery = deliver_generated_key(
            &generated,
            None,
            &mut out,
            &mut err,
            &AtomicBool::new(false),
        );
        assert!(delivery.complete());
        assert!(err.text().is_empty());
    }

    #[test]
    fn pubkey_out_file_is_removed_unless_written() {
        let dir = TempDir::new("cleanup");
        let path = dir.0.join("key.pem");

        drop(create_file(path.clone()).unwrap());
        assert!(!path.exists(), "an unwritten file must be removed");

        let mut file = create_file(path.clone()).unwrap();
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

    #[test]
    fn interrupt_removes_the_file_only_while_it_is_empty() {
        let dir = TempDir::new("interrupt-empty");
        let path = dir.0.join("key.pem");
        let interrupted = AtomicBool::new(false);
        let mut file = create_file(path.clone()).unwrap();
        let reservation = Arc::clone(&file.reservation);

        // The handler first: the first interrupt only sets the flag, the second
        // removes the still-empty file and asks to exit.
        assert!(!generate_interrupt(&interrupted, &reservation));
        assert!(path.exists());
        assert!(generate_interrupt(&interrupted, &reservation));
        assert!(!path.exists());

        // The main thread then cannot claim the file: it writes nothing, still
        // prints the key, and never removes the path, which may belong to
        // someone else by now.
        fs::write(&path, "someone else's").unwrap();
        let (mut out, mut err) = (Console::new(), Console::new());
        let delivery = deliver_generated_key(
            &generated_key(None),
            Some(&mut file),
            &mut out,
            &mut err,
            &interrupted,
        );
        assert_eq!(delivery.file, Some(false));
        assert!(out.text().contains("-----BEGIN PUBLIC KEY-----"));
        assert!(err.text().contains("an interrupt removed it"));
        drop(file);
        assert!(generate_interrupt(&interrupted, &reservation));
        assert_eq!(fs::read_to_string(&path).unwrap(), "someone else's");
    }

    #[test]
    fn interrupt_never_removes_a_claimed_file() {
        let dir = TempDir::new("interrupt-claimed");
        let interrupted = AtomicBool::new(true);

        // The main thread first, and the write succeeded: the file is kept.
        let written = dir.0.join("written.pem");
        let mut file = create_file(written.clone()).unwrap();
        let reservation = Arc::clone(&file.reservation);
        file.write_pem("PEM\n").unwrap();
        assert!(generate_interrupt(&interrupted, &reservation));
        drop(file);
        assert_eq!(fs::read_to_string(&written).unwrap(), "PEM\n");

        // Claimed, but the write failed: the handler leaves the file to the
        // main thread, which removes it.
        let failed = dir.0.join("failed.pem");
        let mut file = read_only_file(&failed);
        let reservation = Arc::clone(&file.reservation);
        assert!(file.write_pem("PEM\n").is_err());
        assert!(generate_interrupt(&interrupted, &reservation));
        assert!(failed.exists());
        drop(file);
        assert!(!failed.exists());
    }

    #[test]
    fn exactly_one_side_wins_the_empty_file() {
        let dir = TempDir::new("interrupt-race");
        for i in 0..100 {
            let path = dir.0.join(format!("key-{i}.pem"));
            let mut file = create_file(path.clone()).unwrap();
            let reservation = Arc::clone(&file.reservation);
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let handler = {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    reservation.remove_if_empty()
                })
            };
            barrier.wait();
            let main_won = file.write_pem("PEM\n").is_ok();
            let handler_won = handler.join().unwrap();
            assert_ne!(main_won, handler_won, "exactly one side wins");
            drop(file);
            if main_won {
                assert_eq!(fs::read_to_string(&path).unwrap(), "PEM\n");
            } else {
                assert!(!path.exists());
            }
        }
    }

    /// A console whose first write blocks until `release` is dropped, then fails.
    struct BlockedConsole {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }

    impl Write for BlockedConsole {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            let _ = self.entered.send(());
            let _ = self.release.recv();
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn second_interrupt_completes_while_the_console_is_blocked() {
        let dir = TempDir::new("interrupt-blocked");
        let path = dir.0.join("key.pem");
        let generated = generated_key(None);
        let pem = public_key_pem(&generated.public_key).unwrap();
        let mut file = create_file(path.clone()).unwrap();
        let reservation = Arc::clone(&file.reservation);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let main = std::thread::spawn(move || {
            let mut out = BlockedConsole {
                entered: entered_tx,
                release: release_rx,
            };
            let delivery = deliver_generated_key(
                &generated,
                Some(&mut file),
                &mut out,
                &mut Console::new(),
                &AtomicBool::new(false),
            );
            drop(file);
            delivery
        });

        // The main thread is now stuck in the console, after writing the file.
        entered_rx.recv().unwrap();
        let interrupted = AtomicBool::new(false);
        assert!(!generate_interrupt(&interrupted, &reservation));
        assert!(generate_interrupt(&interrupted, &reservation));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            pem,
            "a written file is kept"
        );

        drop(release_tx);
        let delivery = main.join().unwrap();
        assert_eq!(delivery.file, Some(true));
        assert!(!delivery.stdout);
        assert_eq!(fs::read_to_string(&path).unwrap(), pem);
    }
}
