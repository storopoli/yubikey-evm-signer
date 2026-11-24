//! YubiKey device abstraction for browser use.
//!
//! This module provides [`YubiKeyDevice`], a JavaScript-friendly API for
//! interacting with YubiKey PIV applets over either the local PC/SC loopback
//! bridge ([`YubiKeyDevice::connect_bridge`]) or raw WebUSB
//! ([`YubiKeyDevice::connect`]). All PIV APDU construction, the slot public key
//! lookup policy, mutual management key cryptography, BER-TLV/X.509 parsing, and
//! EIP-191/EIP-712/EIP-1559 hashing are delegated directly to
//! [`yubikey_evm_signer_core`].

use std::fmt;

use p256::ecdsa::VerifyingKey;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use yubikey_evm_signer_core::crypto::create_ethereum_signature;
use yubikey_evm_signer_core::eip712::TypedData;
use yubikey_evm_signer_core::yubikey::Slot;
use yubikey_evm_signer_core::yubikey::apdu::{Apdu, ApduResponse};
use yubikey_evm_signer_core::yubikey::piv::{
    ManagementKeyAlgorithm, build_delete_certificate_apdu, build_generate_key_apdu,
    build_get_certificate_apdu, build_get_metadata_apdu, build_mgmt_auth_request_witness_apdu,
    build_mgmt_auth_verify_apdu, build_select_piv_apdu, build_sign_apdu, build_verify_pin_apdu,
    check_delete_certificate_response, decrypt_mgmt_witness, encrypt_mgmt_challenge,
    parse_challenge_response, parse_public_key_response, parse_signature_response,
    parse_witness_response, resolve_slot_public_key, slot_key_from_metadata_response,
    verify_mgmt_challenge_response,
};
use yubikey_evm_signer_core::{Address, Transaction, eip191_hash};

use crate::bridge_transport::BridgeTransport;
use crate::error::{WasmError, WasmResult};
use crate::transport::WebUsbTransport;

/// Active browser transport backing a [`YubiKeyDevice`].
enum DeviceTransport {
    WebUsb(WebUsbTransport),
    Bridge(BridgeTransport),
    #[cfg(test)]
    Scripted(crate::transport::test_support::ScriptedTransport),
}

impl DeviceTransport {
    async fn transmit_async(&mut self, apdu: &Apdu) -> WasmResult<ApduResponse> {
        match self {
            Self::WebUsb(t) => t.transmit_async(apdu).await,
            Self::Bridge(t) => t.transmit_async(apdu).await,
            #[cfg(test)]
            Self::Scripted(t) => t.transmit_async(apdu).await,
        }
    }

    async fn transmit_full_async(
        &mut self,
        apdu: &Apdu,
        slot: Option<Slot>,
    ) -> WasmResult<Vec<u8>> {
        match self {
            Self::WebUsb(t) => t.transmit_full_async(apdu, slot).await,
            Self::Bridge(t) => t.transmit_full_async(apdu, slot).await,
            #[cfg(test)]
            Self::Scripted(t) => t.transmit_full_async(apdu, slot).await,
        }
    }

    async fn exchange_full_async(&mut self, apdu: &Apdu) -> WasmResult<ApduResponse> {
        match self {
            Self::WebUsb(t) => t.exchange_full_async(apdu).await,
            Self::Bridge(t) => t.exchange_full_async(apdu).await,
            #[cfg(test)]
            Self::Scripted(t) => t.exchange_full_async(apdu).await,
        }
    }

    async fn close(&mut self) -> WasmResult<()> {
        match self {
            Self::WebUsb(t) => t.close().await,
            Self::Bridge(t) => t.close().await,
            #[cfg(test)]
            Self::Scripted(t) => t.close().await,
        }
    }

    fn is_connected(&self) -> bool {
        match self {
            Self::WebUsb(t) => t.is_connected(),
            Self::Bridge(t) => t.is_connected(),
            #[cfg(test)]
            Self::Scripted(t) => t.is_connected(),
        }
    }
}

/// Parses a PIV slot string (`"9a"`, `"9c"`, `"9d"`, `"9e"`, case-insensitive).
///
/// # Errors
///
/// Returns [`WasmError::InvalidSlot`] if the slot string is unrecognized.
pub fn parse_slot_str(slot: &str) -> WasmResult<Slot> {
    match slot.trim().to_ascii_lowercase().as_str() {
        "9a" => Ok(Slot::Authentication),
        "9c" => Ok(Slot::Signature),
        "9d" => Ok(Slot::KeyManagement),
        "9e" => Ok(Slot::CardAuthentication),
        other => Err(WasmError::InvalidSlot(other.to_string())),
    }
}

/// Formats a [`Slot`] as its two-character lowercase hex identifier.
#[must_use]
pub const fn slot_to_str(slot: Slot) -> &'static str {
    match slot {
        Slot::Authentication => "9a",
        Slot::Signature => "9c",
        Slot::KeyManagement => "9d",
        Slot::CardAuthentication => "9e",
    }
}

/// Parses an optional management key algorithm string (defaults to AES-192).
///
/// # Errors
///
/// Returns [`WasmError::AuthenticationFailed`] if the algorithm name is unsupported.
pub fn parse_mgmt_algorithm(algorithm: Option<&str>) -> WasmResult<ManagementKeyAlgorithm> {
    match algorithm
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("aes192") => Ok(ManagementKeyAlgorithm::Aes192),
        Some("tdes" | "3des") => Ok(ManagementKeyAlgorithm::Tdes),
        Some("aes128") => Ok(ManagementKeyAlgorithm::Aes128),
        Some("aes256") => Ok(ManagementKeyAlgorithm::Aes256),
        Some(_) => Err(WasmError::AuthenticationFailed),
    }
}

/// Parses a 32-byte digest hex string (with optional `0x`/`0X` prefix).
///
/// # Errors
///
/// Returns [`WasmError::InvalidHash`] if the input is not valid 32-byte hex.
pub fn parse_hash_hex(hash: &str) -> WasmResult<[u8; 32]> {
    let trimmed = hash.trim();
    let hex_str = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    let bytes = hex::decode(hex_str).map_err(|e| WasmError::InvalidHash(e.to_string()))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        WasmError::InvalidHash(format!("hash must be exactly 32 bytes, got {}", v.len()))
    })
}

/// Formats a P-256 public key as uncompressed SEC1 hex (`0x04‖X‖Y`, 65 bytes).
#[must_use]
pub fn public_key_to_hex(public_key: &VerifyingKey) -> String {
    format!(
        "0x{}",
        hex::encode(public_key.to_sec1_point(false).as_bytes())
    )
}

/// A connected YubiKey device.
///
/// Supports both the local PC/SC loopback bridge (recommended across all desktop
/// browsers and OSes) and direct WebUSB.
///
/// # What the keys and addresses are
///
/// The slot holds a **P-256 (secp256r1)** key. The value returned by
/// [`get_public_key`](Self::get_public_key) (`0x04‖X‖Y`) is what a smart account
/// or any other verifier using the [EIP-7951] `P256VERIFY` precompile needs. The
/// "address" returned by [`get_address`](Self::get_address) and
/// [`generate_key`](Self::generate_key) is `keccak256(X‖Y)[12..]` of that P-256
/// key: a stable identifier, **not** a secp256k1 externally owned account. On
/// standard EVM chains nothing can be sent from it, and the signatures produced
/// here do not recover to it through `ecrecover`.
///
/// # One call at a time
///
/// Every async method takes `&mut self`, so the object supports **one call at a
/// time**. While a call is pending (for example a signature waiting for a
/// touch), any other call on the same object, including the synchronous
/// `getSlot`, `setSlot`, `hasStaleCertificate`, `lastGeneratedPublicKey` and
/// `isConnected`, throws
/// synchronously with the wasm-bindgen error "recursive use of an object
/// detected which would lead to unsafe aliasing in rust", and the pending call
/// is unaffected. Await each call before starting the next one; for example,
/// route every call through one queue or in-flight guard.
///
/// # Lost sessions
///
/// When a call finds that the session or the device is gone (the bridge
/// answered `409` or `503`, stopped answering, rejected the token because it
/// was restarted (`401`), or failed internally (`500`); the card was reset, the
/// YubiKey was unplugged, or the WebUSB connection was closed after an
/// unrecoverable CCID error), it
/// fails with an error starting with `Disconnected:` (or the card-reset
/// message), the verified PIN, management key authentication and cached public
/// key are discarded, and [`is_connected`](Self::is_connected) returns `false`.
/// A key generated before the session was lost stays available through
/// [`last_generated_public_key`](Self::last_generated_public_key).
/// Create a new device with [`connect_bridge`](Self::connect_bridge) or
/// [`connect`](Self::connect) to continue.
///
/// # Thread Safety
///
/// This type is not thread-safe and should only be used from the main thread
/// in a browser environment.
///
/// [EIP-7951]: https://eips.ethereum.org/EIPS/eip-7951
#[wasm_bindgen]
pub struct YubiKeyDevice {
    /// The underlying transport (WebUSB or local PC/SC bridge).
    transport: DeviceTransport,

    /// The active PIV slot for key retrieval, generation, and signing.
    slot: Slot,

    /// Cached P-256 verifying key for the active slot.
    cached_public_key: Option<VerifyingKey>,

    /// Public key returned by the last successful `GENERATE` in the active slot.
    /// Kept when the session ends (it may be the only copy of the key); cleared
    /// when a new generation starts and when the slot changes.
    last_generated_public_key: Option<VerifyingKey>,

    /// Whether the slot's certificate object is known not to describe the key
    /// in the active slot (stale certificate found by the last lookup, or not
    /// deleted after the last key generation). Reset by changing the slot.
    stale_certificate: bool,

    /// Whether the PIN was verified during the current session.
    authenticated: bool,

    /// Whether the management key was mutually authenticated in this session.
    mgmt_authenticated: bool,
}

impl fmt::Debug for YubiKeyDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("YubiKeyDevice")
            .field("slot", &self.slot)
            .field("authenticated", &self.authenticated)
            .field("mgmt_authenticated", &self.mgmt_authenticated)
            .field("has_cached_key", &self.cached_public_key.is_some())
            .field(
                "has_last_generated_key",
                &self.last_generated_public_key.is_some(),
            )
            .field("stale_certificate", &self.stale_certificate)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl YubiKeyDevice {
    /// Connects to a YubiKey device via WebUSB (experimental on standard web pages).
    ///
    /// Must be called from a user gesture (e.g., button click). Note that standard
    /// Chromium browsers block YubiKey VID `0x1050` and CCID class `0x0B` on regular
    /// web pages; use [`connect_bridge`](Self::connect_bridge) for full cross-browser
    /// support with real YubiKeys.
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if WebUSB is unsupported, blocked, cancelled, or PIV
    /// selection fails.
    #[wasm_bindgen]
    pub async fn connect() -> Result<YubiKeyDevice, JsValue> {
        Self::connect_webusb_internal().await.map_err(JsValue::from)
    }

    /// Connects to a YubiKey device via the hardened local PC/SC loopback bridge.
    ///
    /// Works across Chrome, Firefox, Safari, Edge, and Brave on macOS, Linux, and Windows.
    ///
    /// # Arguments
    ///
    /// * `url` - Bridge URL; only `http://127.0.0.1:<port>` with a port other
    ///   than `80` is accepted (`localhost` and `[::1]` are rejected)
    /// * `token` - Bearer token printed by `yubikey-cli bridge` (at least 32
    ///   visible ASCII characters)
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if `url` or `token` is invalid (checked before any
    /// request), the bridge is unreachable or does not allow this page's origin,
    /// authentication fails, or no YubiKey is available on the local PC/SC daemon.
    #[wasm_bindgen(js_name = "connectBridge")]
    pub async fn connect_bridge(url: &str, token: &str) -> Result<YubiKeyDevice, JsValue> {
        Self::connect_bridge_internal(url, token)
            .await
            .map_err(JsValue::from)
    }

    /// Internal WebUSB connection flow.
    async fn connect_webusb_internal() -> WasmResult<YubiKeyDevice> {
        let mut transport = WebUsbTransport::request_device().await?;

        let select_apdu = build_select_piv_apdu();
        if let Err(err) = transport.transmit_full_async(&select_apdu, None).await {
            let _ = transport.close().await;
            return Err(WasmError::PivSelectFailed(err.to_string()));
        }

        Ok(Self::with_transport(DeviceTransport::WebUsb(transport)))
    }

    /// Internal bridge connection flow (`/v1/connect` already selects `PIV_AID`).
    async fn connect_bridge_internal(url: &str, token: &str) -> WasmResult<YubiKeyDevice> {
        let transport = BridgeTransport::connect(url, token).await?;
        Ok(Self::with_transport(DeviceTransport::Bridge(transport)))
    }

    /// Sets the active PIV slot (`"9a"`, `"9c"`, `"9d"`, or `"9e"`, case-insensitive).
    ///
    /// Changing the slot invalidates the cached public key and resets
    /// [`has_stale_certificate`](Self::has_stale_certificate) and
    /// [`last_generated_public_key`](Self::last_generated_public_key).
    ///
    /// Throws if another call on this object is pending (see the class docs).
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if `slot` is not one of `9a`, `9c`, `9d`, or `9e`.
    #[wasm_bindgen(js_name = "setSlot")]
    pub fn set_slot(&mut self, slot: &str) -> Result<(), JsValue> {
        let parsed = parse_slot_str(slot).map_err(JsValue::from)?;
        if parsed != self.slot {
            self.slot = parsed;
            self.cached_public_key = None;
            self.last_generated_public_key = None;
            self.stale_certificate = false;
        }
        Ok(())
    }

    /// Returns the currently selected PIV slot (`"9a"`, `"9c"`, `"9d"`, or `"9e"`).
    ///
    /// Throws if another call on this object is pending (see the class docs).
    #[wasm_bindgen(js_name = "getSlot")]
    pub fn get_slot(&self) -> String {
        slot_to_str(self.slot).to_string()
    }

    /// Performs NIST SP 800-73-4 mutual management key authentication (required before `generateKey`).
    ///
    /// Over the bridge this needs `yubikey-cli bridge --allow-generate`; without
    /// it the bridge refuses the command (`403`) and the error says so.
    ///
    /// One call at a time: see the class docs.
    ///
    /// # Arguments
    ///
    /// * `key_hex` - Raw management key as hex (with optional `0x` prefix)
    /// * `algorithm` - Optional algorithm: `"aes192"` (default for YubiKey 5.7+),
    ///   `"tdes"` (default for YubiKey `< 5.7`), `"aes128"`, or `"aes256"`
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if the key/algorithm is invalid, mutual authentication
    /// fails, the bridge refuses the command, or the session is lost.
    #[wasm_bindgen(js_name = "authenticateManagementKey")]
    pub async fn authenticate_management_key(
        &mut self,
        key_hex: &str,
        algorithm: Option<String>,
    ) -> Result<(), JsValue> {
        let result = self
            .authenticate_management_key_internal(key_hex, algorithm.as_deref())
            .await;
        self.settle(result).await.map_err(JsValue::from)
    }

    /// Internal mutual management key authentication.
    async fn authenticate_management_key_internal(
        &mut self,
        key_hex: &str,
        algorithm: Option<&str>,
    ) -> WasmResult<()> {
        self.mgmt_authenticated = false;

        let alg = parse_mgmt_algorithm(algorithm)?;
        let trimmed = key_hex.trim();
        let stripped = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);

        let key =
            Zeroizing::new(hex::decode(stripped).map_err(|_| WasmError::AuthenticationFailed)?);
        if key.len() != alg.key_len() {
            return Err(WasmError::AuthenticationFailed);
        }

        // Step 1: Request encrypted witness from card
        let witness_apdu = build_mgmt_auth_request_witness_apdu(alg);
        let witness_resp = self
            .transport
            .transmit_full_async(&witness_apdu, None)
            .await?;
        let witness = parse_witness_response(&witness_resp, alg.block_size())
            .ok_or(WasmError::AuthenticationFailed)?;

        // Step 2: Decrypt witness and generate fresh CSPRNG host challenge
        let decrypted_witness = Zeroizing::new(decrypt_mgmt_witness(alg, &key, &witness)?);
        let mut our_challenge = Zeroizing::new(vec![0u8; alg.block_size()]);
        getrandom::fill(&mut our_challenge)
            .map_err(|e| WasmError::CoreError(format!("CSPRNG failed: {e}")))?;

        // Step 3: Send decrypted witness (0x80) and plaintext host challenge (0x81)
        let mut verify_apdu = build_mgmt_auth_verify_apdu(alg, &decrypted_witness, &our_challenge)?;
        drop(decrypted_witness);

        let transmit_res = self.transport.transmit_full_async(&verify_apdu, None).await;
        verify_apdu.zeroize_data();

        let card_data = match transmit_res {
            Ok(data) => data,
            Err(WasmError::SecurityStatusNotSatisfied) => {
                return Err(WasmError::AuthenticationFailed);
            }
            Err(e) => return Err(e),
        };

        // Step 4: Verify card's encrypted challenge response in constant time
        let expected_response = Zeroizing::new(encrypt_mgmt_challenge(alg, &key, &our_challenge)?);
        drop(our_challenge);

        let actual_response = Zeroizing::new(
            parse_challenge_response(&card_data, alg.block_size())
                .ok_or(WasmError::AuthenticationFailed)?,
        );

        if !verify_mgmt_challenge_response(&expected_response, &actual_response) {
            return Err(WasmError::AuthenticationFailed);
        }

        self.mgmt_authenticated = true;
        Ok(())
    }

    /// Verifies the user's PIV PIN (6-8 bytes).
    ///
    /// Always validates the PIN length locally and transmits `VERIFY` to the YubiKey,
    /// scrubbing the APDU payload immediately afterward.
    ///
    /// One call at a time: see the class docs.
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if the PIN is invalid (with remaining retries when reported)
    /// or locked, or the session is lost.
    #[wasm_bindgen(js_name = "verifyPin")]
    pub async fn verify_pin(&mut self, pin: &str) -> Result<(), JsValue> {
        let result = self.verify_pin_internal(pin).await;
        self.settle(result).await.map_err(JsValue::from)
    }

    /// Internal PIN verification.
    async fn verify_pin_internal(&mut self, pin: &str) -> WasmResult<()> {
        // Always reset before verifying so stale state can never bypass a wrong PIN
        self.authenticated = false;

        let mut apdu = build_verify_pin_apdu(pin)?;
        let resp_res = self.transport.transmit_async(&apdu).await;
        apdu.zeroize_data();

        let response = resp_res?;
        response.check().map_err(WasmError::from)?;

        self.authenticated = true;
        Ok(())
    }

    /// Generates a new P-256 key pair in the active PIV slot.
    ///
    /// Requires prior management key authentication via
    /// [`authenticate_management_key`](Self::authenticate_management_key); over
    /// the bridge this needs `yubikey-cli bridge --allow-generate`.
    /// **Warning:** this overwrites any existing key in the active slot.
    ///
    /// After the key is generated, the slot's certificate object (which
    /// described the destroyed key) is deleted. If that deletion fails, the call
    /// still succeeds with the new key's address (the new key is never lost) and
    /// [`has_stale_certificate`](Self::has_stale_certificate) returns `true`:
    /// remove or replace the old certificate before relying on it.
    ///
    /// The new public key is kept for
    /// [`last_generated_public_key`](Self::last_generated_public_key) even if
    /// the session ends while the certificate is being deleted (the call then
    /// still resolves, but the device is disconnected and
    /// [`get_public_key`](Self::get_public_key) fails). On firmware without
    /// attestation or slot metadata that is the only way to obtain the key, so
    /// read it right after this call resolves.
    ///
    /// One call at a time: see the class docs.
    ///
    /// # Arguments
    ///
    /// * `pin` - Optional PIN; if non-empty, verified before key generation
    ///
    /// # Returns
    ///
    /// The checksummed `keccak256(X‖Y)[12..]` identifier of the new P-256 public
    /// key. It is **not** a secp256k1 account (see the class docs); use
    /// [`last_generated_public_key`](Self::last_generated_public_key) for the
    /// key itself.
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if the management key is not authenticated, key
    /// generation fails or is refused by the bridge, or the session is lost.
    #[wasm_bindgen(js_name = "generateKey")]
    pub async fn generate_key(&mut self, pin: Option<String>) -> Result<String, JsValue> {
        let result = self.generate_key_internal(pin.as_deref()).await;
        self.settle(result).await.map_err(JsValue::from)
    }

    /// Internal key generation.
    async fn generate_key_internal(&mut self, pin: Option<&str>) -> WasmResult<String> {
        // Never report a key from an earlier call as the result of this one.
        self.last_generated_public_key = None;

        if !self.mgmt_authenticated {
            return Err(WasmError::SecurityStatusNotSatisfied);
        }

        if let Some(p) = pin
            && !p.is_empty()
        {
            self.verify_pin_internal(p).await?;
        }

        let slot = self.slot;
        // The slot's key is about to change: never serve the old one again.
        self.cached_public_key = None;
        self.stale_certificate = false;

        let apdu = build_generate_key_apdu(slot);
        let data = self
            .transport
            .transmit_full_async(&apdu, Some(slot))
            .await
            .map_err(|e| match e {
                WasmError::SecurityStatusNotSatisfied => e,
                e if e.ends_session() => e,
                other => WasmError::KeyGenerationFailed(other.to_string()),
            })?;

        let public_key = parse_public_key_response(&data)
            .ok_or_else(|| WasmError::KeyGenerationFailed("invalid response".to_string()))?;

        // The new key exists on the card from here on, so no later failure may
        // hide it: record it where losing the session cannot clear it, and only
        // report a certificate that could not be deleted.
        self.last_generated_public_key = Some(public_key);
        let certificate_deleted = match self
            .transport
            .exchange_full_async(&build_delete_certificate_apdu(slot))
            .await
        {
            Ok(response) => check_delete_certificate_response(&response).is_ok(),
            Err(_) => false,
        };

        self.cached_public_key = Some(public_key);
        self.stale_certificate = !certificate_deleted;

        Ok(Address::from_public_key(&public_key).to_checksum_hex())
    }

    /// Returns the checksummed address identifier of the P-256 key in the active slot.
    ///
    /// The value is `keccak256(X‖Y)[12..]` of the slot's P-256 public key. It is
    /// **not** a secp256k1 externally owned account: nothing can be sent from it
    /// on standard EVM chains, and signatures from this device do not
    /// `ecrecover` to it. Contracts that verify these signatures with
    /// `P256VERIFY` (EIP-7951) need [`get_public_key`](Self::get_public_key).
    ///
    /// The key is read from the YubiKey's slot metadata (firmware 5.3+), which
    /// always describes the key currently in the slot; the slot's X.509
    /// certificate is used only when metadata is unavailable (older firmware). A
    /// certificate holding a different key is ignored and reported by
    /// [`has_stale_certificate`](Self::has_stale_certificate). The key is cached
    /// until the slot changes or the session is lost.
    ///
    /// One call at a time: see the class docs.
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if the slot holds no key, holds a non-P-256 key, or
    /// (without metadata) has no certificate with a P-256 key, or if the session
    /// is lost.
    #[wasm_bindgen(js_name = "getAddress")]
    pub async fn get_address(&mut self) -> Result<String, JsValue> {
        let result = self
            .resolve_public_key()
            .await
            .map(|key| Address::from_public_key(&key).to_checksum_hex());
        self.settle(result).await.map_err(JsValue::from)
    }

    /// Returns the P-256 public key of the active slot as uncompressed SEC1 hex
    /// (`0x04‖X‖Y`, 65 bytes, lowercase).
    ///
    /// This is the key a smart account or other verifier using the EIP-7951
    /// `P256VERIFY` precompile (`0x100`) needs: `X` and `Y` are the `qx` and `qy`
    /// inputs. Uses the same lookup and cache as
    /// [`get_address`](Self::get_address).
    ///
    /// One call at a time: see the class docs.
    ///
    /// # Errors
    ///
    /// Same as [`get_address`](Self::get_address).
    #[wasm_bindgen(js_name = "getPublicKey")]
    pub async fn get_public_key(&mut self) -> Result<String, JsValue> {
        let result = self
            .resolve_public_key()
            .await
            .map(|key| public_key_to_hex(&key));
        self.settle(result).await.map_err(JsValue::from)
    }

    /// Returns `true` if the active slot's certificate object is known **not** to
    /// describe the slot's key.
    ///
    /// That is the case when the last [`get_address`](Self::get_address) /
    /// [`get_public_key`](Self::get_public_key) lookup found a certificate whose
    /// key differs from (or could not be compared with) the key reported by the
    /// slot metadata, or when the last [`generate_key`](Self::generate_key)
    /// could not delete the destroyed key's certificate. The returned address and
    /// public key always describe the actual key; the stale certificate should
    /// be removed or replaced before any other software relies on it.
    ///
    /// `false` before any lookup, after [`set_slot`](Self::set_slot) changes the
    /// slot, and whenever no stale certificate was found. Without slot metadata
    /// (firmware older than 5.3) staleness cannot be detected.
    ///
    /// Throws if another call on this object is pending (see the class docs).
    #[wasm_bindgen(js_name = "hasStaleCertificate")]
    #[allow(clippy::missing_const_for_fn)]
    pub fn has_stale_certificate(&self) -> bool {
        self.stale_certificate
    }

    /// Returns the P-256 public key created by the last successful
    /// [`generate_key`](Self::generate_key) in the active slot, as uncompressed
    /// SEC1 hex (`0x04‖X‖Y`, the same format as
    /// [`get_public_key`](Self::get_public_key)), or `undefined`.
    ///
    /// Unlike the cached key behind `getPublicKey()`, this value survives the
    /// end of the session (and [`disconnect`](Self::disconnect)) and needs no
    /// card access: if `generateKey()` resolved, the new key is here even when
    /// the device reports itself disconnected. That matters on firmware older
    /// than 5.3 without attestation (older than 4.3), where the key cannot be
    /// read from the card again until a certificate for it is stored.
    ///
    /// It is reset to `undefined` when `generateKey()` starts (so after a
    /// rejected `generateKey()` it is `undefined`) and when
    /// [`set_slot`](Self::set_slot) changes the slot, so a defined value always
    /// belongs to the slot returned by [`get_slot`](Self::get_slot). If
    /// `generateKey()` rejects because the session ended while the card was
    /// generating, the slot's key may still have been replaced without the new
    /// key being reported.
    ///
    /// Throws if another call on this object is pending (see the class docs).
    #[wasm_bindgen(js_name = "lastGeneratedPublicKey")]
    pub fn last_generated_public_key(&self) -> Option<String> {
        self.last_generated_public_key
            .as_ref()
            .map(public_key_to_hex)
    }

    /// Signs a 32-byte prehashed digest using the YubiKey.
    ///
    /// One call at a time: see the class docs.
    ///
    /// # Arguments
    ///
    /// * `pin` - PIV PIN (always validated and verified when the slot requires a PIN or `pin` is non-empty)
    /// * `hash` - 32-byte digest as hex (with optional `0x` prefix)
    ///
    /// # Returns
    ///
    /// The 65-byte low-S signature (`r || s || v`) as a `0x`-prefixed hex string,
    /// made with the slot's P-256 key (`v` is the P-256 recovery parameter).
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if the hash or PIN is invalid, the slot has no usable
    /// key (reported before the PIN is sent), signing fails, or the session is
    /// lost.
    #[wasm_bindgen(js_name = "signHash")]
    pub async fn sign_hash(&mut self, pin: &str, hash: &str) -> Result<String, JsValue> {
        let hash_bytes = parse_hash_hex(hash).map_err(JsValue::from)?;
        let result = self.sign_digest_internal(pin, &hash_bytes).await;
        self.settle(result).await.map_err(JsValue::from)
    }

    /// Internal 32-byte digest signing (shared by every sign entry point).
    async fn sign_digest_internal(
        &mut self,
        pin: &str,
        hash_bytes: &[u8; 32],
    ) -> WasmResult<String> {
        // Resolve (and cache) the public key BEFORE verifying the PIN, so VERIFY
        // is the command immediately preceding GENERAL AUTHENTICATE (slot 9c's
        // PIN-always policy rejects a signature after any other command), and a
        // slot without a usable key fails before a PIN attempt is spent.
        let public_key = self.resolve_public_key().await?;

        // Always verify PIN when the slot requires it or a PIN string was provided
        if self.slot.requires_pin() || !pin.is_empty() {
            self.verify_pin_internal(pin).await?;
        }

        let apdu = build_sign_apdu(self.slot, hash_bytes);
        let response_data = match self
            .transport
            .transmit_full_async(&apdu, Some(self.slot))
            .await
        {
            Ok(bytes) => bytes,
            Err(WasmError::SecurityStatusNotSatisfied) => {
                self.authenticated = false;
                return Err(WasmError::SecurityStatusNotSatisfied);
            }
            Err(e) => return Err(e),
        };

        // Slot 9c (Digital Signature) enforces PIN-always on YubiKey
        if self.slot == Slot::Signature {
            self.authenticated = false;
        }

        let der_sig = parse_signature_response(&response_data)
            .ok_or_else(|| WasmError::SigningFailed("invalid signature response".to_string()))?;

        let signature = create_ethereum_signature(&der_sig, hash_bytes, &public_key)
            .map_err(|e| WasmError::SigningFailed(e.to_string()))?;

        Ok(signature.to_hex())
    }

    /// Signs an Ethereum transaction (EIP-155 legacy or EIP-1559).
    ///
    /// The signature is a P-256 signature over the transaction's signing hash.
    /// Standard EVM chains only accept secp256k1 transaction signatures, so this
    /// does **not** produce a transaction a standard chain will execute from
    /// [`get_address`](Self::get_address); it is for P-256 (EIP-7951) aware
    /// verifiers, such as smart accounts that check it against
    /// [`get_public_key`](Self::get_public_key).
    ///
    /// One call at a time: see the class docs.
    ///
    /// # Arguments
    ///
    /// * `pin` - PIV PIN
    /// * `tx_json` - Transaction JSON string (`type: "eip1559" | "legacy"`)
    ///
    /// # Returns
    ///
    /// The 65-byte low-S signature (`r || s || v`) as a `0x`-prefixed hex string.
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if the transaction JSON is invalid, PIN verification fails,
    /// hardware signing fails, or the session is lost.
    #[wasm_bindgen(js_name = "signTransaction")]
    pub async fn sign_transaction(&mut self, pin: &str, tx_json: &str) -> Result<String, JsValue> {
        let result = self.sign_transaction_internal(pin, tx_json).await;
        self.settle(result).await.map_err(JsValue::from)
    }

    /// Internal transaction signing.
    async fn sign_transaction_internal(&mut self, pin: &str, tx_json: &str) -> WasmResult<String> {
        let tx: Transaction = serde_json::from_str(tx_json)
            .map_err(|e| WasmError::InvalidTransaction(e.to_string()))?;

        let hash: [u8; 32] = tx
            .signing_hash()
            .map_err(|e| WasmError::InvalidTransaction(e.to_string()))?
            .into();
        self.sign_digest_internal(pin, &hash).await
    }

    /// Signs EIP-712 typed structured data.
    ///
    /// One call at a time: see the class docs.
    ///
    /// # Arguments
    ///
    /// * `pin` - PIV PIN
    /// * `typed_data_json` - EIP-712 typed data JSON string
    ///
    /// # Returns
    ///
    /// The 65-byte low-S signature (`r || s || v`) as a `0x`-prefixed hex string.
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if the typed data is invalid, signing fails, or the
    /// session is lost.
    #[wasm_bindgen(js_name = "signTypedData")]
    pub async fn sign_typed_data(
        &mut self,
        pin: &str,
        typed_data_json: &str,
    ) -> Result<String, JsValue> {
        let result = self.sign_typed_data_internal(pin, typed_data_json).await;
        self.settle(result).await.map_err(JsValue::from)
    }

    /// Internal EIP-712 signing.
    async fn sign_typed_data_internal(
        &mut self,
        pin: &str,
        typed_data_json: &str,
    ) -> WasmResult<String> {
        let typed_data: TypedData = serde_json::from_str(typed_data_json)
            .map_err(|e| WasmError::InvalidTypedData(e.to_string()))?;

        let hash = typed_data
            .signing_hash()
            .map_err(|e| WasmError::InvalidTypedData(e.to_string()))?;

        self.sign_digest_internal(pin, &hash).await
    }

    /// Signs a personal message using EIP-191 (`personal_sign`).
    ///
    /// One call at a time: see the class docs.
    ///
    /// # Arguments
    ///
    /// * `pin` - PIV PIN
    /// * `message` - UTF-8 message string
    ///
    /// # Returns
    ///
    /// The 65-byte low-S signature (`r || s || v`) as a `0x`-prefixed hex string.
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if PIN verification or signing fails, or the session
    /// is lost.
    #[wasm_bindgen(js_name = "signMessage")]
    pub async fn sign_message(&mut self, pin: &str, message: &str) -> Result<String, JsValue> {
        let hash: [u8; 32] = eip191_hash(message.as_bytes()).into();
        let result = self.sign_digest_internal(pin, &hash).await;
        self.settle(result).await.map_err(JsValue::from)
    }

    /// Disconnects from the YubiKey and clears all cached session state.
    ///
    /// One call at a time: see the class docs.
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if closing the transport fails.
    #[wasm_bindgen]
    pub async fn disconnect(&mut self) -> Result<(), JsValue> {
        self.forget_session();
        self.transport.close().await.map_err(JsValue::from)
    }

    /// Checks if the underlying device transport is still connected.
    ///
    /// Becomes `false` after [`disconnect`](Self::disconnect) and as soon as a
    /// call finds that the session or the device is gone (see the class docs);
    /// for WebUSB also when the browser reports the YubiKey unplugged.
    ///
    /// Throws if another call on this object is pending (see the class docs).
    #[wasm_bindgen(js_name = "isConnected")]
    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
    }
}

impl YubiKeyDevice {
    /// Creates a device on an already connected transport (slot 9a, no state).
    const fn with_transport(transport: DeviceTransport) -> Self {
        Self {
            transport,
            slot: Slot::Authentication,
            cached_public_key: None,
            last_generated_public_key: None,
            stale_certificate: false,
            authenticated: false,
            mgmt_authenticated: false,
        }
    }

    /// Discards the verified PIN, management key authentication and cached key.
    ///
    /// The last generated public key is kept on purpose: it may be the only
    /// copy of a key the card just created.
    const fn forget_session(&mut self) {
        self.authenticated = false;
        self.mgmt_authenticated = false;
        self.cached_public_key = None;
    }

    /// Post-processes the result of an exported operation.
    ///
    /// If the operation ended the session (a [`WasmError::ends_session`] error,
    /// or a transport that no longer reports itself connected), all session
    /// state is discarded and the transport is closed, so `isConnected()`
    /// returns `false` and the caller must reconnect.
    async fn settle<T>(&mut self, result: WasmResult<T>) -> WasmResult<T> {
        let session_ended = match &result {
            Err(e) => e.ends_session(),
            Ok(_) => false,
        };
        if session_ended || !self.transport.is_connected() {
            self.forget_session();
            let _ = self.transport.close().await;
        }
        result
    }

    /// Returns the active slot's P-256 public key, reading it from the card if
    /// it is not cached.
    ///
    /// Implements the core lookup policy with the shared sans-IO helpers: the
    /// `GET METADATA` key is authoritative, the certificate is a fallback only
    /// when metadata is unavailable, `0x6A82` from metadata means "no key", and
    /// a certificate with a different key is reported as stale.
    async fn resolve_public_key(&mut self) -> WasmResult<VerifyingKey> {
        if let Some(public_key) = self.cached_public_key {
            return Ok(public_key);
        }

        let slot = self.slot;
        let metadata = self
            .transport
            .exchange_full_async(&build_get_metadata_apdu(slot))
            .await?;
        let metadata_key = slot_key_from_metadata_response(slot, &metadata)?;

        let certificate = self
            .transport
            .exchange_full_async(&build_get_certificate_apdu(slot))
            .await?;
        let resolved = resolve_slot_public_key(slot, metadata_key, &certificate)?;

        self.cached_public_key = Some(resolved.public_key);
        self.stale_certificate = resolved.stale_certificate;
        Ok(resolved.public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_and_algorithm_parsing() {
        assert_eq!(parse_slot_str("9a").unwrap(), Slot::Authentication);
        assert_eq!(parse_slot_str(" 9C ").unwrap(), Slot::Signature);
        assert_eq!(parse_slot_str("9d").unwrap(), Slot::KeyManagement);
        assert_eq!(parse_slot_str("9E").unwrap(), Slot::CardAuthentication);
        assert!(matches!(
            parse_slot_str("82"),
            Err(WasmError::InvalidSlot(_))
        ));

        assert_eq!(slot_to_str(Slot::Authentication), "9a");
        assert_eq!(slot_to_str(Slot::Signature), "9c");
        assert_eq!(slot_to_str(Slot::KeyManagement), "9d");
        assert_eq!(slot_to_str(Slot::CardAuthentication), "9e");

        assert_eq!(
            parse_mgmt_algorithm(None).unwrap(),
            ManagementKeyAlgorithm::Aes192
        );
        assert_eq!(
            parse_mgmt_algorithm(Some("")).unwrap(),
            ManagementKeyAlgorithm::Aes192
        );
        assert_eq!(
            parse_mgmt_algorithm(Some("AES192")).unwrap(),
            ManagementKeyAlgorithm::Aes192
        );
        assert_eq!(
            parse_mgmt_algorithm(Some("tdes")).unwrap(),
            ManagementKeyAlgorithm::Tdes
        );
        assert_eq!(
            parse_mgmt_algorithm(Some("3des")).unwrap(),
            ManagementKeyAlgorithm::Tdes
        );
        assert_eq!(
            parse_mgmt_algorithm(Some("aes128")).unwrap(),
            ManagementKeyAlgorithm::Aes128
        );
        assert_eq!(
            parse_mgmt_algorithm(Some("aes256")).unwrap(),
            ManagementKeyAlgorithm::Aes256
        );
        assert!(matches!(
            parse_mgmt_algorithm(Some("rsa")),
            Err(WasmError::AuthenticationFailed)
        ));
    }

    #[test]
    fn parse_hash_hex_validates_length_and_encoding() {
        let valid = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let bytes = parse_hash_hex(valid).unwrap();
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[31], 0xEF);

        assert!(matches!(
            parse_hash_hex("0x1234"),
            Err(WasmError::InvalidHash(_))
        ));
        assert!(matches!(
            parse_hash_hex("0xzzzz"),
            Err(WasmError::InvalidHash(_))
        ));
    }

    #[test]
    fn transaction_json_shapes_from_demo_and_readmes_deserialize() {
        // Shape from demo/app.js
        let demo_tx = r#"{
            "type": "eip1559",
            "chain_id": 1,
            "nonce": 0,
            "max_priority_fee_per_gas": "1000000000",
            "max_fee_per_gas": "20000000000",
            "gas_limit": 21000,
            "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD20",
            "value": "0",
            "input": "0x",
            "access_list": []
        }"#;
        let parsed_demo: Transaction = serde_json::from_str(demo_tx).unwrap();
        assert_eq!(parsed_demo.chain_id(), 1);
        assert!(!parsed_demo.signing_hash().unwrap().is_zero());

        // Shape from README.md & packages/npm/README.md (omitted access_list, decimal strings)
        let npm_readme_tx = r#"{
            "type": "eip1559",
            "chain_id": 1,
            "nonce": 0,
            "max_priority_fee_per_gas": "1000000000",
            "max_fee_per_gas": "20000000000",
            "gas_limit": 21000,
            "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD20",
            "value": "1000000000000000000",
            "input": "0x"
        }"#;
        let parsed_npm: Transaction = serde_json::from_str(npm_readme_tx).unwrap();
        assert_eq!(parsed_npm.chain_id(), 1);

        // Contract deployment (to: null) with hex calldata
        let deploy_tx = r#"{
            "type": "eip1559",
            "chain_id": 11155111,
            "nonce": 2,
            "max_priority_fee_per_gas": "1000000000",
            "max_fee_per_gas": "25000000000",
            "gas_limit": 120000,
            "to": null,
            "value": "0",
            "data": "0x60806040"
        }"#;
        let parsed_deploy: Transaction = serde_json::from_str(deploy_tx).unwrap();
        assert_eq!(parsed_deploy.chain_id(), 11155111);
    }

    // -------------------------------------------------------------------------
    // Device flows against a simulated PIV card (scripted transport)
    // -------------------------------------------------------------------------

    use std::cell::RefCell;
    use std::rc::Rc;

    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{Signature as P256Signature, SigningKey};

    use crate::transport::test_support::{Handler, ScriptedTransport, block_on, ok, sw};

    type Reply = Box<dyn FnMut() -> WasmResult<ApduResponse>>;

    const INS_VERIFY: u8 = 0x20;
    const INS_GENERATE: u8 = 0x47;
    const INS_AUTHENTICATE: u8 = 0x87;
    const INS_GET_DATA: u8 = 0xCB;
    const INS_PUT_DATA: u8 = 0xDB;
    const INS_GET_METADATA: u8 = 0xF7;

    fn signing_key(scalar: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[31] = scalar;
        SigningKey::from_bytes(&bytes.into()).unwrap()
    }

    fn point(key: &SigningKey) -> Vec<u8> {
        key.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }

    fn address_of(key: &SigningKey) -> String {
        Address::from_public_key(key.verifying_key()).to_checksum_hex()
    }

    fn der_tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
        let mut out = tag.to_vec();
        match value.len() {
            len @ 0..0x80 => out.push(len as u8),
            len @ 0x80..=0xFF => out.extend_from_slice(&[0x81, len as u8]),
            len => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(value);
        out
    }

    /// `GET METADATA` body for a key with `algorithm` and EC `point`.
    fn metadata_body(algorithm: u8, point: &[u8]) -> Vec<u8> {
        [
            der_tlv(&[0x01], &[algorithm]),
            der_tlv(&[0x02], &[0x01, 0x01]),
            der_tlv(&[0x03], &[0x01]),
            der_tlv(&[0x04], &der_tlv(&[0x86], point)),
        ]
        .concat()
    }

    /// PIV certificate object (`53 { 70 cert, 71 00 }`) for a P-256 `point`.
    fn cert_object(point: &[u8]) -> Vec<u8> {
        let ec_public_key = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
        let secp256r1 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        let sig_alg = der_tlv(
            &[0x30],
            &der_tlv(&[0x06], &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]),
        );
        let spki = der_tlv(
            &[0x30],
            &[
                der_tlv(
                    &[0x30],
                    &[
                        der_tlv(&[0x06], &ec_public_key),
                        der_tlv(&[0x06], &secp256r1),
                    ]
                    .concat(),
                ),
                der_tlv(&[0x03], &[&[0x00], point].concat()),
            ]
            .concat(),
        );
        let tbs = der_tlv(
            &[0x30],
            &[
                der_tlv(&[0xA0], &der_tlv(&[0x02], &[0x02])),
                der_tlv(&[0x02], &[0x01]),
                sig_alg.clone(),
                der_tlv(&[0x30], &[]),
                der_tlv(&[0x30], &[]),
                der_tlv(&[0x30], &[]),
                spki,
            ]
            .concat(),
        );
        let cert = der_tlv(
            &[0x30],
            &[tbs, sig_alg, der_tlv(&[0x03], &[0x00, 0x30, 0x00])].concat(),
        );
        der_tlv(
            &[0x53],
            &[der_tlv(&[0x70], &cert), der_tlv(&[0x71], &[0x00])].concat(),
        )
    }

    fn reply(response: WasmResult<ApduResponse>) -> Reply {
        Box::new(move || response.clone())
    }

    /// Simulated PIV card. `signer` signs digests and is returned by GENERATE.
    fn card(metadata: Reply, certificate: Reply, signer: SigningKey, put_data: Reply) -> Handler {
        let (mut metadata, mut certificate, mut put_data) = (metadata, certificate, put_data);
        Box::new(move |apdu: &Apdu| match apdu.ins() {
            INS_GET_METADATA => metadata(),
            INS_GET_DATA => certificate(),
            INS_VERIFY => ok(Vec::new()),
            INS_AUTHENTICATE => {
                let digest: [u8; 32] = apdu.data()[6..].try_into().unwrap();
                let signature: P256Signature = signer.sign_prehash(&digest).unwrap();
                ok(der_tlv(
                    &[0x7C],
                    &der_tlv(&[0x82], signature.to_der().as_bytes()),
                ))
            }
            INS_GENERATE => ok(der_tlv(&[0x7F, 0x49], &der_tlv(&[0x86], &point(&signer)))),
            INS_PUT_DATA => put_data(),
            other => panic!("unexpected INS {other:#04x}"),
        })
    }

    fn device(handler: Handler, slot: Slot) -> (YubiKeyDevice, Rc<RefCell<Vec<Vec<u8>>>>) {
        let (transport, sent) = ScriptedTransport::new(handler);
        let mut device = YubiKeyDevice::with_transport(DeviceTransport::Scripted(transport));
        device.slot = slot;
        (device, sent)
    }

    fn instructions(sent: &Rc<RefCell<Vec<Vec<u8>>>>) -> Vec<u8> {
        sent.borrow().iter().map(|apdu| apdu[1]).collect()
    }

    const PIN: &str = "123456";
    const DIGEST: [u8; 32] = [0x11; 32];

    #[test]
    fn get_address_uses_metadata_key_and_reports_stale_certificate() {
        let (key_a, key_b) = (signing_key(1), signing_key(2));
        let handler = card(
            reply(ok(metadata_body(0x11, &point(&key_a)))),
            reply(ok(cert_object(&point(&key_b)))),
            key_a.clone(),
            reply(sw(0x90, 0x00)),
        );
        let (mut dev, sent) = device(handler, Slot::Authentication);

        let key = block_on(dev.resolve_public_key()).unwrap();
        assert_eq!(&key, key_a.verifying_key());
        assert_eq!(
            Address::from_public_key(&key).to_checksum_hex(),
            address_of(&key_a)
        );
        assert!(dev.has_stale_certificate());
        assert_eq!(instructions(&sent), vec![INS_GET_METADATA, INS_GET_DATA]);

        // Cached: no further APDUs; the public key is 0x04 || X || Y.
        let hex_key = public_key_to_hex(&block_on(dev.resolve_public_key()).unwrap());
        assert_eq!(hex_key, format!("0x{}", hex::encode(point(&key_a))));
        assert_eq!(hex_key.len(), 2 + 130);
        assert!(hex_key.starts_with("0x04"));
        assert_eq!(sent.borrow().len(), 2);

        // Changing the slot drops the cache and the stale flag.
        dev.set_slot("9c").unwrap();
        assert!(!dev.has_stale_certificate());
        assert!(dev.cached_public_key.is_none());
    }

    #[test]
    fn matching_or_missing_certificate_is_not_stale() {
        let key_a = signing_key(1);
        for certificate in [ok(cert_object(&point(&key_a))), sw(0x6A, 0x82)] {
            let handler = card(
                reply(ok(metadata_body(0x11, &point(&key_a)))),
                reply(certificate),
                key_a.clone(),
                reply(sw(0x90, 0x00)),
            );
            let (mut dev, _) = device(handler, Slot::Authentication);
            assert_eq!(
                &block_on(dev.resolve_public_key()).unwrap(),
                key_a.verifying_key()
            );
            assert!(!dev.has_stale_certificate());
        }
    }

    #[test]
    fn certificate_is_used_only_when_metadata_is_unavailable() {
        let key_b = signing_key(2);
        for metadata in [sw(0x6D, 0x00), sw(0x6A, 0x81), ok(vec![0xFF, 0x00])] {
            let handler = card(
                reply(metadata),
                reply(ok(cert_object(&point(&key_b)))),
                key_b.clone(),
                reply(sw(0x90, 0x00)),
            );
            let (mut dev, sent) = device(handler, Slot::Authentication);
            assert_eq!(
                &block_on(dev.resolve_public_key()).unwrap(),
                key_b.verifying_key()
            );
            assert!(!dev.has_stale_certificate());
            assert_eq!(instructions(&sent), vec![INS_GET_METADATA, INS_GET_DATA]);
        }

        // Metadata unavailable and no certificate: the slot is empty.
        let handler = card(
            reply(sw(0x6D, 0x00)),
            reply(sw(0x6A, 0x82)),
            key_b,
            reply(sw(0x90, 0x00)),
        );
        let (mut dev, _) = device(handler, Slot::Authentication);
        assert!(matches!(
            block_on(dev.resolve_public_key()),
            Err(WasmError::CoreError(msg)) if msg.contains("empty")
        ));
    }

    #[test]
    fn metadata_is_authoritative_for_empty_and_non_p256_slots() {
        let key_b = signing_key(2);
        for (metadata, expected) in [
            (sw(0x6A, 0x82), "empty"),
            (
                ok(metadata_body(0x07, &[0x81, 0x01, 0x00])),
                "not a P-256 key",
            ),
        ] {
            // A (stale) certificate exists but must not be consulted.
            let handler = card(
                reply(metadata),
                reply(ok(cert_object(&point(&key_b)))),
                key_b.clone(),
                reply(sw(0x90, 0x00)),
            );
            let (mut dev, sent) = device(handler, Slot::Authentication);
            assert!(matches!(
                block_on(dev.resolve_public_key()),
                Err(WasmError::CoreError(msg)) if msg.contains(expected)
            ));
            assert_eq!(instructions(&sent), vec![INS_GET_METADATA]);
            assert!(dev.cached_public_key.is_none());
        }
    }

    #[test]
    fn signing_resolves_the_key_before_verify_so_verify_precedes_the_signature() {
        let key_a = signing_key(1);
        let handler = card(
            reply(ok(metadata_body(0x11, &point(&key_a)))),
            reply(sw(0x6A, 0x82)),
            key_a,
            reply(sw(0x90, 0x00)),
        );
        // Slot 9c: PIN policy "always"
        let (mut dev, sent) = device(handler, Slot::Signature);

        let signature = block_on(dev.sign_digest_internal(PIN, &DIGEST)).unwrap();
        assert_eq!(signature.len(), 2 + 130);
        assert_eq!(
            instructions(&sent),
            vec![INS_GET_METADATA, INS_GET_DATA, INS_VERIFY, INS_AUTHENTICATE]
        );
        assert!(!dev.authenticated, "9c consumes the PIN verification");

        // Second signature: cached key, VERIFY again right before the signature.
        sent.borrow_mut().clear();
        block_on(dev.sign_digest_internal(PIN, &DIGEST)).unwrap();
        assert_eq!(instructions(&sent), vec![INS_VERIFY, INS_AUTHENTICATE]);
    }

    #[test]
    fn signing_with_an_empty_slot_fails_before_a_pin_attempt_is_spent() {
        let key_a = signing_key(1);
        let handler = card(
            reply(sw(0x6A, 0x82)),
            reply(sw(0x6A, 0x82)),
            key_a,
            reply(sw(0x90, 0x00)),
        );
        let (mut dev, sent) = device(handler, Slot::Signature);

        assert!(matches!(
            block_on(dev.sign_digest_internal(PIN, &DIGEST)),
            Err(WasmError::CoreError(msg)) if msg.contains("empty")
        ));
        assert!(!instructions(&sent).contains(&INS_VERIFY));
        assert_eq!(instructions(&sent), vec![INS_GET_METADATA]);
    }

    #[test]
    fn generate_deletes_the_certificate_and_never_loses_the_new_key() {
        let (old_key, new_key) = (signing_key(1), signing_key(3));

        // Successful delete (and "no certificate" 6A82 counts as success)
        for put_data in [sw(0x90, 0x00), sw(0x6A, 0x82)] {
            let handler = card(
                reply(ok(metadata_body(0x11, &point(&old_key)))),
                reply(ok(cert_object(&point(&old_key)))),
                new_key.clone(),
                reply(put_data),
            );
            let (mut dev, sent) = device(handler, Slot::Authentication);
            dev.mgmt_authenticated = true;
            block_on(dev.resolve_public_key()).unwrap();
            sent.borrow_mut().clear();

            let address = block_on(dev.generate_key_internal(None)).unwrap();
            assert_eq!(address, address_of(&new_key));
            assert_eq!(
                dev.cached_public_key.as_ref(),
                Some(new_key.verifying_key())
            );
            assert_eq!(
                dev.last_generated_public_key(),
                Some(public_key_to_hex(new_key.verifying_key()))
            );
            assert!(!dev.has_stale_certificate());
            assert_eq!(instructions(&sent), vec![INS_GENERATE, INS_PUT_DATA]);
            assert_eq!(
                sent.borrow()[1],
                vec![
                    0x00, 0xDB, 0x3F, 0xFF, 0x07, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x00
                ]
            );
        }

        // Delete refused by the card: the new key is still returned, the old
        // certificate is reported as stale, and the session stays usable.
        let handler = card(
            reply(ok(metadata_body(0x11, &point(&old_key)))),
            reply(ok(cert_object(&point(&old_key)))),
            new_key.clone(),
            reply(sw(0x69, 0x82)),
        );
        let (mut dev, _) = device(handler, Slot::Authentication);
        dev.mgmt_authenticated = true;
        let address = block_on(async {
            let result = dev.generate_key_internal(None).await;
            dev.settle(result).await
        })
        .unwrap();
        assert_eq!(address, address_of(&new_key));
        assert!(dev.has_stale_certificate());
        assert!(dev.is_connected());
        assert_eq!(
            dev.cached_public_key.as_ref(),
            Some(new_key.verifying_key())
        );

        // Session lost during the delete (whether or not the card deleted the
        // certificate before the reply was lost): the new key's address is
        // still returned, the staleness is still reported, and the new public
        // key stays readable without the session, while the device is
        // disconnected and its session state is gone.
        let new_key_hex = format!("0x{}", hex::encode(point(&new_key)));
        for lost in [
            WasmError::Disconnected("bridge session ended".into()),
            WasmError::CardReset,
        ] {
            let handler = card(
                reply(ok(metadata_body(0x11, &point(&old_key)))),
                reply(ok(cert_object(&point(&old_key)))),
                new_key.clone(),
                reply(Err(lost)),
            );
            let (mut dev, sent) = device(handler, Slot::Authentication);
            dev.mgmt_authenticated = true;
            dev.authenticated = true;
            let address = block_on(async {
                let result = dev.generate_key_internal(None).await;
                dev.settle(result).await
            })
            .unwrap();
            assert_eq!(address, address_of(&new_key));
            assert!(dev.has_stale_certificate());
            assert!(!dev.is_connected());
            assert!(!dev.authenticated);
            assert!(!dev.mgmt_authenticated);
            assert!(dev.cached_public_key.is_none());
            assert_eq!(
                dev.last_generated_public_key().as_deref(),
                Some(new_key_hex.as_str())
            );

            // Reading it needs no card access, and disconnect() keeps it.
            let sent_before = sent.borrow().len();
            block_on(dev.disconnect()).unwrap();
            assert_eq!(
                dev.last_generated_public_key().as_deref(),
                Some(new_key_hex.as_str())
            );
            assert_eq!(sent.borrow().len(), sent_before);
        }
    }

    #[test]
    fn last_generated_public_key_never_outlives_its_slot_or_call() {
        let (old_key, new_key) = (signing_key(1), signing_key(3));
        let handler = card(
            reply(ok(metadata_body(0x11, &point(&old_key)))),
            reply(sw(0x6A, 0x82)),
            new_key.clone(),
            reply(sw(0x90, 0x00)),
        );
        let (mut dev, _) = device(handler, Slot::Authentication);
        assert_eq!(dev.last_generated_public_key(), None);

        dev.mgmt_authenticated = true;
        block_on(dev.generate_key_internal(None)).unwrap();
        let new_key_hex = format!("0x{}", hex::encode(point(&new_key)));
        assert_eq!(dev.last_generated_public_key(), Some(new_key_hex));

        // Re-selecting the same slot keeps it; changing the slot drops it.
        dev.set_slot("9A").unwrap();
        assert!(dev.last_generated_public_key().is_some());
        dev.set_slot("9c").unwrap();
        assert_eq!(dev.last_generated_public_key(), None);
        dev.set_slot("9a").unwrap();
        assert_eq!(dev.last_generated_public_key(), None);

        // A rejected generateKey() clears the key of an earlier call.
        dev.last_generated_public_key = Some(*new_key.verifying_key());
        dev.mgmt_authenticated = false;
        assert_eq!(
            block_on(dev.generate_key_internal(None)),
            Err(WasmError::SecurityStatusNotSatisfied)
        );
        assert_eq!(dev.last_generated_public_key(), None);

        let (transport, _) = ScriptedTransport::new(Box::new(|_| {
            Err(WasmError::Disconnected("gone; reconnect".into()))
        }));
        let mut dev = YubiKeyDevice::with_transport(DeviceTransport::Scripted(transport));
        dev.mgmt_authenticated = true;
        dev.last_generated_public_key = Some(*new_key.verifying_key());
        let result = block_on(async {
            let result = dev.generate_key_internal(None).await;
            dev.settle(result).await
        });
        assert!(matches!(result, Err(WasmError::Disconnected(_))));
        assert_eq!(dev.last_generated_public_key(), None);
    }

    #[test]
    fn generate_requires_management_key_and_keeps_session_errors() {
        let key = signing_key(1);
        let (mut dev, sent) = device(
            card(
                reply(sw(0x6A, 0x82)),
                reply(sw(0x6A, 0x82)),
                key.clone(),
                reply(sw(0x90, 0x00)),
            ),
            Slot::Authentication,
        );
        assert_eq!(
            block_on(dev.generate_key_internal(None)),
            Err(WasmError::SecurityStatusNotSatisfied)
        );
        assert!(sent.borrow().is_empty());

        // A session-ending error from GENERATE is not wrapped as KeyGenerationFailed.
        let (transport, _) = ScriptedTransport::new(Box::new(|_| {
            Err(WasmError::Disconnected("gone; reconnect".into()))
        }));
        let mut dev = YubiKeyDevice::with_transport(DeviceTransport::Scripted(transport));
        dev.mgmt_authenticated = true;
        assert!(matches!(
            block_on(dev.generate_key_internal(None)),
            Err(WasmError::Disconnected(_))
        ));
    }

    #[test]
    fn session_loss_clears_state_and_disconnects() {
        use crate::bridge_transport::{
            body_read_failure_error, bridge_http_error, fetch_failure_error,
        };

        let (url, origin) = ("http://127.0.0.1:8765", "https://app.example");
        for lost in [
            WasmError::Disconnected("bridge session ended (409 Conflict): x; reconnect".into()),
            WasmError::CardReset,
            // The bridge stopped, crashed, or was restarted with a new token.
            fetch_failure_error(url, origin, true),
            body_read_failure_error("failed to await bridge response text", url, origin, true),
            bridge_http_error(401, "missing or invalid bearer token", true),
            bridge_http_error(500, "bridge state lock poisoned", true),
        ] {
            let key = signing_key(1);
            let expected = lost.clone();
            let (transport, _) = ScriptedTransport::new(Box::new(move |_| Err(lost.clone())));
            let mut dev = YubiKeyDevice::with_transport(DeviceTransport::Scripted(transport));
            dev.slot = Slot::Signature;
            dev.authenticated = true;
            dev.mgmt_authenticated = true;
            dev.cached_public_key = Some(*key.verifying_key());

            let result = block_on(async {
                let result = dev.sign_digest_internal(PIN, &DIGEST).await;
                dev.settle(result).await
            });
            assert_eq!(result, Err(expected.clone()));
            assert!(expected.to_string().contains("reconnect"));
            assert!(!dev.is_connected());
            assert!(!dev.authenticated);
            assert!(!dev.mgmt_authenticated);
            assert!(dev.cached_public_key.is_none());
        }

        // Ordinary card errors keep the session.
        let key = signing_key(1);
        let (transport, _) = ScriptedTransport::new(Box::new(|_| sw(0x63, 0xC2)));
        let mut dev = YubiKeyDevice::with_transport(DeviceTransport::Scripted(transport));
        dev.mgmt_authenticated = true;
        dev.cached_public_key = Some(*key.verifying_key());
        let result = block_on(async {
            let result = dev.sign_digest_internal(PIN, &DIGEST).await;
            dev.settle(result).await
        });
        assert!(matches!(result, Err(WasmError::InvalidPin { .. })));
        assert!(dev.is_connected());
        assert!(dev.mgmt_authenticated);
        assert!(dev.cached_public_key.is_some());

        // Transient bridge errors leave the session (and its state) usable.
        for transient in [
            bridge_http_error(403, "APDU rejected by bridge policy", true),
            bridge_http_error(408, "request deadline", true),
            bridge_http_error(502, "APDU transmit failed", true),
        ] {
            let expected = transient.clone();
            let (transport, _) = ScriptedTransport::new(Box::new(move |_| Err(transient.clone())));
            let mut dev = YubiKeyDevice::with_transport(DeviceTransport::Scripted(transport));
            dev.mgmt_authenticated = true;
            dev.cached_public_key = Some(*key.verifying_key());
            let result = block_on(async {
                let result = dev.verify_pin_internal(PIN).await;
                dev.settle(result).await
            });
            assert_eq!(result, Err(expected));
            assert!(dev.is_connected());
            assert!(dev.mgmt_authenticated);
            assert!(dev.cached_public_key.is_some());
        }
    }

    /// Every APDU the device sends must pass the bridge's allowlist byte for byte.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn every_device_apdu_is_accepted_by_the_bridge_allowlist() {
        use yubikey_evm_signer_core::bridge::validate_bridge_apdu;

        let (old_key, new_key) = (signing_key(1), signing_key(3));
        let mut generation_apdus = vec![
            build_mgmt_auth_request_witness_apdu(ManagementKeyAlgorithm::Aes192)
                .to_bytes()
                .unwrap(),
            build_mgmt_auth_verify_apdu(ManagementKeyAlgorithm::Aes192, &[1; 16], &[2; 16])
                .unwrap()
                .to_bytes()
                .unwrap(),
        ];

        for slot in [
            Slot::Authentication,
            Slot::Signature,
            Slot::KeyManagement,
            Slot::CardAuthentication,
        ] {
            let handler = card(
                reply(ok(metadata_body(0x11, &point(&old_key)))),
                reply(ok(cert_object(&point(&old_key)))),
                old_key.clone(),
                reply(sw(0x90, 0x00)),
            );
            let (mut dev, sent) = device(handler, slot);
            block_on(dev.sign_digest_internal(PIN, &DIGEST)).unwrap();
            block_on(dev.verify_pin_internal(PIN)).unwrap();
            let read_and_sign = sent.borrow().clone();
            assert_eq!(read_and_sign.len(), 5);
            for apdu in &read_and_sign {
                validate_bridge_apdu(apdu, false)
                    .unwrap_or_else(|e| panic!("{}: {e}", hex::encode(apdu)));
            }

            let handler = card(
                reply(ok(metadata_body(0x11, &point(&old_key)))),
                reply(ok(cert_object(&point(&old_key)))),
                new_key.clone(),
                reply(sw(0x90, 0x00)),
            );
            let (mut dev, sent) = device(handler, slot);
            dev.mgmt_authenticated = true;
            block_on(dev.generate_key_internal(None)).unwrap();
            generation_apdus.extend(sent.borrow().iter().cloned());
        }

        assert_eq!(generation_apdus.len(), 2 + 4 * 2);
        for apdu in &generation_apdus {
            validate_bridge_apdu(apdu, true)
                .unwrap_or_else(|e| panic!("{}: {e}", hex::encode(apdu)));
            // ...and they are exactly the commands that need --allow-generate.
            assert!(validate_bridge_apdu(apdu, false).is_err());
        }
    }
}
