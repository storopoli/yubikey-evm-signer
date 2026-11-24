//! YubiKey device abstraction for browser use.
//!
//! This module provides [`YubiKeyDevice`], a JavaScript-friendly API for
//! interacting with YubiKey PIV applets over either the local PC/SC loopback
//! bridge ([`YubiKeyDevice::connect_bridge`]) or raw WebUSB
//! ([`YubiKeyDevice::connect`]). All PIV APDU construction, mutual management
//! key cryptography, BER-TLV/X.509 parsing, and EIP-191/EIP-712/EIP-1559
//! hashing are delegated directly to [`yubikey_evm_signer_core`].

use std::fmt;

use p256::ecdsa::VerifyingKey;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use yubikey_evm_signer_core::crypto::create_ethereum_signature;
use yubikey_evm_signer_core::eip712::TypedData;
use yubikey_evm_signer_core::yubikey::Slot;
use yubikey_evm_signer_core::yubikey::apdu::Apdu;
use yubikey_evm_signer_core::yubikey::piv::{
    ManagementKeyAlgorithm, build_generate_key_apdu, build_get_certificate_apdu,
    build_mgmt_auth_request_witness_apdu, build_mgmt_auth_verify_apdu, build_select_piv_apdu,
    build_sign_apdu, build_verify_pin_apdu, decrypt_mgmt_witness, encrypt_mgmt_challenge,
    parse_challenge_response, parse_public_key_response, parse_signature_response,
    parse_witness_response, verify_mgmt_challenge_response,
};
use yubikey_evm_signer_core::{Address, Transaction, eip191_hash};

use crate::bridge_transport::BridgeTransport;
use crate::error::{WasmError, WasmResult};
use crate::transport::WebUsbTransport;

/// Active browser transport backing a [`YubiKeyDevice`].
enum DeviceTransport {
    WebUsb(WebUsbTransport),
    Bridge(BridgeTransport),
}

impl DeviceTransport {
    async fn transmit_async(
        &mut self,
        apdu: &Apdu,
    ) -> WasmResult<yubikey_evm_signer_core::yubikey::ApduResponse> {
        match self {
            Self::WebUsb(t) => t.transmit_async(apdu).await,
            Self::Bridge(t) => t.transmit_async(apdu).await,
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
        }
    }

    async fn close(&mut self) -> WasmResult<()> {
        match self {
            Self::WebUsb(t) => t.close().await,
            Self::Bridge(t) => t.close().await,
        }
    }

    const fn is_connected(&self) -> bool {
        match self {
            Self::WebUsb(t) => t.is_connected(),
            Self::Bridge(t) => t.is_connected(),
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

/// A connected YubiKey device.
///
/// Supports both the local PC/SC loopback bridge (recommended across all desktop
/// browsers and OSes) and direct WebUSB.
///
/// # Thread Safety
///
/// This type is not thread-safe and should only be used from the main thread
/// in a browser environment.
#[wasm_bindgen]
pub struct YubiKeyDevice {
    /// The underlying transport (WebUSB or local PC/SC bridge).
    transport: DeviceTransport,

    /// The active PIV slot for key retrieval, generation, and signing.
    slot: Slot,

    /// Cached P-256 verifying key for the active slot.
    cached_public_key: Option<VerifyingKey>,

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
    /// * `url` - Loopback bridge URL (e.g. `"http://127.0.0.1:8765"`)
    /// * `token` - Per-session bearer token printed by `yubikey-cli bridge`
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if `url` is not loopback, authentication fails, or no
    /// YubiKey is available on the local PC/SC daemon.
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

        Ok(Self {
            transport: DeviceTransport::WebUsb(transport),
            slot: Slot::Authentication,
            cached_public_key: None,
            authenticated: false,
            mgmt_authenticated: false,
        })
    }

    /// Internal bridge connection flow (`/v1/connect` already selects `PIV_AID`).
    async fn connect_bridge_internal(url: &str, token: &str) -> WasmResult<YubiKeyDevice> {
        let transport = BridgeTransport::connect(url, token).await?;

        Ok(Self {
            transport: DeviceTransport::Bridge(transport),
            slot: Slot::Authentication,
            cached_public_key: None,
            authenticated: false,
            mgmt_authenticated: false,
        })
    }

    /// Sets the active PIV slot (`"9a"`, `"9c"`, `"9d"`, or `"9e"`, case-insensitive).
    ///
    /// Changing the slot invalidates any cached public key.
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
        }
        Ok(())
    }

    /// Returns the currently selected PIV slot (`"9a"`, `"9c"`, `"9d"`, or `"9e"`).
    #[wasm_bindgen(js_name = "getSlot")]
    pub fn get_slot(&self) -> String {
        slot_to_str(self.slot).to_string()
    }

    /// Performs NIST SP 800-73-4 mutual management key authentication (required before `generateKey`).
    ///
    /// # Arguments
    ///
    /// * `key_hex` - Raw management key as hex (with optional `0x` prefix)
    /// * `algorithm` - Optional algorithm: `"aes192"` (default for YubiKey 5.7+),
    ///   `"tdes"` (default for YubiKey `< 5.7`), `"aes128"`, or `"aes256"`
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if the key/algorithm is invalid or mutual authentication fails.
    #[wasm_bindgen(js_name = "authenticateManagementKey")]
    pub async fn authenticate_management_key(
        &mut self,
        key_hex: &str,
        algorithm: Option<String>,
    ) -> Result<(), JsValue> {
        self.authenticate_management_key_internal(key_hex, algorithm.as_deref())
            .await
            .map_err(JsValue::from)
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
    /// # Errors
    ///
    /// Returns a JS `Error` if the PIN is invalid (with remaining retries when reported)
    /// or locked.
    #[wasm_bindgen(js_name = "verifyPin")]
    pub async fn verify_pin(&mut self, pin: &str) -> Result<(), JsValue> {
        self.verify_pin_internal(pin).await.map_err(JsValue::from)
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
    /// [`authenticate_management_key`](Self::authenticate_management_key).
    /// **Warning:** this overwrites any existing key in the active slot.
    ///
    /// # Arguments
    ///
    /// * `pin` - Optional PIN; if non-empty, verified before key generation
    ///
    /// # Returns
    ///
    /// The checksummed Ethereum address derived from the generated public key.
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if the management key is not authenticated or key
    /// generation fails.
    #[wasm_bindgen(js_name = "generateKey")]
    pub async fn generate_key(&mut self, pin: Option<String>) -> Result<String, JsValue> {
        self.generate_key_internal(pin.as_deref())
            .await
            .map_err(JsValue::from)
    }

    /// Internal key generation.
    async fn generate_key_internal(&mut self, pin: Option<&str>) -> WasmResult<String> {
        if !self.mgmt_authenticated {
            return Err(WasmError::SecurityStatusNotSatisfied);
        }

        if let Some(p) = pin
            && !p.is_empty()
        {
            self.verify_pin_internal(p).await?;
        }

        let apdu = build_generate_key_apdu(self.slot);
        let data = self
            .transport
            .transmit_full_async(&apdu, Some(self.slot))
            .await
            .map_err(|e| match e {
                WasmError::SecurityStatusNotSatisfied => WasmError::SecurityStatusNotSatisfied,
                other => WasmError::KeyGenerationFailed(other.to_string()),
            })?;

        let public_key = parse_public_key_response(&data)
            .ok_or_else(|| WasmError::KeyGenerationFailed("invalid response".to_string()))?;

        let address = Address::from_public_key(&public_key);
        self.cached_public_key = Some(public_key);

        Ok(address.to_checksum_hex())
    }

    /// Retrieves the checksummed Ethereum address for the P-256 key in the active slot.
    ///
    /// Reads and strictly validates the slot's X.509 certificate (including gzip-compressed
    /// PIV certificates and multi-chunk `61 XX` responses).
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if the slot has no certificate or does not hold a P-256 key.
    #[wasm_bindgen(js_name = "getAddress")]
    pub async fn get_address(&mut self) -> Result<String, JsValue> {
        self.get_address_internal().await.map_err(JsValue::from)
    }

    /// Internal address retrieval.
    async fn get_address_internal(&mut self) -> WasmResult<String> {
        if let Some(ref pk) = self.cached_public_key {
            return Ok(Address::from_public_key(pk).to_checksum_hex());
        }

        let apdu = build_get_certificate_apdu(self.slot);
        let data = self
            .transport
            .transmit_full_async(&apdu, Some(self.slot))
            .await?;

        if data.is_empty() {
            return Err(WasmError::CoreError(format!(
                "PIV slot {} is empty",
                slot_to_str(self.slot)
            )));
        }

        let public_key = yubikey_evm_signer_core::yubikey::piv::parse_certificate_public_key(&data)
            .ok_or_else(|| {
                WasmError::CoreError(format!(
                    "certificate in slot {} does not contain a valid P-256 public key",
                    slot_to_str(self.slot)
                ))
            })?;

        let address = Address::from_public_key(&public_key);
        self.cached_public_key = Some(public_key);

        Ok(address.to_checksum_hex())
    }

    /// Signs a 32-byte prehashed digest using the YubiKey.
    ///
    /// # Arguments
    ///
    /// * `pin` - PIV PIN (always validated and verified when the slot requires a PIN or `pin` is non-empty)
    /// * `hash` - 32-byte digest as hex (with optional `0x` prefix)
    ///
    /// # Returns
    ///
    /// The 65-byte low-S Ethereum signature (`r || s || v`) as a `0x`-prefixed hex string.
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if the hash or PIN is invalid, or signing fails.
    #[wasm_bindgen(js_name = "signHash")]
    pub async fn sign_hash(&mut self, pin: &str, hash: &str) -> Result<String, JsValue> {
        let hash_bytes = parse_hash_hex(hash).map_err(JsValue::from)?;
        self.sign_digest_internal(pin, &hash_bytes)
            .await
            .map_err(JsValue::from)
    }

    /// Internal 32-byte digest signing.
    async fn sign_digest_internal(
        &mut self,
        pin: &str,
        hash_bytes: &[u8; 32],
    ) -> WasmResult<String> {
        // Always verify PIN when the slot requires it or a PIN string was provided
        if self.slot.requires_pin() || !pin.is_empty() {
            self.verify_pin_internal(pin).await?;
        }

        // Ensure we have the public key for recovery parameter calculation
        if self.cached_public_key.is_none() {
            self.get_address_internal().await?;
        }

        let public_key = self.cached_public_key.ok_or_else(|| {
            WasmError::SigningFailed(
                "public key could not be retrieved for active slot".to_string(),
            )
        })?;

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
    /// or hardware signing fails.
    #[wasm_bindgen(js_name = "signTransaction")]
    pub async fn sign_transaction(&mut self, pin: &str, tx_json: &str) -> Result<String, JsValue> {
        self.sign_transaction_internal(pin, tx_json)
            .await
            .map_err(JsValue::from)
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
    /// Returns a JS `Error` if the typed data is invalid or signing fails.
    #[wasm_bindgen(js_name = "signTypedData")]
    pub async fn sign_typed_data(
        &mut self,
        pin: &str,
        typed_data_json: &str,
    ) -> Result<String, JsValue> {
        self.sign_typed_data_internal(pin, typed_data_json)
            .await
            .map_err(JsValue::from)
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
    /// Returns a JS `Error` if PIN verification or signing fails.
    #[wasm_bindgen(js_name = "signMessage")]
    pub async fn sign_message(&mut self, pin: &str, message: &str) -> Result<String, JsValue> {
        let hash: [u8; 32] = eip191_hash(message.as_bytes()).into();
        self.sign_digest_internal(pin, &hash)
            .await
            .map_err(JsValue::from)
    }

    /// Disconnects from the YubiKey and clears all cached session state.
    ///
    /// # Errors
    ///
    /// Returns a JS `Error` if closing the transport fails.
    #[wasm_bindgen]
    pub async fn disconnect(&mut self) -> Result<(), JsValue> {
        self.authenticated = false;
        self.mgmt_authenticated = false;
        self.cached_public_key = None;
        self.transport.close().await.map_err(JsValue::from)
    }

    /// Checks if the underlying device transport is still connected.
    #[wasm_bindgen(js_name = "isConnected")]
    #[allow(clippy::missing_const_for_fn)]
    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
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
}
