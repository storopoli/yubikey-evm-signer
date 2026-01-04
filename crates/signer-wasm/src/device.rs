//! YubiKey device abstraction for browser use.
//!
//! This module provides a high-level, JavaScript-friendly API for interacting
//! with YubiKey devices via WebUSB. It wraps the lower-level transport and
//! PIV operations into a simple interface suitable for Ethereum signing.
//!
//! # Example
//!
//! ```ignore
//! use yubikey_evm_signer_wasm::device::YubiKeyDevice;
//!
//! // Connect to a YubiKey (must be called from user gesture)
//! let device = YubiKeyDevice::connect().await?;
//!
//! // Generate a new key
//! device.generate_key("123456").await?;
//!
//! // Get the Ethereum address
//! let address = device.get_address().await?;
//!
//! // Sign a transaction
//! let signature = device.sign_hash("123456", &hash).await?;
//! ```

use std::fmt;

use alloy_primitives::keccak256;
use p256::EncodedPoint;
use p256::ecdsa::VerifyingKey;
use wasm_bindgen::prelude::*;

use yubikey_evm_signer_core::Address;
use yubikey_evm_signer_core::crypto::create_ethereum_signature;
use yubikey_evm_signer_core::yubikey::Slot;
use yubikey_evm_signer_core::yubikey::apdu::Apdu;

use crate::error::{WasmError, WasmResult};
use crate::transport::WebUsbTransport;

/// PIV applet AID (Application Identifier).
const PIV_AID: [u8; 9] = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

/// PIV instruction codes.
mod ins {
    /// `SELECT` instruction.
    pub(super) const SELECT: u8 = 0xA4;

    /// `VERIFY` instruction.
    pub(super) const VERIFY: u8 = 0x20;

    /// `AUTHENTICATE` instruction.
    pub(super) const AUTHENTICATE: u8 = 0x87;

    /// `GENERATE ASYMMETRIC` instruction.
    pub(super) const GENERATE_ASYMMETRIC: u8 = 0x47;

    /// `GET DATA` instruction.
    pub(super) const GET_DATA: u8 = 0xCB;
}

/// Algorithm identifier for P-256.
const ALG_ECCP256: u8 = 0x11;

/// A connected YubiKey device.
///
/// This type represents an active connection to a YubiKey device and provides
/// methods for Ethereum-related operations such as key generation and signing.
///
/// # Thread Safety
///
/// This type is not thread-safe and should only be used from the main thread
/// in a browser environment.
#[wasm_bindgen]
pub struct YubiKeyDevice {
    /// The underlying WebUSB transport.
    transport: WebUsbTransport,

    /// The PIV slot to use for Ethereum signing.
    slot: Slot,

    /// Cached public key (if retrieved).
    cached_public_key: Option<VerifyingKey>,

    /// Whether PIN has been verified in current session.
    authenticated: bool,
}

impl fmt::Debug for YubiKeyDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("YubiKeyDevice")
            .field("slot", &self.slot)
            .field("authenticated", &self.authenticated)
            .field("has_cached_key", &self.cached_public_key.is_some())
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl YubiKeyDevice {
    /// Connects to a YubiKey device via WebUSB.
    ///
    /// This method must be called in response to a user gesture (e.g., button click).
    /// It will display the browser's device picker dialog.
    ///
    /// # Returns
    ///
    /// A `Promise` that resolves to a [`YubiKeyDevice`] instance.
    ///
    /// # Errors
    ///
    /// - If WebUSB is not supported
    /// - If no device was selected
    /// - If the device could not be opened
    #[wasm_bindgen]
    pub async fn connect() -> Result<YubiKeyDevice, JsValue> {
        Self::connect_internal().await.map_err(JsValue::from)
    }

    /// Internal connect implementation.
    async fn connect_internal() -> WasmResult<YubiKeyDevice> {
        let mut transport = WebUsbTransport::request_device().await?;

        // Select PIV applet
        let apdu = Apdu::new(0x00, ins::SELECT, 0x04, 0x00, PIV_AID.to_vec());
        let response = transport.transmit_async(&apdu).await?;
        response
            .check()
            .map_err(|e| WasmError::PivSelectFailed(e.to_string()))?;

        Ok(Self {
            transport,
            slot: Slot::Authentication, // Slot 9a is recommended for Ethereum
            cached_public_key: None,
            authenticated: false,
        })
    }

    /// Verifies the user's PIN.
    ///
    /// This must be called before signing operations.
    ///
    /// # Arguments
    ///
    /// * `pin` - The PIN string (typically 6-8 digits)
    ///
    /// # Errors
    ///
    /// - If the PIN is incorrect
    /// - If the PIN is locked
    #[wasm_bindgen(js_name = "verifyPin")]
    pub async fn verify_pin(&mut self, pin: &str) -> Result<(), JsValue> {
        self.verify_pin_internal(pin).await.map_err(JsValue::from)
    }

    /// Internal PIN verification.
    async fn verify_pin_internal(&mut self, pin: &str) -> WasmResult<()> {
        let pin_bytes = pin.as_bytes();
        if pin_bytes.len() > 8 {
            return Err(WasmError::InvalidPin);
        }

        // Pad PIN to 8 bytes with 0xFF
        let mut padded_pin = [0xFF; 8];
        padded_pin[..pin_bytes.len()].copy_from_slice(pin_bytes);

        let apdu = Apdu::new(0x00, ins::VERIFY, 0x00, 0x80, padded_pin.to_vec());
        let response = self.transport.transmit_async(&apdu).await?;

        match response.check() {
            Ok(()) => {
                self.authenticated = true;
                Ok(())
            }
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("locked") {
                    Err(WasmError::PinLocked)
                } else {
                    Err(WasmError::InvalidPin)
                }
            }
        }
    }

    /// Generates a new P-256 key pair in the YubiKey.
    ///
    /// # Arguments
    ///
    /// * `pin` - The PIN for authentication
    ///
    /// # Returns
    ///
    /// The Ethereum address derived from the generated public key.
    ///
    /// # Errors
    ///
    /// - If PIN verification fails
    /// - If key generation fails
    #[wasm_bindgen(js_name = "generateKey")]
    pub async fn generate_key(&mut self, pin: &str) -> Result<String, JsValue> {
        self.generate_key_internal(pin).await.map_err(JsValue::from)
    }

    /// Internal key generation.
    async fn generate_key_internal(&mut self, pin: &str) -> WasmResult<String> {
        // Verify PIN first
        if !self.authenticated {
            self.verify_pin_internal(pin).await?;
        }

        // Build generate key APDU
        let template = vec![0xAC, 0x03, 0x80, 0x01, ALG_ECCP256];
        let apdu = Apdu::new(
            0x00,
            ins::GENERATE_ASYMMETRIC,
            0x00,
            self.slot.id(),
            template,
        );

        let response = self.transport.transmit_async(&apdu).await?;
        response
            .check()
            .map_err(|e| WasmError::KeyGenerationFailed(e.to_string()))?;

        // Parse public key from response
        let public_key = parse_public_key_response(response.data())
            .ok_or_else(|| WasmError::KeyGenerationFailed("invalid response".to_string()))?;

        let address = Address::from_public_key(&public_key);
        self.cached_public_key = Some(public_key);

        Ok(address.to_checksum_hex())
    }

    /// Gets the Ethereum address for the key in the current slot.
    ///
    /// # Returns
    ///
    /// The checksummed Ethereum address as a hex string.
    ///
    /// # Errors
    ///
    /// - If no key is present in the slot
    /// - If the key type is not supported
    #[wasm_bindgen(js_name = "getAddress")]
    pub async fn get_address(&mut self) -> Result<String, JsValue> {
        self.get_address_internal().await.map_err(JsValue::from)
    }

    /// Internal address retrieval.
    async fn get_address_internal(&mut self) -> WasmResult<String> {
        // Use cached public key if available
        if let Some(ref pk) = self.cached_public_key {
            return Ok(Address::from_public_key(pk).to_checksum_hex());
        }

        // Retrieve public key from device
        let object_id = self.slot.object_id();
        let data = vec![0x5C, 0x03, object_id[0], object_id[1], object_id[2]];
        let apdu = Apdu::with_le(0x00, ins::GET_DATA, 0x3F, 0xFF, data, 256);

        let response = self.transport.transmit_async(&apdu).await?;
        response
            .check()
            .map_err(|e| WasmError::CoreError(e.to_string()))?;

        if response.data().is_empty() {
            return Err(WasmError::CoreError("slot is empty".to_string()));
        }

        // Parse public key from certificate
        let public_key = parse_certificate_public_key(response.data())
            .ok_or_else(|| WasmError::CoreError("invalid key type".to_string()))?;

        let address = Address::from_public_key(&public_key);
        self.cached_public_key = Some(public_key);

        Ok(address.to_checksum_hex())
    }

    /// Signs a 32-byte hash using the YubiKey.
    ///
    /// # Arguments
    ///
    /// * `pin` - The PIN for authentication
    /// * `hash` - The 32-byte hash to sign (as hex string with optional 0x prefix)
    ///
    /// # Returns
    ///
    /// The signature as a hex string (r || s || v, 65 bytes).
    ///
    /// # Errors
    ///
    /// - If PIN verification fails
    /// - If the hash is invalid
    /// - If signing fails
    #[wasm_bindgen(js_name = "signHash")]
    pub async fn sign_hash(&mut self, pin: &str, hash: &str) -> Result<String, JsValue> {
        self.sign_hash_internal(pin, hash)
            .await
            .map_err(JsValue::from)
    }

    /// Internal hash signing.
    async fn sign_hash_internal(&mut self, pin: &str, hash: &str) -> WasmResult<String> {
        // Parse hash
        let hash_str = hash.strip_prefix("0x").unwrap_or(hash);
        let hash_bytes: [u8; 32] = hex::decode(hash_str)
            .map_err(|e| WasmError::InvalidTransaction(e.to_string()))?
            .try_into()
            .map_err(|_| WasmError::InvalidTransaction("hash must be 32 bytes".to_string()))?;

        // Verify PIN if needed
        if !self.authenticated {
            self.verify_pin_internal(pin).await?;
        }

        // Ensure we have the public key for recovery parameter calculation
        if self.cached_public_key.is_none() {
            self.get_address_internal().await?;
        }

        let public_key = self.cached_public_key.as_ref().unwrap();

        // Build sign APDU
        let mut template = Vec::with_capacity(6 + hash_bytes.len());
        template.push(0x7C);
        template.push((4 + hash_bytes.len()) as u8);
        template.push(0x82);
        template.push(0x00);
        template.push(0x81);
        template.push(hash_bytes.len() as u8);
        template.extend_from_slice(&hash_bytes);

        let apdu = Apdu::with_le(
            0x00,
            ins::AUTHENTICATE,
            ALG_ECCP256,
            self.slot.id(),
            template,
            256,
        );

        let response = self.transport.transmit_async(&apdu).await?;
        response
            .check()
            .map_err(|e| WasmError::SigningFailed(e.to_string()))?;

        // Parse DER signature
        let der_sig = parse_signature_response(response.data())
            .ok_or_else(|| WasmError::SigningFailed("invalid signature response".to_string()))?;

        // Convert to Ethereum signature format
        let signature = create_ethereum_signature(&der_sig, &hash_bytes, public_key)
            .map_err(|e| WasmError::SigningFailed(e.to_string()))?;

        Ok(signature.to_hex())
    }

    /// Signs an Ethereum transaction.
    ///
    /// # Arguments
    ///
    /// * `pin` - The PIN for authentication
    /// * `tx_json` - The transaction as a JSON string
    ///
    /// # Returns
    ///
    /// The signature as a hex string.
    #[wasm_bindgen(js_name = "signTransaction")]
    pub async fn sign_transaction(&mut self, pin: &str, tx_json: &str) -> Result<String, JsValue> {
        self.sign_transaction_internal(pin, tx_json)
            .await
            .map_err(JsValue::from)
    }

    /// Internal transaction signing.
    async fn sign_transaction_internal(&mut self, pin: &str, tx_json: &str) -> WasmResult<String> {
        use yubikey_evm_signer_core::Transaction;

        let tx: Transaction = serde_json::from_str(tx_json)
            .map_err(|e| WasmError::InvalidTransaction(e.to_string()))?;

        let hash = tx.signing_hash();
        let hash_hex = format!("0x{}", hex::encode(hash.as_slice()));

        self.sign_hash_internal(pin, &hash_hex).await
    }

    /// Signs EIP-712 typed data.
    ///
    /// # Arguments
    ///
    /// * `pin` - The PIN for authentication
    /// * `typed_data_json` - The typed data as a JSON string
    ///
    /// # Returns
    ///
    /// The signature as a hex string.
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

    /// Internal typed data signing.
    async fn sign_typed_data_internal(
        &mut self,
        pin: &str,
        typed_data_json: &str,
    ) -> WasmResult<String> {
        use yubikey_evm_signer_core::eip712::TypedData;

        let typed_data: TypedData = serde_json::from_str(typed_data_json)
            .map_err(|e| WasmError::InvalidTypedData(e.to_string()))?;

        let hash = typed_data
            .signing_hash()
            .map_err(|e| WasmError::InvalidTypedData(e.to_string()))?;

        let hash_hex = format!("0x{}", hex::encode(hash));

        self.sign_hash_internal(pin, &hash_hex).await
    }

    /// Signs a personal message (EIP-191).
    ///
    /// # Arguments
    ///
    /// * `pin` - The PIN for authentication
    /// * `message` - The message to sign (as UTF-8 string)
    ///
    /// # Returns
    ///
    /// The signature as a hex string.
    #[wasm_bindgen(js_name = "signMessage")]
    pub async fn sign_message(&mut self, pin: &str, message: &str) -> Result<String, JsValue> {
        self.sign_message_internal(pin, message)
            .await
            .map_err(JsValue::from)
    }

    /// Internal message signing (EIP-191).
    async fn sign_message_internal(&mut self, pin: &str, message: &str) -> WasmResult<String> {
        // EIP-191 personal message prefix
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut data = prefix.into_bytes();
        data.extend_from_slice(message.as_bytes());

        let hash = keccak256(&data);
        let hash_hex = format!("0x{}", hex::encode(hash.as_slice()));

        self.sign_hash_internal(pin, &hash_hex).await
    }

    /// Disconnects from the YubiKey device.
    #[wasm_bindgen]
    pub async fn disconnect(&mut self) -> Result<(), JsValue> {
        self.transport.close().await.map_err(JsValue::from)
    }

    /// Checks if the device is still connected.
    #[wasm_bindgen(js_name = "isConnected")]
    #[allow(clippy::missing_const_for_fn)]
    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
    }
}

/// Parses a public key from a `GENERATE ASYMMETRIC` response.
fn parse_public_key_response(data: &[u8]) -> Option<VerifyingKey> {
    // Response format: 7F 49 len 86 len point
    let mut i = 0;

    // Skip outer tag (7F 49)
    if data.len() < 2 || data[i] != 0x7F || data[i + 1] != 0x49 {
        return None;
    }
    i += 2;

    // Skip length
    if data[i] >= 0x80 {
        i += 1 + (data[i] & 0x7F) as usize;
    } else {
        i += 1;
    }

    // Find tag 86
    while i < data.len() {
        if data[i] == 0x86 {
            i += 1;
            let len = if data[i] >= 0x80 {
                let len_bytes = (data[i] & 0x7F) as usize;
                i += 1;
                let mut len = 0usize;
                for j in 0..len_bytes {
                    len = (len << 8) | (data[i + j] as usize);
                }
                i += len_bytes;
                len
            } else {
                let len = data[i] as usize;
                i += 1;
                len
            };

            if len == 65 && data[i] == 0x04 {
                let point_bytes = &data[i..i + len];
                let point = EncodedPoint::from_bytes(point_bytes).ok()?;
                return VerifyingKey::from_encoded_point(&point).ok();
            }
            break;
        }
        i += 1;
        if i >= data.len() {
            break;
        }
        let len = data[i] as usize;
        i += 1 + len;
    }

    None
}

/// Parses a public key from a certificate response.
fn parse_certificate_public_key(data: &[u8]) -> Option<VerifyingKey> {
    // Look for uncompressed point (0x04 followed by 64 bytes)
    for i in 0..data.len().saturating_sub(65) {
        if data[i] == 0x04 {
            let point_bytes = &data[i..i + 65];
            if let Ok(point) = EncodedPoint::from_bytes(point_bytes)
                && let Ok(key) = VerifyingKey::from_encoded_point(&point)
            {
                return Some(key);
            }
        }
    }
    None
}

/// Parses a signature from a `GENERAL AUTHENTICATE` response.
fn parse_signature_response(data: &[u8]) -> Option<Vec<u8>> {
    // Response format: 7C len 82 len signature
    let mut i = 0;

    if data.is_empty() || data[i] != 0x7C {
        return None;
    }
    i += 1;

    // Skip outer length
    if i >= data.len() {
        return None;
    }
    if data[i] >= 0x80 {
        i += 1 + (data[i] & 0x7F) as usize;
    } else {
        i += 1;
    }

    // Find tag 82
    while i < data.len() {
        if data[i] == 0x82 {
            i += 1;
            if i >= data.len() {
                return None;
            }

            let len = if data[i] >= 0x80 {
                let len_bytes = (data[i] & 0x7F) as usize;
                i += 1;
                let mut len = 0usize;
                for j in 0..len_bytes {
                    if i + j >= data.len() {
                        return None;
                    }
                    len = (len << 8) | (data[i + j] as usize);
                }
                i += len_bytes;
                len
            } else {
                let len = data[i] as usize;
                i += 1;
                len
            };

            if i + len <= data.len() {
                return Some(data[i..i + len].to_vec());
            }
            break;
        }
        i += 1;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn piv_aid() {
        assert_eq!(PIV_AID.len(), 9);
        assert_eq!(PIV_AID[0], 0xA0);
    }
}
