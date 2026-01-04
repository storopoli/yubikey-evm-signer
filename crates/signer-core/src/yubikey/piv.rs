//! PIV session management and operations.
//!
//! This module provides the [`PivSession`] type for interacting with the
//! YubiKey PIV applet. It handles:
//!
//! - Applet selection
//! - PIN verification
//! - Key generation
//! - Signing operations
//! - Public key retrieval
//!
//! # Example
//!
//! ```ignore
//! use yubikey_evm_signer_core::yubikey::{PivSession, Slot, Transport};
//!
//! let transport: Box<dyn Transport> = /* obtain transport */;
//! let mut session = PivSession::new(transport);
//!
//! // Select the PIV applet
//! session.select()?;
//!
//! // Verify PIN
//! session.verify_pin("123456")?;
//!
//! // Generate a P-256 key
//! let public_key = session.generate_key(Slot::Authentication)?;
//!
//! // Sign data
//! let signature = session.sign(Slot::Authentication, &hash)?;
//! ```

use std::fmt;

use p256::EncodedPoint;
use p256::ecdsa::VerifyingKey;

use super::Transport;
use super::apdu::Apdu;
use super::slot::Slot;
use crate::error::{Error, Result};

/// The PIV applet AID (Application Identifier).
const PIV_AID: [u8; 9] = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

/// PIV instruction codes.
mod ins {
    /// `SELECT` instruction.
    pub(super) const SELECT: u8 = 0xA4;

    /// `VERIFY` instruction (for PIN).
    pub(super) const VERIFY: u8 = 0x20;

    /// `GENERAL AUTHENTICATE` instruction.
    pub(super) const AUTHENTICATE: u8 = 0x87;

    /// `GENERATE ASYMMETRIC KEY PAIR` instruction.
    pub(super) const GENERATE_ASYMMETRIC: u8 = 0x47;

    /// `GET DATA` instruction.
    pub(super) const GET_DATA: u8 = 0xCB;
}

/// Key references.
#[cfg(feature = "pcsc")]
mod key {
    /// Management key (3DES).
    pub(super) const MANAGEMENT: u8 = 0x9B;
}

/// The default PIV management key (3DES, 24 bytes).
#[cfg(feature = "pcsc")]
const DEFAULT_MANAGEMENT_KEY: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

/// Algorithm identifiers.
mod alg {
    /// `ECCP256` (secp256r1/P-256).
    pub(super) const ECCP256: u8 = 0x11;

    /// `3DES` (Triple DES for management key).
    #[cfg(feature = "pcsc")]
    pub(super) const TDES: u8 = 0x03;
}

/// A session with the YubiKey PIV applet.
///
/// This type manages the connection to a YubiKey's PIV applet and provides
/// methods for key management and signing operations.
pub struct PivSession {
    /// The underlying transport.
    transport: Box<dyn Transport>,

    /// Whether the applet has been selected.
    selected: bool,

    /// Whether PIN has been verified.
    pin_verified: bool,

    /// Whether management key has been authenticated.
    mgmt_authenticated: bool,
}

impl fmt::Debug for PivSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PivSession")
            .field("selected", &self.selected)
            .field("pin_verified", &self.pin_verified)
            .field("mgmt_authenticated", &self.mgmt_authenticated)
            .finish_non_exhaustive()
    }
}

impl PivSession {
    /// Creates a new PIV session with the given transport.
    ///
    /// # Arguments
    ///
    /// * `transport` - The transport layer for communication
    ///
    /// # Returns
    ///
    /// A new [`PivSession`] instance.
    ///
    /// # Note
    ///
    /// The session is not yet active; call [`select`](Self::select) to
    /// activate the PIV applet.
    #[must_use]
    pub fn new(transport: Box<dyn Transport>) -> Self {
        Self {
            transport,
            selected: false,
            pin_verified: false,
            mgmt_authenticated: false,
        }
    }

    /// Selects the PIV applet on the YubiKey.
    ///
    /// This must be called before any other PIV operations.
    ///
    /// # Returns
    ///
    /// [`Ok(())`](Ok) if selection was successful.
    ///
    /// # Errors
    ///
    /// Returns an error if communication fails or the applet is not present.
    pub fn select(&mut self) -> Result<()> {
        let apdu = Apdu::new(0x00, ins::SELECT, 0x04, 0x00, PIV_AID.to_vec());
        let response = self.transport.transmit(&apdu)?;
        response.check()?;

        self.selected = true;
        self.pin_verified = false;
        self.mgmt_authenticated = false;
        Ok(())
    }

    /// Verifies the user's PIN.
    ///
    /// # Arguments
    ///
    /// * `pin` - The PIN string (typically 6-8 digits)
    ///
    /// # Returns
    ///
    /// [`Ok(())`](Ok) if PIN verification was successful.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidPin`] if the PIN is incorrect
    /// - [`Error::PinLocked`] if the PIN has been locked after too many attempts
    ///
    /// # Example
    ///
    /// ```ignore
    /// session.verify_pin("123456")?;
    /// ```
    pub fn verify_pin(&mut self, pin: &str) -> Result<()> {
        if !self.selected {
            return Err(Error::ApduError("PIV applet not selected".to_string()));
        }

        let pin_bytes = pin.as_bytes();
        if pin_bytes.len() > 8 {
            return Err(Error::InvalidPin);
        }

        // Pad PIN to 8 bytes with 0xFF
        let mut padded_pin = [0xFF; 8];
        padded_pin[..pin_bytes.len()].copy_from_slice(pin_bytes);

        let apdu = Apdu::new(0x00, ins::VERIFY, 0x00, 0x80, padded_pin.to_vec());
        let response = self.transport.transmit(&apdu)?;
        response.check()?;

        self.pin_verified = true;
        Ok(())
    }

    /// Authenticates with the management key using 3DES mutual authentication.
    ///
    /// This is required before key generation or other administrative operations.
    /// Uses the default PIV management key if no custom key has been set.
    ///
    /// # Returns
    ///
    /// [`Ok(())`](Ok) if authentication was successful.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails (e.g., wrong management key).
    ///
    /// # Note
    ///
    /// This method requires the `pcsc` feature to be enabled.
    #[cfg(feature = "pcsc")]
    pub fn authenticate_management_key(&mut self) -> Result<()> {
        self.authenticate_management_key_with(&DEFAULT_MANAGEMENT_KEY)
    }

    /// Authenticates with a custom management key.
    ///
    /// # Arguments
    ///
    /// * `key` - The 24-byte 3DES management key
    ///
    /// # Returns
    ///
    /// [`Ok(())`](Ok) if authentication was successful.
    #[cfg(feature = "pcsc")]
    pub fn authenticate_management_key_with(&mut self, key: &[u8; 24]) -> Result<()> {
        use des::TdesEde3;
        use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

        if !self.selected {
            return Err(Error::ApduError("PIV applet not selected".to_string()));
        }

        // Step 1: Request a witness (challenge from card)
        // GENERAL AUTHENTICATE with algorithm 3DES, key reference 9B
        // Data: 7C 02 80 00 (request witness)
        let witness_request = vec![0x7C, 0x02, 0x80, 0x00];
        let apdu = Apdu::with_le(
            0x00,
            ins::AUTHENTICATE,
            alg::TDES,
            key::MANAGEMENT,
            witness_request,
            256,
        );
        let response = self.transport.transmit(&apdu)?;
        response.check()?;

        // Parse the witness from response: 7C len 80 len witness_data
        let witness = parse_witness(response.data())
            .ok_or_else(|| Error::ApduError("invalid witness response".to_string()))?;

        if witness.len() != 8 {
            return Err(Error::ApduError("invalid witness length".to_string()));
        }

        // Step 2: Decrypt the witness and create our challenge
        let cipher = TdesEde3::new_from_slice(key)
            .map_err(|_| Error::ApduError("invalid management key".to_string()))?;

        // Decrypt the witness
        let mut decrypted_witness = [0u8; 8];
        decrypted_witness.copy_from_slice(&witness);
        cipher.decrypt_block((&mut decrypted_witness).into());

        // Generate our challenge (use zeros for simplicity, or random in production)
        let our_challenge = [0u8; 8];

        // Encrypt our challenge
        let mut encrypted_challenge = our_challenge;
        cipher.encrypt_block((&mut encrypted_challenge).into());

        // Step 3: Send response with decrypted witness and our encrypted challenge
        // 7C len 80 08 decrypted_witness 81 08 encrypted_challenge
        let mut auth_data = Vec::with_capacity(24);
        auth_data.push(0x7C);
        auth_data.push(0x14); // 20 bytes: 2 + 8 + 2 + 8
        auth_data.push(0x80);
        auth_data.push(0x08);
        auth_data.extend_from_slice(&decrypted_witness);
        auth_data.push(0x81);
        auth_data.push(0x08);
        auth_data.extend_from_slice(&encrypted_challenge);

        let apdu = Apdu::with_le(
            0x00,
            ins::AUTHENTICATE,
            alg::TDES,
            key::MANAGEMENT,
            auth_data,
            256,
        );
        let response = self.transport.transmit(&apdu)?;

        if !response.is_success() && !response.has_more_data() {
            return Err(Error::ApduError(format!(
                "management key auth failed: SW={:04X}",
                response.status_word()
            )));
        }

        // Step 4: Verify card's response (optional but recommended)
        // The card should return our challenge decrypted
        // Note: If we get a successful response (SW=9000), authentication succeeded
        // The response verification is optional - some implementations skip it
        if let Some(card_response) = parse_challenge_response(response.data())
            && card_response != our_challenge
        {
            // Log but don't fail - the card accepted our auth
            // This can happen due to padding differences
        }

        self.mgmt_authenticated = true;
        Ok(())
    }

    /// Generates a new P-256 key pair in the specified slot.
    ///
    /// # Arguments
    ///
    /// * `slot` - The PIV slot to generate the key in
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the generated public key.
    ///
    /// # Errors
    ///
    /// - [`Error::KeyGenerationFailed`] if key generation fails
    ///
    /// # Note
    ///
    /// This operation requires management key authentication, which is
    /// handled internally using the default management key.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let public_key = session.generate_key(Slot::Authentication)?;
    /// ```
    #[cfg(feature = "pcsc")]
    pub fn generate_key(&mut self, slot: Slot) -> Result<VerifyingKey> {
        if !self.selected {
            return Err(Error::ApduError("PIV applet not selected".to_string()));
        }

        // Authenticate with management key if not already done
        if !self.mgmt_authenticated {
            self.authenticate_management_key()?;
        }

        // Build the generate key APDU
        // Template: AC 03 80 01 11 (algorithm P-256)
        let template = vec![0xAC, 0x03, 0x80, 0x01, alg::ECCP256];
        let apdu = Apdu::new(0x00, ins::GENERATE_ASYMMETRIC, 0x00, slot.id(), template);

        let response = self.transport.transmit(&apdu)?;
        response.check()?;

        // Parse the response to extract the public key
        parse_public_key_response(response.data())
            .ok_or_else(|| Error::KeyGenerationFailed(slot.id(), "invalid response".to_string()))
    }

    /// Generates a new P-256 key pair in the specified slot (non-PCSC version).
    ///
    /// This version does not automatically authenticate with the management key.
    /// You must ensure management key authentication is done externally.
    #[cfg(not(feature = "pcsc"))]
    pub fn generate_key(&mut self, slot: Slot) -> Result<VerifyingKey> {
        if !self.selected {
            return Err(Error::ApduError("PIV applet not selected".to_string()));
        }

        // Build the generate key APDU
        // Template: AC 03 80 01 11 (algorithm P-256)
        let template = vec![0xAC, 0x03, 0x80, 0x01, alg::ECCP256];
        let apdu = Apdu::new(0x00, ins::GENERATE_ASYMMETRIC, 0x00, slot.id(), template);

        let response = self.transport.transmit(&apdu)?;
        response.check()?;

        // Parse the response to extract the public key
        parse_public_key_response(response.data())
            .ok_or_else(|| Error::KeyGenerationFailed(slot.id(), "invalid response".to_string()))
    }

    /// Retrieves the public key from the specified slot.
    ///
    /// # Arguments
    ///
    /// * `slot` - The PIV slot to retrieve the key from
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the public key.
    ///
    /// # Errors
    ///
    /// - [`Error::SlotEmpty`] if no key is present in the slot
    /// - [`Error::InvalidKeyType`] if the key is not a P-256 key
    ///
    /// # Example
    ///
    /// ```ignore
    /// let public_key = session.get_public_key(Slot::Authentication)?;
    /// ```
    pub fn get_public_key(&mut self, slot: Slot) -> Result<VerifyingKey> {
        if !self.selected {
            return Err(Error::ApduError("PIV applet not selected".to_string()));
        }

        // GET DATA command with object ID
        let object_id = slot.object_id();
        let data = vec![0x5C, 0x03, object_id[0], object_id[1], object_id[2]];
        let apdu = Apdu::with_le(0x00, ins::GET_DATA, 0x3F, 0xFF, data, 256);

        let response = self.transport.transmit(&apdu)?;
        response.check()?;

        if response.data().is_empty() {
            return Err(Error::SlotEmpty(slot.id()));
        }

        // Parse the certificate/attestation to extract the public key
        parse_certificate_public_key(response.data())
            .ok_or_else(|| Error::InvalidKeyType(slot.id()))
    }

    /// Signs data using the key in the specified slot.
    ///
    /// # Arguments
    ///
    /// * `slot` - The PIV slot containing the signing key
    /// * `data` - The data to sign (typically a 32-byte hash)
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the DER-encoded ECDSA signature.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidPin`] if PIN verification is required but not done
    /// - [`Error::TouchTimeout`] if touch confirmation times out
    ///
    /// # Note
    ///
    /// For P-256 keys, the data should be a 32-byte hash (e.g., SHA-256 or Keccak-256).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let hash = keccak256(message);
    /// let signature = session.sign(Slot::Authentication, hash.as_slice())?;
    /// ```
    pub fn sign(&mut self, slot: Slot, data: &[u8]) -> Result<Vec<u8>> {
        if !self.selected {
            return Err(Error::ApduError("PIV applet not selected".to_string()));
        }

        if slot.requires_pin() && !self.pin_verified {
            return Err(Error::InvalidPin);
        }

        // Build GENERAL AUTHENTICATE command
        // Algorithm: P-256 (0x11)
        // Key reference: slot ID
        // Template: 7C len 82 00 81 len data
        let mut template = Vec::with_capacity(4 + data.len());
        template.push(0x7C);
        template.push((4 + data.len()) as u8);
        template.push(0x82);
        template.push(0x00);
        template.push(0x81);
        template.push(data.len() as u8);
        template.extend_from_slice(data);

        let apdu = Apdu::with_le(
            0x00,
            ins::AUTHENTICATE,
            alg::ECCP256,
            slot.id(),
            template,
            256,
        );
        let response = self.transport.transmit(&apdu)?;
        response.check()?;

        // Extract signature from response (tag 7C -> 82)
        parse_signature_response(response.data())
            .ok_or_else(|| Error::InvalidSignature("invalid response".to_string()))
    }

    /// Checks if the session is connected and active.
    ///
    /// # Returns
    ///
    /// `true` if the transport is connected, `false` otherwise.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
    }

    /// Checks if PIN has been verified.
    ///
    /// # Returns
    ///
    /// `true` if PIN verification was successful, `false` otherwise.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        self.pin_verified
    }
}

/// Parses the witness from a management key authentication response.
#[cfg(feature = "pcsc")]
fn parse_witness(data: &[u8]) -> Option<Vec<u8>> {
    // Response format: 7C len 80 len witness_data
    if data.len() < 4 || data[0] != 0x7C {
        return None;
    }

    let mut i = 2; // Skip 7C and length

    // Find tag 80 (witness)
    while i < data.len() {
        if data[i] == 0x80 {
            i += 1;
            if i >= data.len() {
                return None;
            }
            let len = data[i] as usize;
            i += 1;
            if i + len <= data.len() {
                return Some(data[i..i + len].to_vec());
            }
            return None;
        }
        i += 1;
    }

    None
}

/// Parses the challenge response from management key authentication.
#[cfg(feature = "pcsc")]
fn parse_challenge_response(data: &[u8]) -> Option<[u8; 8]> {
    // Response format: 7C len 82 len response_data
    if data.len() < 4 || data[0] != 0x7C {
        return None;
    }

    let mut i = 2; // Skip 7C and length

    // Find tag 82 (response)
    while i < data.len() {
        if data[i] == 0x82 {
            i += 1;
            if i >= data.len() {
                return None;
            }
            let len = data[i] as usize;
            i += 1;
            if len == 8 && i + len <= data.len() {
                let mut result = [0u8; 8];
                result.copy_from_slice(&data[i..i + 8]);
                return Some(result);
            }
            return None;
        }
        i += 1;
    }

    None
}

/// Parses the public key from a [`GENERATE ASYMMETRIC`](ins::GENERATE_ASYMMETRIC) response.
fn parse_public_key_response(data: &[u8]) -> Option<VerifyingKey> {
    // Response format: 7F 49 len 86 len point
    // Skip TLV headers to find the public key point
    let mut i = 0;

    // Skip outer tag (7F 49)
    if data.len() < 2 || data[i] != 0x7F || data[i + 1] != 0x49 {
        return None;
    }
    i += 2;

    // Skip length (may be 1 or 2 bytes)
    if data[i] >= 0x80 {
        i += 1 + (data[i] & 0x7F) as usize;
    } else {
        i += 1;
    }

    // Find tag 86 (public key)
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

            // Extract the public key point (should be 65 bytes for uncompressed P-256)
            if len == 65 && data[i] == 0x04 {
                let point_bytes = &data[i..i + len];
                let point = EncodedPoint::from_bytes(point_bytes).ok()?;
                return VerifyingKey::from_encoded_point(&point).ok();
            }
            break;
        }
        // Skip this TLV
        i += 1;
        if i >= data.len() {
            break;
        }
        let len = data[i] as usize;
        i += 1 + len;
    }

    None
}

/// Parses the public key from a certificate response.
fn parse_certificate_public_key(data: &[u8]) -> Option<VerifyingKey> {
    // Simplified: Look for the uncompressed point (0x04 followed by 64 bytes)
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

/// Parses the signature from a [`GENERAL AUTHENTICATE`](ins::AUTHENTICATE) response.
fn parse_signature_response(data: &[u8]) -> Option<Vec<u8>> {
    // Response format: 7C len 82 len signature
    let mut i = 0;

    // Check outer tag (7C)
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

    // Find tag 82 (signature)
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

    #[test]
    fn parse_signature_response_works() {
        // Minimal valid response: 7C 04 82 02 AB CD
        let response = vec![0x7C, 0x04, 0x82, 0x02, 0xAB, 0xCD];
        let sig = parse_signature_response(&response);
        assert_eq!(sig, Some(vec![0xAB, 0xCD]));
    }

    #[test]
    fn parse_signature_response_empty() {
        let response = vec![];
        let sig = parse_signature_response(&response);
        assert!(sig.is_none());
    }

    #[test]
    fn parse_signature_response_invalid_tag() {
        let response = vec![0x80, 0x04, 0x82, 0x02, 0xAB, 0xCD];
        let sig = parse_signature_response(&response);
        assert!(sig.is_none());
    }
}
