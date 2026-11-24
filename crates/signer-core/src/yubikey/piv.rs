//! PIV session management, sans-IO APDU helpers, and strict BER-TLV/X.509 parsing.
//!
//! This module provides both:
//!
//! - [`PivSession`]: stateful session manager over any [`Transport`]
//! - Reusable sans-IO APDU builders, management-key cryptography helpers, and
//!   strict response parsers that async transports (such as WebUSB in WASM) can
//!   call directly without duplicating PIV protocol logic.
//!
//! # Example
//!
//! ```ignore
//! use yubikey_evm_signer_core::yubikey::piv::ManagementKeyAlgorithm;
//! use yubikey_evm_signer_core::yubikey::{PivSession, Slot, Transport};
//!
//! let transport: Box<dyn Transport> = /* obtain transport */;
//! let mut session = PivSession::new(transport);
//!
//! // Select the PIV applet
//! session.select()?;
//!
//! // Authenticate management key and generate a key atomically; the slot's
//! // stale certificate is deleted in the same exclusive scope
//! let generated = session.exclusive(|piv| {
//!     piv.authenticate_management_key_with(&mgmt_key, ManagementKeyAlgorithm::Aes192)?;
//!     piv.generate_key(Slot::Authentication)
//! })?;
//! let public_key = generated.public_key;
//!
//! // Verify PIN and sign a 32-byte digest in one exclusive scope
//! let signature = session.verify_pin_and_sign("123456", Slot::Authentication, &hash)?;
//! ```

use std::fmt;
use std::io::Read;

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use des::TdesEde3;
use flate2::read::GzDecoder;
use p256::Sec1Point;
use p256::ecdsa::VerifyingKey;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::Transport;
use super::apdu::{Apdu, ApduResponse};
use super::slot::Slot;
use crate::error::{Error, Result};

/// The PIV applet AID (Application Identifier).
pub const PIV_AID: [u8; 9] = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

/// Maximum total bytes accepted across chained `GET RESPONSE` chunks (16 KiB).
const MAX_APDU_RESPONSE_BYTES: usize = 16 * 1024;

/// Maximum number of `GET RESPONSE` chaining iterations.
const MAX_RESPONSE_CHUNKS: usize = 128;

/// Maximum decompressed PIV certificate size (64 KiB) to guard against zip bombs.
const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;

/// DER OID bytes for `id-ecPublicKey` (`1.2.840.10045.2.1`).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// DER OID bytes for `secp256r1` / `prime256v1` (`1.2.840.10045.3.1.7`).
const OID_SECP256R1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

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

    /// `GET RESPONSE` instruction (ISO 7816-4 response chaining).
    pub(super) const GET_RESPONSE: u8 = 0xC0;

    /// `PUT DATA` instruction.
    pub(super) const PUT_DATA: u8 = 0xDB;

    /// Yubico `GET METADATA` instruction (firmware 5.3+).
    pub(super) const GET_METADATA: u8 = 0xF7;
}

/// Yubico `GET METADATA` response tags.
mod metadata_tag {
    /// Algorithm identifier (1 byte).
    pub(super) const ALGORITHM: u32 = 0x01;

    /// PIN and touch policy (2 bytes).
    pub(super) const POLICY: u32 = 0x02;

    /// Key origin (1 byte: `0x01` generated, `0x02` imported).
    pub(super) const ORIGIN: u32 = 0x03;

    /// Public key, itself TLV-encoded (tag `0x86` = uncompressed EC point).
    pub(super) const PUBLIC_KEY: u32 = 0x04;
}

/// PIV key references.
mod key {
    /// PIV Card Application Administration (management) key (`0x9B`).
    pub(super) const MANAGEMENT: u8 = 0x9B;
}

/// PIV algorithm identifiers.
mod alg {
    /// `ECCP256` (secp256r1/P-256).
    pub(super) const ECCP256: u8 = 0x11;
}

/// Supported YubiKey PIV management key algorithms (slot `9B`).
///
/// YubiKey firmware `< 5.7` defaults to [`Self::Tdes`] (24-byte Triple DES),
/// while firmware `>= 5.7` defaults to [`Self::Aes192`] (24-byte AES-192).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManagementKeyAlgorithm {
    /// Triple DES (3DES-EDE3, 24-byte key, 8-byte block, PIV algorithm `0x03`).
    Tdes,
    /// AES-128 (16-byte key, 16-byte block, PIV algorithm `0x08`).
    Aes128,
    /// AES-192 (24-byte key, 16-byte block, PIV algorithm `0x0A`).
    Aes192,
    /// AES-256 (32-byte key, 16-byte block, PIV algorithm `0x0C`).
    Aes256,
}

impl ManagementKeyAlgorithm {
    /// Returns the PIV algorithm identifier byte (`P1` in `GENERAL AUTHENTICATE`).
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Tdes => 0x03,
            Self::Aes128 => 0x08,
            Self::Aes192 => 0x0A,
            Self::Aes256 => 0x0C,
        }
    }

    /// Returns the required key length in bytes.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Tdes | Self::Aes192 => 24,
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }

    /// Returns the cipher block size in bytes (`8` for 3DES, `16` for AES).
    #[must_use]
    pub const fn block_size(self) -> usize {
        match self {
            Self::Tdes => 8,
            Self::Aes128 | Self::Aes192 | Self::Aes256 => 16,
        }
    }
}

// =============================================================================
// Sans-IO APDU Builders
// =============================================================================

/// Builds the `SELECT` APDU for the PIV applet.
#[must_use]
pub fn build_select_piv_apdu() -> Apdu {
    Apdu::new(0x00, ins::SELECT, 0x04, 0x00, PIV_AID.to_vec())
}

/// Builds the `VERIFY` APDU for PIV PIN authentication.
///
/// Enforces that `pin` is between 6 and 8 bytes inclusive so empty or malformed
/// PINs are rejected before burning a hardware retry counter, then pads to 8
/// bytes with `0xFF`.
///
/// # Errors
///
/// Returns [`Error::InvalidPin`] if `pin.len()` is outside `6..=8`.
pub fn build_verify_pin_apdu(pin: &str) -> Result<Apdu> {
    let pin_bytes = pin.as_bytes();
    if !(6..=8).contains(&pin_bytes.len()) {
        return Err(Error::InvalidPin {
            remaining_attempts: None,
        });
    }

    let mut padded_pin = [0xFFu8; 8];
    padded_pin[..pin_bytes.len()].copy_from_slice(pin_bytes);
    let apdu = Apdu::new(0x00, ins::VERIFY, 0x00, 0x80, padded_pin.to_vec());
    padded_pin.zeroize();
    Ok(apdu)
}

/// Builds a `GET RESPONSE` APDU for ISO 7816-4 `0x61 XX` response chaining.
///
/// A `sw2` value of `0x00` requests 256 bytes.
#[must_use]
pub fn build_get_response_apdu(sw2: u8) -> Apdu {
    let le = if sw2 == 0 { 256 } else { u32::from(sw2) };
    Apdu::with_le(0x00, ins::GET_RESPONSE, 0x00, 0x00, Vec::new(), le)
}

/// Builds a `GENERATE ASYMMETRIC KEY PAIR` APDU for P-256 in the given [`Slot`].
#[must_use]
pub fn build_generate_key_apdu(slot: Slot) -> Apdu {
    let template = vec![0xAC, 0x03, 0x80, 0x01, alg::ECCP256];
    Apdu::with_le(
        0x00,
        ins::GENERATE_ASYMMETRIC,
        0x00,
        slot.id(),
        template,
        256,
    )
}

/// Builds a `GET DATA` APDU to retrieve the X.509 certificate object for [`Slot`].
#[must_use]
pub fn build_get_certificate_apdu(slot: Slot) -> Apdu {
    let object_id = slot.object_id();
    let data = vec![0x5C, 0x03, object_id[0], object_id[1], object_id[2]];
    Apdu::with_le(0x00, ins::GET_DATA, 0x3F, 0xFF, data, 256)
}

/// Builds the Yubico `GET METADATA` APDU (`00 F7 00 <slot>`) for [`Slot`].
///
/// Supported on YubiKey firmware 5.3 and later; older firmware answers `0x6D00`
/// (instruction not supported). Parse a successful response with
/// [`parse_metadata_response`] and decide whether a failed one may fall back to
/// the certificate with [`metadata_status_allows_certificate_fallback`].
#[must_use]
pub const fn build_get_metadata_apdu(slot: Slot) -> Apdu {
    Apdu::with_le(0x00, ins::GET_METADATA, 0x00, slot.id(), Vec::new(), 256)
}

/// Builds a `PUT DATA` APDU (`00 DB 3F FF`) that deletes the X.509 certificate
/// object for [`Slot`] by writing an empty `0x53` data object.
///
/// Requires prior management key authentication on the card.
#[must_use]
pub fn build_delete_certificate_apdu(slot: Slot) -> Apdu {
    let object_id = slot.object_id();
    let data = vec![
        0x5C,
        0x03,
        object_id[0],
        object_id[1],
        object_id[2],
        0x53,
        0x00,
    ];
    Apdu::new(0x00, ins::PUT_DATA, 0x3F, 0xFF, data)
}

/// Builds a `GENERAL AUTHENTICATE` signing APDU for a 32-byte digest using P-256.
#[must_use]
pub fn build_sign_apdu(slot: Slot, hash: &[u8; 32]) -> Apdu {
    // Template: 7C 24 82 00 81 20 <32-byte hash>
    let mut template = Vec::with_capacity(6 + 32);
    template.push(0x7C);
    template.push(0x24); // 4 + 32 = 36 bytes
    template.push(0x82);
    template.push(0x00);
    template.push(0x81);
    template.push(0x20); // 32 bytes
    template.extend_from_slice(hash);

    Apdu::with_le(
        0x00,
        ins::AUTHENTICATE,
        alg::ECCP256,
        slot.id(),
        template,
        256,
    )
}

/// Builds step 1 of PIV mutual management key authentication: request an encrypted witness.
#[must_use]
pub fn build_mgmt_auth_request_witness_apdu(alg: ManagementKeyAlgorithm) -> Apdu {
    Apdu::with_le(
        0x00,
        ins::AUTHENTICATE,
        alg.id(),
        key::MANAGEMENT,
        vec![0x7C, 0x02, 0x80, 0x00],
        256,
    )
}

/// Builds step 2 of PIV mutual management key authentication.
///
/// Sends the decrypted card witness in tag `0x80` and a fresh **plaintext** host
/// challenge in tag `0x81` (per NIST SP 800-73-4 / YubiKey PIV mutual auth).
///
/// # Errors
///
/// Returns [`Error::ApduError`] if `decrypted_witness` or `host_challenge` does not
/// match `alg.block_size()`.
pub fn build_mgmt_auth_verify_apdu(
    alg: ManagementKeyAlgorithm,
    decrypted_witness: &[u8],
    host_challenge: &[u8],
) -> Result<Apdu> {
    let block_size = alg.block_size();
    if decrypted_witness.len() != block_size || host_challenge.len() != block_size {
        return Err(Error::ApduError(format!(
            "management auth witness and challenge must be {block_size} bytes for {alg:?}"
        )));
    }

    let inner_len = 2 + block_size + 2 + block_size;
    let mut auth_data = Vec::with_capacity(2 + inner_len);
    auth_data.push(0x7C);
    auth_data.push(inner_len as u8);
    auth_data.push(0x80);
    auth_data.push(block_size as u8);
    auth_data.extend_from_slice(decrypted_witness);
    auth_data.push(0x81);
    auth_data.push(block_size as u8);
    auth_data.extend_from_slice(host_challenge);

    Ok(Apdu::with_le(
        0x00,
        ins::AUTHENTICATE,
        alg.id(),
        key::MANAGEMENT,
        auth_data,
        256,
    ))
}

// =============================================================================
// Management Key Cryptography Helpers
// =============================================================================

/// Decrypts the card's encrypted witness block using the specified management key algorithm.
///
/// # Errors
///
/// Returns [`Error::AuthenticationFailed`] if the key length or witness block length is invalid.
pub fn decrypt_mgmt_witness(
    alg: ManagementKeyAlgorithm,
    key: &[u8],
    witness: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != alg.key_len() || witness.len() != alg.block_size() {
        return Err(Error::AuthenticationFailed);
    }

    let mut block = witness.to_vec();
    match alg {
        ManagementKeyAlgorithm::Tdes => {
            let cipher = TdesEde3::new_from_slice(key).map_err(|_| Error::AuthenticationFailed)?;
            cipher.decrypt_block(block.as_mut_slice().into());
        }
        ManagementKeyAlgorithm::Aes128 => {
            let cipher = Aes128::new_from_slice(key).map_err(|_| Error::AuthenticationFailed)?;
            cipher.decrypt_block(block.as_mut_slice().into());
        }
        ManagementKeyAlgorithm::Aes192 => {
            let cipher = Aes192::new_from_slice(key).map_err(|_| Error::AuthenticationFailed)?;
            cipher.decrypt_block(block.as_mut_slice().into());
        }
        ManagementKeyAlgorithm::Aes256 => {
            let cipher = Aes256::new_from_slice(key).map_err(|_| Error::AuthenticationFailed)?;
            cipher.decrypt_block(block.as_mut_slice().into());
        }
    }

    Ok(block)
}

/// Encrypts the host's plaintext challenge block to compute the expected card response.
///
/// # Errors
///
/// Returns [`Error::AuthenticationFailed`] if the key length or challenge block length is invalid.
pub fn encrypt_mgmt_challenge(
    alg: ManagementKeyAlgorithm,
    key: &[u8],
    challenge: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != alg.key_len() || challenge.len() != alg.block_size() {
        return Err(Error::AuthenticationFailed);
    }

    let mut block = challenge.to_vec();
    match alg {
        ManagementKeyAlgorithm::Tdes => {
            let cipher = TdesEde3::new_from_slice(key).map_err(|_| Error::AuthenticationFailed)?;
            cipher.encrypt_block(block.as_mut_slice().into());
        }
        ManagementKeyAlgorithm::Aes128 => {
            let cipher = Aes128::new_from_slice(key).map_err(|_| Error::AuthenticationFailed)?;
            cipher.encrypt_block(block.as_mut_slice().into());
        }
        ManagementKeyAlgorithm::Aes192 => {
            let cipher = Aes192::new_from_slice(key).map_err(|_| Error::AuthenticationFailed)?;
            cipher.encrypt_block(block.as_mut_slice().into());
        }
        ManagementKeyAlgorithm::Aes256 => {
            let cipher = Aes256::new_from_slice(key).map_err(|_| Error::AuthenticationFailed)?;
            cipher.encrypt_block(block.as_mut_slice().into());
        }
    }

    Ok(block)
}

/// Compares the expected encrypted challenge against the card's response in constant time.
#[must_use]
pub fn verify_mgmt_challenge_response(expected: &[u8], actual: &[u8]) -> bool {
    bool::from(expected.ct_eq(actual))
}

// =============================================================================
// Strict BER-TLV & X.509 Response Parsers
// =============================================================================

/// Parses a BER-TLV tag (1 to 4 bytes) and returns `(tag, bytes_consumed)`.
fn parse_ber_tag(data: &[u8]) -> Option<(u32, usize)> {
    let first = *data.first()?;
    if (first & 0x1F) != 0x1F {
        return Some((u32::from(first), 1));
    }

    // Multi-byte tag (e.g., 0x7F 0x49)
    let mut tag = u32::from(first);
    let mut idx = 1usize;
    loop {
        if idx >= 4 {
            return None;
        }
        let next = *data.get(idx)?;
        tag = (tag << 8) | u32::from(next);
        idx += 1;
        if (next & 0x80) == 0 {
            return Some((tag, idx));
        }
    }
}

/// Parses a canonical DER length and returns `(value_len, bytes_consumed)`.
///
/// Rejects indefinite lengths, lengths exceeding 4 bytes, non-canonical leading
/// zero length bytes, and long-form encodings of lengths `< 0x80`.
fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first < 0x80 {
        return Some((usize::from(first), 1));
    }

    let len_bytes = usize::from(first & 0x7F);
    if len_bytes == 0 || len_bytes > 4 || len_bytes > core::mem::size_of::<usize>() {
        return None;
    }

    let bytes = data.get(1..1 + len_bytes)?;
    // Canonical DER: first length byte must not be 0x00
    if bytes[0] == 0 {
        return None;
    }

    let mut len = 0usize;
    for &b in bytes {
        len = len.checked_shl(8)? | usize::from(b);
    }

    // Canonical DER: long form must not be used for lengths < 0x80
    if len < 0x80 {
        return None;
    }

    Some((len, 1 + len_bytes))
}

/// Parses a single BER-TLV element, returning `(tag, value_slice, remaining_slice)`.
fn parse_tlv(data: &[u8]) -> Option<(u32, &[u8], &[u8])> {
    let (tag, tag_len) = parse_ber_tag(data)?;
    let (val_len, len_len) = parse_der_length(data.get(tag_len..)?)?;
    let val_start = tag_len.checked_add(len_len)?;
    let val_end = val_start.checked_add(val_len)?;
    let value = data.get(val_start..val_end)?;
    let rest = data.get(val_end..)?;
    Some((tag, value, rest))
}

/// Iterates sibling TLVs inside a constructed TLV body to find `target_tag`.
fn find_tlv_child(mut body: &[u8], target_tag: u32) -> Option<&[u8]> {
    while !body.is_empty() {
        let (tag, value, rest) = parse_tlv(body)?;
        if tag == target_tag {
            return Some(value);
        }
        body = rest;
    }
    None
}

/// Parses the encrypted witness from a management key auth step-1 response (`7C -> 80`).
#[must_use]
pub fn parse_witness_response(data: &[u8], expected_block_len: usize) -> Option<Vec<u8>> {
    let (outer_tag, outer_val, rest) = parse_tlv(data)?;
    if outer_tag != 0x7C || !rest.is_empty() {
        return None;
    }
    let witness = find_tlv_child(outer_val, 0x80)?;
    if witness.len() != expected_block_len {
        return None;
    }
    Some(witness.to_vec())
}

/// Parses the card's encrypted challenge response from management key auth step 2 (`7C -> 82`).
#[must_use]
pub fn parse_challenge_response(data: &[u8], expected_block_len: usize) -> Option<Vec<u8>> {
    let (outer_tag, outer_val, rest) = parse_tlv(data)?;
    if outer_tag != 0x7C || !rest.is_empty() {
        return None;
    }
    let response = find_tlv_child(outer_val, 0x82)?;
    if response.len() != expected_block_len {
        return None;
    }
    Some(response.to_vec())
}

/// Parses a P-256 [`VerifyingKey`] from a `GENERATE ASYMMETRIC` response (`7F49 -> 86`).
#[must_use]
pub fn parse_public_key_response(data: &[u8]) -> Option<VerifyingKey> {
    let (outer_tag, outer_val, rest) = parse_tlv(data)?;
    if outer_tag != 0x7F49 || !rest.is_empty() {
        return None;
    }

    let point_bytes = find_tlv_child(outer_val, 0x86)?;
    if point_bytes.len() != 65 || point_bytes[0] != 0x04 {
        return None;
    }

    let point = Sec1Point::from_bytes(point_bytes).ok()?;
    VerifyingKey::from_sec1_point(&point).ok()
}

/// Slot metadata returned by the Yubico `GET METADATA` instruction (firmware 5.3+).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotMetadata {
    /// PIV algorithm identifier of the key in the slot (`0x11` = ECC P-256).
    pub algorithm: u8,

    /// `[pin_policy, touch_policy]`, if reported.
    pub policy: Option<[u8; 2]>,

    /// Key origin (`0x01` generated on the device, `0x02` imported), if reported.
    pub origin: Option<u8>,

    /// The slot's P-256 public key.
    ///
    /// `Some` exactly when [`Self::algorithm`] is P-256 (`0x11`); keys of other
    /// algorithms are not decoded.
    pub public_key: Option<VerifyingKey>,
}

impl SlotMetadata {
    /// Returns `true` if the slot holds a P-256 key.
    #[must_use]
    pub const fn is_p256(&self) -> bool {
        self.algorithm == alg::ECCP256
    }
}

/// Parses a Yubico `GET METADATA` response body (status word removed).
///
/// The body is a flat TLV list: `01` algorithm, `02` `[pin, touch]` policy, `03`
/// origin, `04` public key (for EC keys a nested TLV whose tag `0x86` holds the
/// uncompressed point). Unknown tags are ignored.
///
/// # Returns
///
/// `None` if the TLV list is malformed, a known tag is repeated or has the wrong
/// length, the algorithm tag is missing, or the algorithm is P-256 but the public
/// key is missing or is not a valid uncompressed P-256 point.
#[must_use]
pub fn parse_metadata_response(data: &[u8]) -> Option<SlotMetadata> {
    let mut algorithm: Option<u8> = None;
    let mut policy: Option<[u8; 2]> = None;
    let mut origin: Option<u8> = None;
    let mut public_key_tlv: Option<&[u8]> = None;

    let mut rest = data;
    while !rest.is_empty() {
        let (tag, value, remaining) = parse_tlv(rest)?;
        match tag {
            metadata_tag::ALGORITHM => {
                if algorithm.is_some() || value.len() != 1 {
                    return None;
                }
                algorithm = Some(value[0]);
            }
            metadata_tag::POLICY => {
                if policy.is_some() || value.len() != 2 {
                    return None;
                }
                policy = Some([value[0], value[1]]);
            }
            metadata_tag::ORIGIN => {
                if origin.is_some() || value.len() != 1 {
                    return None;
                }
                origin = Some(value[0]);
            }
            metadata_tag::PUBLIC_KEY => {
                if public_key_tlv.is_some() {
                    return None;
                }
                public_key_tlv = Some(value);
            }
            _ => {}
        }
        rest = remaining;
    }

    let algorithm = algorithm?;
    let public_key = if algorithm == alg::ECCP256 {
        let (point_tag, point_bytes, trailing) = parse_tlv(public_key_tlv?)?;
        if point_tag != 0x86
            || !trailing.is_empty()
            || point_bytes.len() != 65
            || point_bytes[0] != 0x04
        {
            return None;
        }
        let point = Sec1Point::from_bytes(point_bytes).ok()?;
        Some(VerifyingKey::from_sec1_point(&point).ok()?)
    } else {
        None
    };

    Some(SlotMetadata {
        algorithm,
        policy,
        origin,
        public_key,
    })
}

/// Decides whether a non-success `GET METADATA` status word means "metadata
/// unavailable", so a caller may fall back to reading the slot's certificate.
///
/// - `0x9000`: metadata is available; use it (returns `false`).
/// - `0x6A82` (referenced data not found): the card supports `GET METADATA` and
///   reports that the slot holds **no key**. This is authoritative: falling back
///   to a certificate would return a stale key, so callers must report the slot
///   as empty (returns `false`).
/// - Anything else (notably `0x6D00`, instruction not supported on firmware
///   older than 5.3): metadata is unavailable; fall back (returns `true`).
#[must_use]
pub const fn metadata_status_allows_certificate_fallback(sw1: u8, sw2: u8) -> bool {
    !matches!((sw1, sw2), (0x90, 0x00) | (0x6A, 0x82))
}

/// Parses the ASN.1 DER ECDSA signature from a `GENERAL AUTHENTICATE` response (`7C -> 82`).
#[must_use]
pub fn parse_signature_response(data: &[u8]) -> Option<Vec<u8>> {
    let (outer_tag, outer_val, rest) = parse_tlv(data)?;
    if outer_tag != 0x7C || !rest.is_empty() {
        return None;
    }

    let sig = find_tlv_child(outer_val, 0x82)?;
    if sig.is_empty() {
        return None;
    }
    Some(sig.to_vec())
}

/// Parses a P-256 [`VerifyingKey`] from a PIV `GET DATA` certificate container (`53 -> 70 / 71`).
///
/// Handles optional gzip compression signaled by PIV CertInfo tag `0x71` (bit 0)
/// with a strict 64 KiB decompressed size cap, then parses the X.509 DER
/// `Certificate -> tbsCertificate -> subjectPublicKeyInfo` and verifies that the
/// algorithm OID is `id-ecPublicKey` (`1.2.840.10045.2.1`) and curve parameter
/// OID is `secp256r1` (`1.2.840.10045.3.1.7`).
#[must_use]
pub fn parse_certificate_public_key(data: &[u8]) -> Option<VerifyingKey> {
    // 1. Parse PIV data object wrapper (tag 0x53)
    let (outer_tag, mut container, rest) = parse_tlv(data)?;
    if outer_tag != 0x53 || !rest.is_empty() {
        return None;
    }

    let mut cert_bytes: Option<&[u8]> = None;
    let mut cert_info: u8 = 0;

    while !container.is_empty() {
        let (tag, value, remaining) = parse_tlv(container)?;
        match tag {
            0x70 => cert_bytes = Some(value),
            0x71 => {
                if value.len() != 1 {
                    return None;
                }
                cert_info = value[0];
            }
            _ => {}
        }
        container = remaining;
    }

    let raw_cert = cert_bytes?;
    if raw_cert.is_empty() {
        return None;
    }

    // 2. Decompress if CertInfo bit 0 (gzip) is set, enforcing strict size cap
    let decompressed;
    let der_cert: &[u8] = if (cert_info & 0x01) != 0 {
        let mut decoder = GzDecoder::new(raw_cert).take((MAX_CERTIFICATE_BYTES as u64) + 1);
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf).ok()?;
        if buf.len() > MAX_CERTIFICATE_BYTES {
            return None;
        }
        decompressed = buf;
        &decompressed
    } else {
        if raw_cert.len() > MAX_CERTIFICATE_BYTES {
            return None;
        }
        raw_cert
    };

    // 3. Parse X.509 Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (cert_tag, cert_body, cert_rest) = parse_tlv(der_cert)?;
    if cert_tag != 0x30 || !cert_rest.is_empty() {
        return None;
    }

    // tbsCertificate ::= SEQUENCE
    let (tbs_tag, mut tbs_body, _) = parse_tlv(cert_body)?;
    if tbs_tag != 0x30 {
        return None;
    }

    // Optional [0] EXPLICIT version (tag 0xA0)
    let (first_tag, _, after_first) = parse_tlv(tbs_body)?;
    if first_tag == 0xA0 {
        tbs_body = after_first;
    }

    // serialNumber ::= INTEGER (0x02)
    let (serial_tag, _, rest) = parse_tlv(tbs_body)?;
    if serial_tag != 0x02 {
        return None;
    }
    // signature ::= AlgorithmIdentifier SEQUENCE (0x30)
    let (sig_alg_tag, _, rest) = parse_tlv(rest)?;
    if sig_alg_tag != 0x30 {
        return None;
    }
    // issuer ::= Name SEQUENCE (0x30)
    let (issuer_tag, _, rest) = parse_tlv(rest)?;
    if issuer_tag != 0x30 {
        return None;
    }
    // validity ::= Validity SEQUENCE (0x30)
    let (validity_tag, _, rest) = parse_tlv(rest)?;
    if validity_tag != 0x30 {
        return None;
    }
    // subject ::= Name SEQUENCE (0x30)
    let (subject_tag, _, rest) = parse_tlv(rest)?;
    if subject_tag != 0x30 {
        return None;
    }
    // subjectPublicKeyInfo ::= SEQUENCE (0x30)
    let (spki_tag, spki_body, _) = parse_tlv(rest)?;
    if spki_tag != 0x30 {
        return None;
    }

    // algorithm ::= AlgorithmIdentifier SEQUENCE (0x30)
    let (alg_tag, alg_body, spki_rest) = parse_tlv(spki_body)?;
    if alg_tag != 0x30 {
        return None;
    }
    let (oid_tag, alg_oid, alg_rest) = parse_tlv(alg_body)?;
    if oid_tag != 0x06 || alg_oid != OID_EC_PUBLIC_KEY {
        return None;
    }
    let (param_tag, param_oid, alg_trailing) = parse_tlv(alg_rest)?;
    if param_tag != 0x06 || param_oid != OID_SECP256R1 || !alg_trailing.is_empty() {
        return None;
    }

    // subjectPublicKey ::= BIT STRING (0x03)
    let (pk_tag, pk_bits, spki_trailing) = parse_tlv(spki_rest)?;
    if pk_tag != 0x03 || !spki_trailing.is_empty() {
        return None;
    }
    // First byte of BIT STRING is number of unused bits (must be 0)
    if pk_bits.len() < 2 || pk_bits[0] != 0x00 {
        return None;
    }

    let point_bytes = &pk_bits[1..];
    if point_bytes.len() != 65 && point_bytes.len() != 33 {
        return None;
    }

    let point = Sec1Point::from_bytes(point_bytes).ok()?;
    VerifyingKey::from_sec1_point(&point).ok()
}

// =============================================================================
// Full Exchange (6Cxx retry + 61xx chaining)
// =============================================================================

/// Builds a status-word-only response (data discarded) from `response`.
fn status_only(response: &ApduResponse) -> ApduResponse {
    ApduResponse::new(vec![response.sw1(), response.sw2()])
}

/// Exchanges `apdu` on `transport`, handling one `0x6C XX` (wrong `Le`) retry and
/// `0x61 XX` `GET RESPONSE` chaining (each `GET RESPONSE` requests `Le = XX`,
/// `0x00` meaning 256, and is itself retried once on `0x6C XX`).
///
/// Returns the concatenated response data with a `0x9000` status word, or a
/// status-word-only response carrying the first non-success, non-`0x61` status
/// word. Status words are never converted into errors here.
///
/// This does not open an exclusive scope itself; callers run it inside one.
fn exchange_full(transport: &mut dyn Transport, apdu: &Apdu) -> Result<ApduResponse> {
    let mut response = transport.transmit(apdu)?;

    // Handle SW1 == 0x6C (wrong Le): retry once with the card's requested Le
    if let Some(correct_le) = response.wrong_le() {
        let mut retry_apdu = apdu.with_le_override(Some(u32::from(correct_le)));
        let retry_result = transport.transmit(&retry_apdu);
        retry_apdu.zeroize_data();
        response = retry_result?;
    }

    if !response.is_success() && !response.has_more_data() {
        return Ok(status_only(&response));
    }

    let mut remaining = response.remaining_bytes();
    let mut data = response.into_data();
    if data.len() > MAX_APDU_RESPONSE_BYTES {
        return Err(Error::MalformedResponse(
            "APDU response exceeded maximum allowed size".to_string(),
        ));
    }

    let mut chunks = 0usize;
    while let Some(sw2) = remaining {
        chunks += 1;
        if chunks > MAX_RESPONSE_CHUNKS {
            return Err(Error::MalformedResponse(
                "APDU response exceeded maximum GET RESPONSE chunk limit".to_string(),
            ));
        }

        let get_resp = build_get_response_apdu(sw2);
        let mut chunk_resp = transport.transmit(&get_resp)?;

        if let Some(correct_le) = chunk_resp.wrong_le() {
            let retry = get_resp.with_le_override(Some(u32::from(correct_le)));
            chunk_resp = transport.transmit(&retry)?;
        }

        if !chunk_resp.is_success() && !chunk_resp.has_more_data() {
            return Ok(status_only(&chunk_resp));
        }

        remaining = chunk_resp.remaining_bytes();
        let chunk = chunk_resp.into_data();
        if data.len().saturating_add(chunk.len()) > MAX_APDU_RESPONSE_BYTES {
            return Err(Error::MalformedResponse(
                "chained APDU response exceeded maximum allowed size".to_string(),
            ));
        }
        data.extend_from_slice(&chunk);
    }

    data.extend_from_slice(&[0x90, 0x00]);
    ApduResponse::try_from_bytes(data)
}

/// Exchanges one APDU together with its `0x6C XX` retry and `0x61 XX`
/// `GET RESPONSE` continuation as **one exclusive scope** on `transport`
/// (see [`Transport::exclusive`]).
///
/// Intended for relays such as the local PC/SC bridge that forward one command at
/// a time but must not let another PC/SC client interleave APDUs inside a chain.
///
/// # Arguments
///
/// * `transport` - The transport to exchange on
/// * `apdu` - The command APDU
///
/// # Returns
///
/// One [`ApduResponse`]: on success, the concatenated data of every chunk with
/// status word `0x9000`; otherwise an empty response carrying the first
/// non-success status word (for example `0x6982`), which is **not** converted
/// into an error.
///
/// # Errors
///
/// Returns transport errors (including [`Error::CardReset`] and
/// [`Error::DeviceDisconnected`]) and [`Error::MalformedResponse`] if the chained
/// response exceeds the size or chunk limits.
pub fn transmit_chained(transport: &mut dyn Transport, apdu: &Apdu) -> Result<ApduResponse> {
    let mut output: Option<ApduResponse> = None;
    transport.exclusive(&mut |scoped| {
        output = Some(exchange_full(scoped, apdu)?);
        Ok(())
    })?;
    output.ok_or_else(scope_not_run)
}

/// Error returned when a [`Transport::exclusive`] implementation never ran its closure.
fn scope_not_run() -> Error {
    Error::ApduError("transport did not run the exclusive scope".to_string())
}

// =============================================================================
// PivSession
// =============================================================================

/// Where a slot's public key was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeySource {
    /// The Yubico `GET METADATA` response (authoritative for the key in the slot).
    Metadata,

    /// The X.509 certificate stored for the slot (used only when metadata is
    /// unavailable, e.g. firmware older than 5.3).
    Certificate,
}

/// A slot's P-256 public key and how it was obtained.
#[derive(Debug, Clone)]
pub struct SlotPublicKey {
    /// The public key of the private key currently in the slot.
    pub public_key: VerifyingKey,

    /// Where [`Self::public_key`] was read from.
    pub source: PublicKeySource,

    /// `true` if the slot also holds a certificate whose public key differs from
    /// (or could not be decoded and compared with) the metadata key.
    ///
    /// Such a certificate is stale (left over from a previous key) and must not
    /// be used to identify the slot's key. Always `false` when
    /// [`Self::source`] is [`PublicKeySource::Certificate`].
    pub stale_certificate: bool,
}

/// A newly generated key and the outcome of removing the slot's old certificate.
#[derive(Debug)]
pub struct GeneratedKey {
    /// The public key of the newly generated P-256 private key.
    pub public_key: VerifyingKey,

    /// `None` if the slot's certificate object was deleted (or none existed);
    /// otherwise the error that prevented deleting it.
    ///
    /// The generated key is valid either way, but a certificate that could not
    /// be deleted still describes the **previous** key and should be removed or
    /// replaced before relying on it.
    pub certificate_delete_error: Option<Error>,
}

/// Per-session PIV state tracked by the host.
#[derive(Debug, Clone, Copy, Default)]
struct SessionState {
    /// Whether the applet has been selected.
    selected: bool,

    /// Whether PIN has been verified.
    pin_verified: bool,

    /// Whether management key has been authenticated.
    mgmt_authenticated: bool,
}

impl SessionState {
    /// Forgets all card-side state (applet selection, PIN, management key).
    fn clear(&mut self) {
        *self = Self::default();
    }
}

/// A session with the YubiKey PIV applet.
///
/// This type manages the connection to a YubiKey's PIV applet and provides
/// methods for key management, mutual authentication, and signing operations.
///
/// Every method runs as one exclusive scope on the transport (see
/// [`Transport::exclusive`]). To make a sequence of operations atomic with
/// respect to other PC/SC clients (for example `SELECT` → `VERIFY` →
/// `GENERAL AUTHENTICATE`), run it inside [`Self::exclusive`].
///
/// Any transport-level failure (including [`Error::CardReset`] and
/// [`Error::DeviceDisconnected`]) clears the session's selection, PIN, and
/// management key state; call [`Self::select`] again to recover. Status-word
/// errors reported by the card do not clear the state.
pub struct PivSession {
    /// The underlying transport.
    transport: Box<dyn Transport>,

    /// Host-side view of the card's PIV state.
    state: SessionState,
}

impl fmt::Debug for PivSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PivSession")
            .field("selected", &self.state.selected)
            .field("pin_verified", &self.state.pin_verified)
            .field("mgmt_authenticated", &self.state.mgmt_authenticated)
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
            state: SessionState::default(),
        }
    }

    /// Runs `f` as one exclusive scope on the transport.
    ///
    /// No other PC/SC client can send APDUs to the card while `f` runs, so a
    /// sequence such as select → verify PIN → sign, or select → management key
    /// authentication → generate, is atomic. Do not wait for user input inside
    /// `f` (prompt for PINs and keys before calling this).
    ///
    /// # Arguments
    ///
    /// * `f` - The operations to run, given a [`PivExclusive`] view of this session
    ///
    /// # Returns
    ///
    /// The result of `f`.
    ///
    /// # Errors
    ///
    /// Returns the error from `f`, or a transport error if the exclusive scope
    /// could not be started (in which case the session state is cleared).
    pub fn exclusive<T>(
        &mut self,
        f: impl FnOnce(&mut PivExclusive<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut f = Some(f);
        let mut output: Option<Result<T>> = None;
        let state = &mut self.state;

        let scope_result = self.transport.exclusive(&mut |transport| {
            if let Some(f) = f.take() {
                let mut piv = PivExclusive {
                    transport,
                    state: &mut *state,
                };
                output = Some(f(&mut piv));
            }
            Ok(())
        });

        if let Err(e) = scope_result {
            self.state.clear();
            return Err(e);
        }
        output.unwrap_or_else(|| Err(scope_not_run()))
    }

    /// Transmits an APDU, handling `0x6C XX` (wrong `Le`) retries and `0x61 XX`
    /// (`GET RESPONSE`) response chaining, as one exclusive scope.
    ///
    /// # Errors
    ///
    /// Returns transport, APDU status-word, or malformed-response errors.
    pub fn transmit_full(&mut self, apdu: &Apdu) -> Result<Vec<u8>> {
        self.exclusive(|piv| piv.transmit_full(apdu))
    }

    /// Selects the PIV applet on the YubiKey.
    ///
    /// This must be called before any other PIV operations, and again after
    /// [`Error::CardReset`] or any other transport failure.
    ///
    /// # Errors
    ///
    /// Returns an error if communication fails or the applet is not present.
    pub fn select(&mut self) -> Result<()> {
        self.exclusive(|piv| piv.select())
    }

    /// Verifies the user's PIN.
    ///
    /// See [`PivExclusive::verify_pin`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidPin`] if the PIN length is outside `6..=8` or the card rejects it
    /// - [`Error::PinLocked`] if the PIN has been locked after too many attempts
    pub fn verify_pin(&mut self, pin: &str) -> Result<()> {
        self.exclusive(|piv| piv.verify_pin(pin))
    }

    /// Performs mutual management key authentication (both steps in one exclusive scope).
    ///
    /// See [`PivExclusive::authenticate_management_key_with`].
    ///
    /// # Errors
    ///
    /// - [`Error::AuthenticationFailed`] if the key length is wrong, the card rejects
    ///   our witness, or the card's challenge response fails constant-time verification
    /// - [`Error::MalformedResponse`] if the card returns malformed TLV data
    pub fn authenticate_management_key_with(
        &mut self,
        key: &[u8],
        alg: ManagementKeyAlgorithm,
    ) -> Result<()> {
        self.exclusive(|piv| piv.authenticate_management_key_with(key, alg))
    }

    /// Generates a new P-256 key pair in `slot` and deletes the slot's stale
    /// certificate, in one exclusive scope.
    ///
    /// See [`PivExclusive::generate_key`].
    ///
    /// # Errors
    ///
    /// - [`Error::SecurityStatusNotSatisfied`] if management key is not authenticated
    /// - [`Error::KeyGenerationFailed`] if response parsing fails
    pub fn generate_key(&mut self, slot: Slot) -> Result<GeneratedKey> {
        self.exclusive(|piv| piv.generate_key(slot))
    }

    /// Retrieves the P-256 public key of the private key in `slot`.
    ///
    /// See [`PivExclusive::get_slot_public_key`]; this returns only the key.
    ///
    /// # Errors
    ///
    /// See [`PivExclusive::get_slot_public_key`].
    pub fn get_public_key(&mut self, slot: Slot) -> Result<VerifyingKey> {
        self.exclusive(|piv| piv.get_public_key(slot))
    }

    /// Retrieves the P-256 public key of the private key in `slot`, with its source.
    ///
    /// See [`PivExclusive::get_slot_public_key`].
    ///
    /// # Errors
    ///
    /// See [`PivExclusive::get_slot_public_key`].
    pub fn get_slot_public_key(&mut self, slot: Slot) -> Result<SlotPublicKey> {
        self.exclusive(|piv| piv.get_slot_public_key(slot))
    }

    /// Signs a 32-byte digest using the P-256 key in the specified slot.
    ///
    /// See [`PivExclusive::sign`].
    ///
    /// # Errors
    ///
    /// See [`PivExclusive::sign`].
    pub fn sign(&mut self, slot: Slot, data: &[u8]) -> Result<Vec<u8>> {
        self.exclusive(|piv| piv.sign(slot, data))
    }

    /// Verifies the PIN and signs a 32-byte digest in one exclusive scope.
    ///
    /// See [`PivExclusive::verify_pin_and_sign`].
    ///
    /// # Errors
    ///
    /// See [`PivExclusive::verify_pin_and_sign`].
    pub fn verify_pin_and_sign(&mut self, pin: &str, slot: Slot, data: &[u8]) -> Result<Vec<u8>> {
        self.exclusive(|piv| piv.verify_pin_and_sign(pin, slot, data))
    }

    /// Checks if the underlying transport is connected.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
    }

    /// Checks if the PIV applet is selected in this session.
    #[must_use]
    pub const fn is_selected(&self) -> bool {
        self.state.selected
    }

    /// Checks if the user's PIN has been verified in this session.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        self.state.pin_verified
    }

    /// Checks if the management key has been authenticated in this session.
    #[must_use]
    pub const fn is_mgmt_authenticated(&self) -> bool {
        self.state.mgmt_authenticated
    }
}

/// A [`PivSession`] borrowed for the duration of one exclusive transport scope.
///
/// Obtained from [`PivSession::exclusive`]. Every APDU sent through it is part
/// of the same exclusive scope, so no other PC/SC client can interleave
/// commands between its method calls.
pub struct PivExclusive<'a> {
    /// The transport inside the exclusive scope.
    transport: &'a mut dyn Transport,

    /// The owning session's state.
    state: &'a mut SessionState,
}

impl fmt::Debug for PivExclusive<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PivExclusive")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl PivExclusive<'_> {
    /// Transmits one APDU, clearing the session state on any transport failure.
    fn transmit_raw(&mut self, apdu: &Apdu) -> Result<ApduResponse> {
        let result = self.transport.transmit(apdu);
        if result.is_err() {
            self.state.clear();
        }
        result
    }

    /// Runs [`exchange_full`], clearing the session state on any transport failure.
    fn exchange(&mut self, apdu: &Apdu) -> Result<ApduResponse> {
        let result = exchange_full(&mut *self.transport, apdu);
        if result.is_err() {
            self.state.clear();
        }
        result
    }

    /// Full exchange with optional slot-aware status-word mapping.
    fn transmit_full_inner(&mut self, apdu: &Apdu, slot: Option<Slot>) -> Result<Vec<u8>> {
        let response = self.exchange(apdu)?;
        match slot {
            Some(s) => response.check_for_slot(s)?,
            None => response.check()?,
        }
        Ok(response.into_data())
    }

    /// Returns an error unless the PIV applet has been selected.
    fn require_selected(&self) -> Result<()> {
        if self.state.selected {
            Ok(())
        } else {
            Err(Error::ApduError("PIV applet not selected".to_string()))
        }
    }

    /// Transmits an APDU, handling `0x6C XX` (wrong `Le`) retries and `0x61 XX`
    /// (`GET RESPONSE`) response chaining.
    ///
    /// # Errors
    ///
    /// Returns transport, APDU status-word, or malformed-response errors.
    pub fn transmit_full(&mut self, apdu: &Apdu) -> Result<Vec<u8>> {
        self.transmit_full_inner(apdu, None)
    }

    /// Selects the PIV applet on the YubiKey.
    ///
    /// Clears the session's PIN and management key state first.
    ///
    /// # Errors
    ///
    /// Returns an error if communication fails or the applet is not present.
    pub fn select(&mut self) -> Result<()> {
        self.state.clear();

        let apdu = build_select_piv_apdu();
        let _ = self.transmit_full(&apdu)?;

        self.state.selected = true;
        Ok(())
    }

    /// Verifies the user's PIN.
    ///
    /// # Arguments
    ///
    /// * `pin` - The PIN string (6 to 8 bytes)
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidPin`] if the PIN length is outside `6..=8` or the card rejects it
    /// - [`Error::PinLocked`] if the PIN has been locked after too many attempts
    pub fn verify_pin(&mut self, pin: &str) -> Result<()> {
        self.require_selected()?;

        // Clear verification state before sending so failed retries never leave stale state
        self.state.pin_verified = false;

        let mut apdu = build_verify_pin_apdu(pin)?;
        let response_result = self.transmit_raw(&apdu);
        apdu.zeroize_data();

        let response = response_result?;
        response.check()?;

        self.state.pin_verified = true;
        Ok(())
    }

    /// Performs mutual management key authentication with the YubiKey PIV applet.
    ///
    /// Supports 3DES, AES-128, AES-192, and AES-256 across all transports (native PC/SC,
    /// mock transports, and WASM). Generates a cryptographic random challenge via
    /// [`getrandom`], sends it in plaintext in tag `0x81`, and verifies the card's
    /// encrypted response in tag `0x82` in constant time.
    ///
    /// # Arguments
    ///
    /// * `key` - Raw management key bytes (`key.len() == alg.key_len()`)
    /// * `alg` - The management key algorithm configured on the YubiKey
    ///
    /// # Errors
    ///
    /// - [`Error::AuthenticationFailed`] if the key length is wrong, the card rejects
    ///   our witness, or the card's challenge response fails constant-time verification
    /// - [`Error::MalformedResponse`] if the card returns malformed TLV data
    pub fn authenticate_management_key_with(
        &mut self,
        key: &[u8],
        alg: ManagementKeyAlgorithm,
    ) -> Result<()> {
        self.require_selected()?;

        self.state.mgmt_authenticated = false;

        if key.len() != alg.key_len() {
            return Err(Error::AuthenticationFailed);
        }

        // Step 1: Request an encrypted witness from the card
        let witness_apdu = build_mgmt_auth_request_witness_apdu(alg);
        let witness_resp = self.transmit_full(&witness_apdu)?;
        let witness = parse_witness_response(&witness_resp, alg.block_size())
            .ok_or_else(|| Error::MalformedResponse("invalid witness response".to_string()))?;

        // Step 2: Decrypt witness and generate CSPRNG host challenge
        let decrypted_witness = Zeroizing::new(decrypt_mgmt_witness(alg, key, &witness)?);
        let mut our_challenge = Zeroizing::new(vec![0u8; alg.block_size()]);
        getrandom::fill(&mut our_challenge)
            .map_err(|e| Error::ApduError(format!("CSPRNG failed: {e}")))?;

        // Step 3: Send decrypted witness (0x80) and plaintext host challenge (0x81)
        let mut verify_apdu = build_mgmt_auth_verify_apdu(alg, &decrypted_witness, &our_challenge)?;
        drop(decrypted_witness);

        let transmit_result = self.transmit_full(&verify_apdu);
        verify_apdu.zeroize_data();

        let card_data = match transmit_result {
            Ok(data) => data,
            Err(Error::SecurityStatusNotSatisfied) => return Err(Error::AuthenticationFailed),
            Err(e) => return Err(e),
        };

        // Step 4: Verify the card's encrypted response to our plaintext challenge in constant time
        let expected_response = Zeroizing::new(encrypt_mgmt_challenge(alg, key, &our_challenge)?);
        drop(our_challenge);

        let actual_response = Zeroizing::new(
            parse_challenge_response(&card_data, alg.block_size())
                .ok_or(Error::AuthenticationFailed)?,
        );

        if !verify_mgmt_challenge_response(&expected_response, &actual_response) {
            return Err(Error::AuthenticationFailed);
        }

        self.state.mgmt_authenticated = true;
        Ok(())
    }

    /// Generates a new P-256 key pair in the specified slot, then deletes the
    /// slot's certificate object while management key authentication is held.
    ///
    /// `GENERATE ASYMMETRIC KEY PAIR` replaces the private key but leaves the
    /// slot's certificate untouched, so without the delete the certificate would
    /// keep describing the destroyed key.
    ///
    /// Requires prior management key authentication via
    /// [`authenticate_management_key_with`](Self::authenticate_management_key_with).
    ///
    /// # Arguments
    ///
    /// * `slot` - The PIV slot to generate the key in
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`GeneratedKey`]. A failure to delete the old
    /// certificate does not fail the call (the new key already exists on the
    /// card); it is reported in [`GeneratedKey::certificate_delete_error`].
    ///
    /// # Errors
    ///
    /// - [`Error::SecurityStatusNotSatisfied`] if management key is not authenticated
    /// - [`Error::KeyGenerationFailed`] if response parsing fails
    pub fn generate_key(&mut self, slot: Slot) -> Result<GeneratedKey> {
        self.require_selected()?;

        if !self.state.mgmt_authenticated {
            return Err(Error::SecurityStatusNotSatisfied);
        }

        let apdu = build_generate_key_apdu(slot);
        let data = self.transmit_full_inner(&apdu, Some(slot))?;

        let public_key = parse_public_key_response(&data)
            .ok_or_else(|| Error::KeyGenerationFailed(slot.id(), "invalid response".to_string()))?;

        let certificate_delete_error = self.delete_certificate(slot).err();

        Ok(GeneratedKey {
            public_key,
            certificate_delete_error,
        })
    }

    /// Deletes the slot's certificate object (`PUT DATA` with an empty `0x53`).
    ///
    /// `0x6A82` (no such object) counts as success: there is nothing to delete.
    fn delete_certificate(&mut self, slot: Slot) -> Result<()> {
        let response = self.exchange(&build_delete_certificate_apdu(slot))?;
        match (response.sw1(), response.sw2()) {
            (0x90, 0x00) | (0x6A, 0x82) => Ok(()),
            _ => Err(response.to_error()),
        }
    }

    /// Retrieves the P-256 public key of the private key in `slot`.
    ///
    /// Equivalent to [`Self::get_slot_public_key`] without the source details.
    ///
    /// # Errors
    ///
    /// See [`Self::get_slot_public_key`].
    pub fn get_public_key(&mut self, slot: Slot) -> Result<VerifyingKey> {
        self.get_slot_public_key(slot).map(|key| key.public_key)
    }

    /// Retrieves the P-256 public key of the private key in `slot`.
    ///
    /// Prefers the Yubico `GET METADATA` response (firmware 5.3+), which always
    /// describes the private key currently in the slot. The slot's certificate is
    /// read as well: if it holds a different key it is reported as stale
    /// ([`SlotPublicKey::stale_certificate`]) and ignored.
    ///
    /// Falls back to the certificate only when metadata is unavailable: the card
    /// does not support `GET METADATA` (`0x6D00`) or answers another non-success
    /// status word other than `0x6A82` (see
    /// [`metadata_status_allows_certificate_fallback`]), or returns a payload that
    /// cannot be parsed. Transport errors are never treated as "unsupported".
    ///
    /// # Arguments
    ///
    /// * `slot` - The PIV slot to retrieve the key from
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`SlotPublicKey`].
    ///
    /// # Errors
    ///
    /// - [`Error::SlotEmpty`] if metadata reports no key in the slot (`0x6A82`), or
    ///   metadata is unavailable and no certificate is present
    /// - [`Error::InvalidKeyType`] if metadata reports a non-P-256 key, or metadata is
    ///   unavailable and the certificate does not contain a valid P-256 key
    /// - Transport errors such as [`Error::CardReset`] or [`Error::DeviceDisconnected`]
    pub fn get_slot_public_key(&mut self, slot: Slot) -> Result<SlotPublicKey> {
        self.require_selected()?;

        let metadata = self.exchange(&build_get_metadata_apdu(slot))?;
        let metadata_key = if metadata.is_success() {
            match parse_metadata_response(metadata.data()) {
                Some(SlotMetadata {
                    public_key: Some(public_key),
                    ..
                }) => Some(public_key),
                // Authoritative: the slot holds a key of another algorithm.
                Some(_) => return Err(Error::InvalidKeyType(slot.id())),
                // Unparseable metadata: treat as unavailable.
                None => None,
            }
        } else if metadata_status_allows_certificate_fallback(metadata.sw1(), metadata.sw2()) {
            None
        } else {
            return Err(metadata.to_error_for_slot(slot));
        };

        let certificate = self.exchange(&build_get_certificate_apdu(slot))?;
        let certificate_key = if !certificate.is_success() {
            Err(certificate.to_error_for_slot(slot))
        } else if certificate.data().is_empty() {
            Err(Error::SlotEmpty(slot.id()))
        } else {
            Ok(parse_certificate_public_key(certificate.data()))
        };

        match (metadata_key, certificate_key) {
            (Some(public_key), certificate_key) => {
                let stale_certificate = match certificate_key {
                    Ok(Some(cert_key)) => cert_key != public_key,
                    Ok(None) => true,
                    Err(_) => false,
                };
                Ok(SlotPublicKey {
                    public_key,
                    source: PublicKeySource::Metadata,
                    stale_certificate,
                })
            }
            (None, Ok(Some(public_key))) => Ok(SlotPublicKey {
                public_key,
                source: PublicKeySource::Certificate,
                stale_certificate: false,
            }),
            (None, Ok(None)) => Err(Error::InvalidKeyType(slot.id())),
            (None, Err(e)) => Err(e),
        }
    }

    /// Signs a 32-byte digest using the P-256 key in the specified slot.
    ///
    /// # Arguments
    ///
    /// * `slot` - The PIV slot containing the signing key
    /// * `data` - The 32-byte prehashed digest to sign
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the ASN.1 DER-encoded ECDSA signature.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidSignature`] if `data` is not 32 bytes or the response is malformed
    /// - [`Error::PinRequired`] if the slot requires a PIN and it has not been verified
    /// - [`Error::SecurityStatusNotSatisfied`] if PIN expired or touch confirmation failed
    /// - [`Error::SlotEmpty`] if the slot has no key
    pub fn sign(&mut self, slot: Slot, data: &[u8]) -> Result<Vec<u8>> {
        self.require_selected()?;

        let hash = sign_digest(data)?;

        if slot.requires_pin() && !self.state.pin_verified {
            return Err(Error::PinRequired);
        }

        let apdu = build_sign_apdu(slot, hash);
        let response_data = match self.transmit_full_inner(&apdu, Some(slot)) {
            Ok(bytes) => bytes,
            Err(Error::SecurityStatusNotSatisfied) => {
                self.state.pin_verified = false;
                return Err(Error::SecurityStatusNotSatisfied);
            }
            Err(e) => return Err(e),
        };

        // Slot 9c (Digital Signature) enforces PIN-always on YubiKey
        if slot == Slot::Signature {
            self.state.pin_verified = false;
        }

        parse_signature_response(&response_data)
            .ok_or_else(|| Error::InvalidSignature("invalid signature response".to_string()))
    }

    /// Verifies the PIN and then signs a 32-byte digest.
    ///
    /// The digest length is checked before the PIN is sent. Inside
    /// [`PivSession::exclusive`] (or via [`PivSession::verify_pin_and_sign`]) no
    /// other client can use the verified PIN state between the two commands.
    ///
    /// # Arguments
    ///
    /// * `pin` - The PIN string (6 to 8 bytes)
    /// * `slot` - The PIV slot containing the signing key
    /// * `data` - The 32-byte prehashed digest to sign
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the ASN.1 DER-encoded ECDSA signature.
    ///
    /// # Errors
    ///
    /// Any error from [`Self::verify_pin`] or [`Self::sign`].
    pub fn verify_pin_and_sign(&mut self, pin: &str, slot: Slot, data: &[u8]) -> Result<Vec<u8>> {
        sign_digest(data)?;
        self.verify_pin(pin)?;
        self.sign(slot, data)
    }
}

/// Checks that `data` is a 32-byte digest suitable for P-256 signing.
fn sign_digest(data: &[u8]) -> Result<&[u8; 32]> {
    data.try_into().map_err(|_| {
        Error::InvalidSignature(format!(
            "expected 32-byte hash for P-256 signing, got {} bytes",
            data.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;
    use crate::yubikey::ApduResponse;

    /// NIST P-256 generator point G (65-byte uncompressed SEC1).
    fn sample_p256_uncompressed_point() -> Vec<u8> {
        hex::decode(concat!(
            "04",
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        ))
        .unwrap()
    }

    /// Second valid P-256 point (2*G) for testing bogus embedded points in cert subject.
    fn second_p256_uncompressed_point() -> Vec<u8> {
        let sk = p256::ecdsa::SigningKey::from_bytes(&{
            let mut b = [0u8; 32];
            b[31] = 2;
            b.into()
        })
        .unwrap();
        sk.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }

    /// DER-encodes a TLV element with canonical length.
    fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() < 0x80 {
            out.push(value.len() as u8);
        } else if value.len() <= 0xFF {
            out.push(0x81);
            out.push(value.len() as u8);
        } else {
            out.push(0x82);
            out.push((value.len() >> 8) as u8);
            out.push((value.len() & 0xFF) as u8);
        }
        out.extend_from_slice(value);
        out
    }

    /// Builds a minimal valid X.509 DER certificate with arbitrary subject bytes and SPKI.
    fn build_test_x509_der(
        subject_payload: &[u8],
        alg_oid: &[u8],
        param_oid: &[u8],
        pubkey_point: &[u8],
    ) -> Vec<u8> {
        let version = der_tlv(0xA0, &der_tlv(0x02, &[0x02])); // v3
        let serial = der_tlv(0x02, &[0x01]);
        let sig_alg = der_tlv(
            0x30,
            &der_tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]),
        );
        let issuer = der_tlv(0x30, &[]);
        let validity = der_tlv(0x30, &[]);
        let subject = der_tlv(0x30, subject_payload);

        let mut spki_alg = Vec::new();
        spki_alg.extend_from_slice(&der_tlv(0x06, alg_oid));
        if !param_oid.is_empty() {
            spki_alg.extend_from_slice(&der_tlv(0x06, param_oid));
        }
        let spki_alg_seq = der_tlv(0x30, &spki_alg);

        let mut bit_string_val = vec![0x00]; // 0 unused bits
        bit_string_val.extend_from_slice(pubkey_point);
        let spki_pk = der_tlv(0x03, &bit_string_val);

        let mut spki_inner = Vec::new();
        spki_inner.extend_from_slice(&spki_alg_seq);
        spki_inner.extend_from_slice(&spki_pk);
        let spki = der_tlv(0x30, &spki_inner);

        let mut tbs_inner = Vec::new();
        tbs_inner.extend_from_slice(&version);
        tbs_inner.extend_from_slice(&serial);
        tbs_inner.extend_from_slice(&sig_alg);
        tbs_inner.extend_from_slice(&issuer);
        tbs_inner.extend_from_slice(&validity);
        tbs_inner.extend_from_slice(&subject);
        tbs_inner.extend_from_slice(&spki);
        let tbs = der_tlv(0x30, &tbs_inner);

        let mut cert_inner = Vec::new();
        cert_inner.extend_from_slice(&tbs);
        cert_inner.extend_from_slice(&sig_alg);
        cert_inner.extend_from_slice(&der_tlv(0x03, &[0x00, 0x30, 0x00]));
        der_tlv(0x30, &cert_inner)
    }

    /// Wraps a certificate payload into a PIV `0x53` data object container.
    fn wrap_piv_cert(cert_bytes: &[u8], compressed: bool) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&der_tlv(0x70, cert_bytes));
        inner.extend_from_slice(&der_tlv(0x71, &[u8::from(compressed)]));
        inner.extend_from_slice(&der_tlv(0xFE, &[]));
        der_tlv(0x53, &inner)
    }

    type HandlerFn = Box<dyn FnMut(&Apdu) -> Result<ApduResponse>>;

    /// Scriptable mock transport for testing `PivSession`.
    struct MockTransport {
        handler: HandlerFn,
        sent: Arc<Mutex<Vec<Apdu>>>,
    }

    impl MockTransport {
        fn from_responses(responses: Vec<ApduResponse>) -> (Self, Arc<Mutex<Vec<Apdu>>>) {
            let mut queue: VecDeque<ApduResponse> = responses.into_iter().collect();
            let sent = Arc::new(Mutex::new(Vec::new()));
            let transport = Self {
                handler: Box::new(move |_apdu| {
                    queue
                        .pop_front()
                        .ok_or_else(|| Error::ApduError("no mock response left".to_string()))
                }),
                sent: Arc::clone(&sent),
            };
            (transport, sent)
        }

        fn with_handler<F>(handler: F) -> (Self, Arc<Mutex<Vec<Apdu>>>)
        where
            F: FnMut(&Apdu) -> Result<ApduResponse> + 'static,
        {
            let sent = Arc::new(Mutex::new(Vec::new()));
            let transport = Self {
                handler: Box::new(handler),
                sent: Arc::clone(&sent),
            };
            (transport, sent)
        }
    }

    impl Transport for MockTransport {
        fn transmit(&mut self, apdu: &Apdu) -> Result<ApduResponse> {
            self.sent.lock().unwrap().push(apdu.clone());
            (self.handler)(apdu)
        }

        fn is_connected(&self) -> bool {
            true
        }
    }

    #[test]
    fn piv_aid_valid() {
        assert_eq!(PIV_AID.len(), 9);
        assert_eq!(PIV_AID[0], 0xA0);
    }

    #[test]
    fn parse_signature_response_strict() {
        let response = vec![0x7C, 0x04, 0x82, 0x02, 0xAB, 0xCD];
        assert_eq!(parse_signature_response(&response), Some(vec![0xAB, 0xCD]));

        // Empty, wrong outer tag, trailing garbage, truncated length, non-canonical length
        assert!(parse_signature_response(&[]).is_none());
        assert!(parse_signature_response(&[0x80, 0x04, 0x82, 0x02, 0xAB, 0xCD]).is_none());
        assert!(parse_signature_response(&[0x7C, 0x04, 0x82, 0x02, 0xAB, 0xCD, 0x00]).is_none());
        assert!(parse_signature_response(&[0x7C, 0x04, 0x82, 0x05, 0xAB, 0xCD]).is_none());
        // Non-canonical long form 0x81 0x04 for length 4 (< 0x80)
        assert!(parse_signature_response(&[0x7C, 0x81, 0x04, 0x82, 0x02, 0xAB, 0xCD]).is_none());
        // Indefinite length 0x80
        assert!(parse_signature_response(&[0x7C, 0x80, 0x82, 0x02, 0xAB, 0xCD]).is_none());
    }

    #[test]
    fn parse_certificate_public_key_der_gzip_bogus_point_and_zip_bomb() {
        let real_point = sample_p256_uncompressed_point();
        let bogus_point = second_p256_uncompressed_point();
        let expected_vk =
            VerifyingKey::from_sec1_point(&Sec1Point::from_bytes(&real_point).unwrap()).unwrap();

        // 1. Real X.509 DER P-256 cert with a bogus valid P-256 point embedded in subject
        let bogus_subject_attr = der_tlv(0x04, &bogus_point);
        let cert_der = build_test_x509_der(
            &bogus_subject_attr,
            OID_EC_PUBLIC_KEY,
            OID_SECP256R1,
            &real_point,
        );
        let piv_obj = wrap_piv_cert(&cert_der, false);
        let parsed = parse_certificate_public_key(&piv_obj).unwrap();
        assert_eq!(
            parsed.to_sec1_point(false),
            expected_vk.to_sec1_point(false)
        );

        // 2. Gzip-compressed PIV certificate (tag 0x71 = 0x01)
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&cert_der).unwrap();
        let compressed_cert = gz.finish().unwrap();
        let piv_gz_obj = wrap_piv_cert(&compressed_cert, true);
        let parsed_gz = parse_certificate_public_key(&piv_gz_obj).unwrap();
        assert_eq!(
            parsed_gz.to_sec1_point(false),
            expected_vk.to_sec1_point(false)
        );

        // 3. RSA / non-P-256 OID certificate rejected even if bogus P-256 point is present
        let rsa_oid = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]; // rsaEncryption
        let rsa_cert = build_test_x509_der(&bogus_subject_attr, rsa_oid, &[], &real_point);
        assert!(parse_certificate_public_key(&wrap_piv_cert(&rsa_cert, false)).is_none());

        // 4. Wrong EC curve (secp256k1 OID 1.3.132.0.10 = 2B 81 04 00 0A) rejected
        let secp256k1_oid = &[0x2B, 0x81, 0x04, 0x00, 0x0A];
        let k1_cert = build_test_x509_der(&[], OID_EC_PUBLIC_KEY, secp256k1_oid, &real_point);
        assert!(parse_certificate_public_key(&wrap_piv_cert(&k1_cert, false)).is_none());

        // 5. Zip bomb (> 64 KiB decompressed) rejected cleanly
        let mut bomb_gz = GzEncoder::new(Vec::new(), Compression::best());
        bomb_gz
            .write_all(&vec![0u8; MAX_CERTIFICATE_BYTES + 1024])
            .unwrap();
        let bomb_bytes = bomb_gz.finish().unwrap();
        assert!(parse_certificate_public_key(&wrap_piv_cert(&bomb_bytes, true)).is_none());
    }

    #[test]
    fn piv_session_verify_pin_validation_and_status_words() {
        let (transport, sent) = MockTransport::from_responses(vec![
            ApduResponse::new(vec![0x90, 0x00]), // select
            ApduResponse::new(vec![0x90, 0x00]), // verify ok
            ApduResponse::new(vec![0x63, 0xC2]), // wrong pin (2 left)
            ApduResponse::new(vec![0x63, 0xC0]), // locked
        ]);

        let mut session = PivSession::new(Box::new(transport));
        session.select().unwrap();

        // Empty or short PIN must fail WITHOUT transmitting to card
        assert!(matches!(
            session.verify_pin(""),
            Err(Error::InvalidPin {
                remaining_attempts: None
            })
        ));
        assert!(matches!(
            session.verify_pin("12345"),
            Err(Error::InvalidPin {
                remaining_attempts: None
            })
        ));
        assert!(matches!(
            session.verify_pin("123456789"),
            Err(Error::InvalidPin {
                remaining_attempts: None
            })
        ));
        assert_eq!(sent.lock().unwrap().len(), 1); // Only SELECT was sent!

        // Valid PIN
        session.verify_pin("123456").unwrap();
        assert!(session.is_authenticated());

        // Wrong PIN clears pin_verified and reports remaining attempts
        let err = session.verify_pin("000000").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidPin {
                remaining_attempts: Some(2)
            }
        ));
        assert!(!session.is_authenticated());

        // Locked PIN
        assert!(matches!(
            session.verify_pin("000000"),
            Err(Error::PinLocked)
        ));
        assert!(!session.is_authenticated());
    }

    #[test]
    fn piv_session_mutual_auth_all_algorithms_and_spoof_rejection() {
        let cases: &[(ManagementKeyAlgorithm, Vec<u8>)] = &[
            (ManagementKeyAlgorithm::Tdes, vec![0x01; 24]),
            (ManagementKeyAlgorithm::Aes128, vec![0x11; 16]),
            (ManagementKeyAlgorithm::Aes192, vec![0x22; 24]),
            (ManagementKeyAlgorithm::Aes256, vec![0x33; 32]),
        ];

        for (alg, key) in cases {
            let alg = *alg;
            let card_key = key.clone();
            let card_plaintext_witness = vec![0xA5; alg.block_size()];
            let encrypted_witness =
                encrypt_mgmt_challenge(alg, &card_key, &card_plaintext_witness).unwrap();

            // Simulate a real card for mutual auth
            let mut step = 0u8;
            let expected_witness = card_plaintext_witness.clone();
            let card_key_clone = card_key.clone();
            let (transport, sent) = MockTransport::with_handler(move |apdu| {
                step += 1;
                match step {
                    1 => Ok(ApduResponse::new(vec![0x90, 0x00])), // SELECT
                    2 => {
                        assert_eq!(apdu.p1(), alg.id());
                        assert_eq!(apdu.p2(), key::MANAGEMENT);
                        let mut resp = der_tlv(0x7C, &der_tlv(0x80, &encrypted_witness));
                        resp.extend_from_slice(&[0x90, 0x00]);
                        Ok(ApduResponse::new(resp))
                    }
                    3 => {
                        assert_eq!(apdu.p1(), alg.id());
                        let (outer_tag, outer_val, _) = parse_tlv(apdu.data()).unwrap();
                        assert_eq!(outer_tag, 0x7C);
                        let got_witness = find_tlv_child(outer_val, 0x80).unwrap();
                        let host_challenge = find_tlv_child(outer_val, 0x81).unwrap();
                        assert_eq!(got_witness, expected_witness.as_slice());
                        assert_eq!(host_challenge.len(), alg.block_size());

                        // Card encrypts the plaintext host challenge with shared key
                        let card_resp =
                            encrypt_mgmt_challenge(alg, &card_key_clone, host_challenge).unwrap();
                        let mut resp = der_tlv(0x7C, &der_tlv(0x82, &card_resp));
                        resp.extend_from_slice(&[0x90, 0x00]);
                        Ok(ApduResponse::new(resp))
                    }
                    _ => panic!("unexpected APDU"),
                }
            });

            let mut session = PivSession::new(Box::new(transport));
            session.select().unwrap();
            session.authenticate_management_key_with(key, alg).unwrap();
            assert!(session.is_mgmt_authenticated());
            assert_eq!(sent.lock().unwrap().len(), 3);

            // Now test a spoofed card that returns garbage in tag 0x82 -> MUST FAIL!
            let enc_w2 = encrypt_mgmt_challenge(alg, &card_key, &card_plaintext_witness).unwrap();
            let mut step2 = 0u8;
            let (spoof_transport, _) = MockTransport::with_handler(move |_apdu| {
                step2 += 1;
                match step2 {
                    1 => Ok(ApduResponse::new(vec![0x90, 0x00])),
                    2 => {
                        let mut resp = der_tlv(0x7C, &der_tlv(0x80, &enc_w2));
                        resp.extend_from_slice(&[0x90, 0x00]);
                        Ok(ApduResponse::new(resp))
                    }
                    3 => {
                        // Spoofed wrong response even with SW=9000
                        let mut resp = der_tlv(0x7C, &der_tlv(0x82, &vec![0x00; alg.block_size()]));
                        resp.extend_from_slice(&[0x90, 0x00]);
                        Ok(ApduResponse::new(resp))
                    }
                    _ => panic!("unexpected APDU"),
                }
            });

            let mut spoof_session = PivSession::new(Box::new(spoof_transport));
            spoof_session.select().unwrap();
            assert!(matches!(
                spoof_session.authenticate_management_key_with(key, alg),
                Err(Error::AuthenticationFailed)
            ));
            assert!(!spoof_session.is_mgmt_authenticated());
        }
    }

    #[test]
    fn piv_session_chaining_61xx_and_wrong_le_6cxx() {
        let real_point = sample_p256_uncompressed_point();
        let cert_der = build_test_x509_der(&[], OID_EC_PUBLIC_KEY, OID_SECP256R1, &real_point);
        let piv_obj = wrap_piv_cert(&cert_der, false);

        // Split PIV cert into 3 chunks to test 6C retry + 61 chaining
        let split1 = piv_obj.len() / 3;
        let split2 = (piv_obj.len() * 2) / 3;
        let chunk1 = piv_obj[..split1].to_vec();
        let chunk2 = piv_obj[split1..split2].to_vec();
        let chunk3 = piv_obj[split2..].to_vec();

        let chunk2_len = chunk2.len() as u8;
        let chunk3_len = chunk3.len() as u8;
        let mut resp1 = chunk1;
        resp1.extend_from_slice(&[0x61, chunk2_len]);
        let mut resp2 = chunk2;
        resp2.extend_from_slice(&[0x61, chunk3_len]);
        let mut resp3 = chunk3;
        resp3.extend_from_slice(&[0x90, 0x00]);

        let (transport, sent) = MockTransport::from_responses(vec![
            ApduResponse::new(vec![0x90, 0x00]), // SELECT
            ApduResponse::new(vec![0x6D, 0x00]), // GET METADATA unsupported -> certificate
            ApduResponse::new(vec![0x6C, 0x40]), // GET DATA wrong Le -> retry with Le=0x40
            ApduResponse::new(resp1),            // chunk 1 + 61
            ApduResponse::new(resp2),            // chunk 2 + 61
            ApduResponse::new(resp3),            // chunk 3 + 9000
        ]);

        let mut session = PivSession::new(Box::new(transport));
        session.select().unwrap();
        let info = session.get_slot_public_key(Slot::Authentication).unwrap();
        assert_eq!(
            info.public_key.to_sec1_point(false).as_bytes(),
            real_point.as_slice()
        );
        assert_eq!(info.source, PublicKeySource::Certificate);
        assert!(!info.stale_certificate);

        let sent_apdus = sent.lock().unwrap();
        assert_eq!(sent_apdus.len(), 6);
        assert_eq!(sent_apdus[1].ins(), ins::GET_METADATA);
        // Second GET DATA retry must have Le = Some(0x40)
        assert_eq!(sent_apdus[3].ins(), ins::GET_DATA);
        assert_eq!(sent_apdus[3].le(), Some(0x40));
        // Chained requests must use GET RESPONSE (INS = 0xC0) with Le = preceding SW2
        assert_eq!(sent_apdus[4].ins(), ins::GET_RESPONSE);
        assert_eq!(sent_apdus[4].le(), Some(u32::from(chunk2_len)));
        assert_eq!(sent_apdus[5].ins(), ins::GET_RESPONSE);
        assert_eq!(sent_apdus[5].le(), Some(u32::from(chunk3_len)));
    }

    #[test]
    fn piv_session_generate_key_requires_mgmt_auth_and_sign_rules() {
        let real_point = sample_p256_uncompressed_point();
        let mut gen_resp = vec![0x7F, 0x49, 67, 0x86, 65];
        gen_resp.extend_from_slice(&real_point);
        gen_resp.extend_from_slice(&[0x90, 0x00]);

        let mut sign_resp = der_tlv(
            0x7C,
            &der_tlv(0x82, &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]),
        );
        sign_resp.extend_from_slice(&[0x90, 0x00]);

        let alg = ManagementKeyAlgorithm::Aes192;
        let mgmt_key = vec![0x44u8; 24];
        let witness_plain = vec![0x77u8; 16];
        let witness_enc = encrypt_mgmt_challenge(alg, &mgmt_key, &witness_plain).unwrap();

        let mgmt_key_clone = mgmt_key.clone();
        let mut step = 0u8;
        let (transport, sent) = MockTransport::with_handler(move |apdu| {
            step += 1;
            match step {
                1 => Ok(ApduResponse::new(vec![0x90, 0x00])), // SELECT
                2 => {
                    // Mgmt auth step 1: witness
                    let mut r = der_tlv(0x7C, &der_tlv(0x80, &witness_enc));
                    r.extend_from_slice(&[0x90, 0x00]);
                    Ok(ApduResponse::new(r))
                }
                3 => {
                    // Mgmt auth step 2: verify & respond
                    let (_, outer_val, _) = parse_tlv(apdu.data()).unwrap();
                    let host_chal = find_tlv_child(outer_val, 0x81).unwrap();
                    let card_resp =
                        encrypt_mgmt_challenge(alg, &mgmt_key_clone, host_chal).unwrap();
                    let mut r = der_tlv(0x7C, &der_tlv(0x82, &card_resp));
                    r.extend_from_slice(&[0x90, 0x00]);
                    Ok(ApduResponse::new(r))
                }
                4 => {
                    // GENERATE ASYMMETRIC must include Le = Some(256)
                    assert_eq!(apdu.ins(), ins::GENERATE_ASYMMETRIC);
                    assert_eq!(apdu.le(), Some(256));
                    Ok(ApduResponse::new(gen_resp.clone()))
                }
                5 => {
                    // Stale certificate deleted right after GENERATE
                    assert_eq!(
                        apdu.to_bytes().unwrap(),
                        build_delete_certificate_apdu(Slot::Authentication)
                            .to_bytes()
                            .unwrap()
                    );
                    Ok(ApduResponse::new(vec![0x90, 0x00]))
                }
                6 => Ok(ApduResponse::new(vec![0x6D, 0x00])), // GET METADATA unsupported
                7 => Ok(ApduResponse::new(vec![0x6A, 0x82])), // GET DATA slot empty (9c)
                8 => Ok(ApduResponse::new(vec![0x90, 0x00])), // VERIFY PIN
                9 => Ok(ApduResponse::new(sign_resp.clone())), // SIGN on Slot::Signature (9c)
                10 => Ok(ApduResponse::new(vec![0x90, 0x00])), // VERIFY PIN again
                11 => Ok(ApduResponse::new(vec![0x69, 0x82])), // SIGN returns 69 82 (touch/security)
                _ => panic!("unexpected APDU step {step}"),
            }
        });

        let mut session = PivSession::new(Box::new(transport));
        session.select().unwrap();

        // generate_key without mgmt auth fails before touching transport
        assert!(matches!(
            session.generate_key(Slot::Authentication),
            Err(Error::SecurityStatusNotSatisfied)
        ));

        // Authenticate management key, then generate_key succeeds
        session
            .authenticate_management_key_with(&mgmt_key, alg)
            .unwrap();
        let generated = session.generate_key(Slot::Authentication).unwrap();
        assert_eq!(
            generated.public_key.to_sec1_point(false).as_bytes(),
            real_point.as_slice()
        );
        assert!(generated.certificate_delete_error.is_none());

        // get_public_key maps 6A 82 to SlotEmpty with the actual slot ID (0x9C)
        assert!(matches!(
            session.get_public_key(Slot::Signature),
            Err(Error::SlotEmpty(0x9C))
        ));

        // sign rejects non-32-byte input
        session.verify_pin("123456").unwrap();
        assert!(matches!(
            session.sign(Slot::Authentication, &[0u8; 31]),
            Err(Error::InvalidSignature(_))
        ));

        // sign on Slot::Signature succeeds AND resets pin_verified
        let sig = session.sign(Slot::Signature, &[0x42u8; 32]).unwrap();
        assert_eq!(sig, vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
        assert!(!session.is_authenticated());

        // sign returning 69 82 returns SecurityStatusNotSatisfied and resets pin_verified
        session.verify_pin("123456").unwrap();
        assert!(session.is_authenticated());
        assert!(matches!(
            session.sign(Slot::Authentication, &[0x42u8; 32]),
            Err(Error::SecurityStatusNotSatisfied)
        ));
        assert!(!session.is_authenticated());

        assert_eq!(sent.lock().unwrap().len(), 11);
    }

    #[test]
    fn tlv_parsers_handle_malformed_and_truncated_inputs_without_panic() {
        let edge_cases: &[&[u8]] = &[
            &[],
            &[0x7F],
            &[0x7F, 0x49],
            &[0x7F, 0x49, 0x80],
            &[0x7F, 0x49, 0x85, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            &[0x7F, 0x49, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
            &[0x7F, 0x49, 0x82, 0x00, 0x01, 0x86],
            &[0x7F, 0x81, 0x81, 0x81, 0x81, 0x01],
            &[0x7C, 0x02, 0x80, 0xFF],
            &[0x7C, 0x02, 0x82, 0x08],
            &[0x53, 0x00],
            &[0x53, 0x04, 0x70, 0x02, 0x30, 0x80],
            &[0x53, 0x05, 0x71, 0x02, 0x00, 0x00, 0x00],
            &[0x53, 0x06, 0x70, 0x01, 0xFF, 0x71, 0x01, 0x01],
        ];

        for input in edge_cases {
            assert!(parse_witness_response(input, 8).is_none());
            assert!(parse_challenge_response(input, 16).is_none());
            assert!(parse_public_key_response(input).is_none());
            assert!(parse_signature_response(input).is_none());
            assert!(parse_certificate_public_key(input).is_none());
            assert!(parse_metadata_response(input).is_none());
        }
    }

    // -------------------------------------------------------------------------
    // Exclusive-scope recording mock and simulated card helpers
    // -------------------------------------------------------------------------

    /// Event recorded by [`ScopedMock`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Event {
        Begin,
        End,
        Apdu(u8),
    }

    /// Mock transport that records exclusive scopes and refuses nested begins,
    /// like a PC/SC transaction would deadlock or misbehave.
    struct ScopedMock {
        handler: HandlerFn,
        events: Arc<Mutex<Vec<Event>>>,
        sent: Arc<Mutex<Vec<Apdu>>>,
        in_scope: bool,
        fail_begin: Arc<AtomicBool>,
    }

    /// The transport handed to closures inside a [`ScopedMock`] scope.
    struct InScope<'a> {
        mock: &'a mut ScopedMock,
    }

    struct ScopedHandles {
        events: Arc<Mutex<Vec<Event>>>,
        sent: Arc<Mutex<Vec<Apdu>>>,
        fail_begin: Arc<AtomicBool>,
    }

    impl ScopedMock {
        fn new<F>(handler: F) -> (Self, ScopedHandles)
        where
            F: FnMut(&Apdu) -> Result<ApduResponse> + 'static,
        {
            let events = Arc::new(Mutex::new(Vec::new()));
            let sent = Arc::new(Mutex::new(Vec::new()));
            let fail_begin = Arc::new(AtomicBool::new(false));
            let mock = Self {
                handler: Box::new(handler),
                events: Arc::clone(&events),
                sent: Arc::clone(&sent),
                in_scope: false,
                fail_begin: Arc::clone(&fail_begin),
            };
            (
                mock,
                ScopedHandles {
                    events,
                    sent,
                    fail_begin,
                },
            )
        }

        fn record(&mut self, apdu: &Apdu) -> Result<ApduResponse> {
            self.events.lock().unwrap().push(Event::Apdu(apdu.ins()));
            self.sent.lock().unwrap().push(apdu.clone());
            (self.handler)(apdu)
        }
    }

    impl Transport for InScope<'_> {
        fn transmit(&mut self, apdu: &Apdu) -> Result<ApduResponse> {
            self.mock.record(apdu)
        }

        fn is_connected(&self) -> bool {
            true
        }
    }

    impl Transport for ScopedMock {
        fn transmit(&mut self, apdu: &Apdu) -> Result<ApduResponse> {
            self.record(apdu)
        }

        fn is_connected(&self) -> bool {
            true
        }

        fn exclusive(&mut self, f: &mut dyn FnMut(&mut dyn Transport) -> Result<()>) -> Result<()> {
            assert!(
                !self.in_scope,
                "nested exclusive begin on the outer transport"
            );
            if self.fail_begin.swap(false, Ordering::SeqCst) {
                return Err(Error::CardReset);
            }
            self.in_scope = true;
            self.events.lock().unwrap().push(Event::Begin);
            let result = f(&mut InScope { mock: self });
            self.events.lock().unwrap().push(Event::End);
            self.in_scope = false;
            result
        }
    }

    /// Splits recorded events into the INS bytes of each exclusive scope,
    /// panicking if any APDU was sent outside a scope.
    fn scopes(events: &Arc<Mutex<Vec<Event>>>) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut current: Option<Vec<u8>> = None;
        for event in events.lock().unwrap().drain(..) {
            match event {
                Event::Begin => {
                    assert!(current.is_none(), "nested scope");
                    current = Some(Vec::new());
                }
                Event::End => out.push(current.take().expect("End without Begin")),
                Event::Apdu(ins) => current
                    .as_mut()
                    .expect("APDU sent outside an exclusive scope")
                    .push(ins),
            }
        }
        assert!(current.is_none(), "unterminated scope");
        out
    }

    /// `data || 90 00`.
    fn ok(mut data: Vec<u8>) -> Result<ApduResponse> {
        data.extend_from_slice(&[0x90, 0x00]);
        Ok(ApduResponse::new(data))
    }

    /// Status-word-only response.
    fn sw(sw1: u8, sw2: u8) -> Result<ApduResponse> {
        Ok(ApduResponse::new(vec![sw1, sw2]))
    }

    fn vk(point: &[u8]) -> VerifyingKey {
        VerifyingKey::from_sec1_point(&Sec1Point::from_bytes(point).unwrap()).unwrap()
    }

    /// `GET METADATA` body for a key with the given algorithm and EC point.
    fn metadata_body(algorithm: u8, point: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&der_tlv(0x01, &[algorithm]));
        body.extend_from_slice(&der_tlv(0x02, &[0x01, 0x01]));
        body.extend_from_slice(&der_tlv(0x03, &[0x01]));
        body.extend_from_slice(&der_tlv(0x04, &der_tlv(0x86, point)));
        body
    }

    /// PIV certificate object for a P-256 point.
    fn cert_object(point: &[u8]) -> Vec<u8> {
        wrap_piv_cert(
            &build_test_x509_der(&[], OID_EC_PUBLIC_KEY, OID_SECP256R1, point),
            false,
        )
    }

    /// Simulates `SELECT` and both management key authentication steps; all
    /// other APDUs go to `other`.
    fn simulated_card<F>(
        alg: ManagementKeyAlgorithm,
        mgmt_key: Vec<u8>,
        mut other: F,
    ) -> impl FnMut(&Apdu) -> Result<ApduResponse> + 'static
    where
        F: FnMut(&Apdu) -> Result<ApduResponse> + 'static,
    {
        let witness_plain = vec![0x5Au8; alg.block_size()];
        move |apdu| {
            if apdu.ins() == ins::SELECT {
                return ok(Vec::new());
            }
            if apdu.ins() == ins::AUTHENTICATE && apdu.p2() == key::MANAGEMENT {
                let (_, outer, _) = parse_tlv(apdu.data()).unwrap();
                if let Some(challenge) = find_tlv_child(outer, 0x81) {
                    let response = encrypt_mgmt_challenge(alg, &mgmt_key, challenge).unwrap();
                    return ok(der_tlv(0x7C, &der_tlv(0x82, &response)));
                }
                let witness = encrypt_mgmt_challenge(alg, &mgmt_key, &witness_plain).unwrap();
                return ok(der_tlv(0x7C, &der_tlv(0x80, &witness)));
            }
            other(apdu)
        }
    }

    fn generate_response(point: &[u8]) -> Vec<u8> {
        der_tlv_multi(0x7F49, &der_tlv(0x86, point))
    }

    /// DER TLV with a two-byte tag.
    fn der_tlv_multi(tag: u16, value: &[u8]) -> Vec<u8> {
        let mut out = vec![(tag >> 8) as u8];
        out.extend_from_slice(&der_tlv((tag & 0xFF) as u8, value));
        out
    }

    // -------------------------------------------------------------------------
    // Builders and parsers
    // -------------------------------------------------------------------------

    #[test]
    fn metadata_delete_and_get_response_apdu_encoding() {
        assert_eq!(
            build_get_metadata_apdu(Slot::Authentication)
                .to_bytes()
                .unwrap(),
            vec![0x00, 0xF7, 0x00, 0x9A, 0x00]
        );
        assert_eq!(
            build_delete_certificate_apdu(Slot::Signature)
                .to_bytes()
                .unwrap(),
            vec![
                0x00, 0xDB, 0x3F, 0xFF, 0x07, 0x5C, 0x03, 0x5F, 0xC1, 0x0A, 0x53, 0x00
            ]
        );
        assert_eq!(build_get_response_apdu(0x00).le(), Some(256));
        assert_eq!(
            build_get_response_apdu(0x00).to_bytes().unwrap(),
            vec![0x00, 0xC0, 0x00, 0x00, 0x00]
        );
        assert_eq!(build_get_response_apdu(0x10).le(), Some(0x10));
    }

    #[test]
    fn parse_metadata_response_strict() {
        let point = sample_p256_uncompressed_point();

        let parsed = parse_metadata_response(&metadata_body(alg::ECCP256, &point)).unwrap();
        assert!(parsed.is_p256());
        assert_eq!(parsed.policy, Some([0x01, 0x01]));
        assert_eq!(parsed.origin, Some(0x01));
        assert_eq!(parsed.public_key, Some(vk(&point)));

        // Unknown tags are ignored
        let mut with_unknown = metadata_body(alg::ECCP256, &point);
        with_unknown.extend_from_slice(&der_tlv(0x06, &[0x03, 0x03]));
        assert!(parse_metadata_response(&with_unknown).is_some());

        // Non-P-256 algorithm (RSA-2048 = 0x07): parsed, key not decoded
        let rsa = parse_metadata_response(&metadata_body(0x07, &[0x81, 0x01, 0x00])).unwrap();
        assert!(!rsa.is_p256());
        assert_eq!(rsa.public_key, None);

        // Missing algorithm
        assert!(parse_metadata_response(&der_tlv(0x04, &der_tlv(0x86, &point))).is_none());
        // Duplicate algorithm tag
        let mut dup = der_tlv(0x01, &[0x11]);
        dup.extend_from_slice(&metadata_body(alg::ECCP256, &point));
        assert!(parse_metadata_response(&dup).is_none());
        // Wrong algorithm length
        let mut long_alg = der_tlv(0x01, &[0x11, 0x00]);
        long_alg.extend_from_slice(&der_tlv(0x04, &der_tlv(0x86, &point)));
        assert!(parse_metadata_response(&long_alg).is_none());
        // P-256 without public key
        assert!(parse_metadata_response(&der_tlv(0x01, &[0x11])).is_none());
        // Wrong inner tag
        let mut wrong_inner = der_tlv(0x01, &[0x11]);
        wrong_inner.extend_from_slice(&der_tlv(0x04, &der_tlv(0x85, &point)));
        assert!(parse_metadata_response(&wrong_inner).is_none());
        // Compressed point
        let compressed = vk(&point).to_sec1_point(true).as_bytes().to_vec();
        assert!(parse_metadata_response(&metadata_body(alg::ECCP256, &compressed)).is_none());
        // Point not on the curve
        let mut off_curve = point.clone();
        off_curve[64] ^= 0x01;
        assert!(parse_metadata_response(&metadata_body(alg::ECCP256, &off_curve)).is_none());
        // Trailing bytes inside the public key TLV
        let mut inner = der_tlv(0x86, &point);
        inner.push(0x00);
        let mut trailing = der_tlv(0x01, &[0x11]);
        trailing.extend_from_slice(&der_tlv(0x04, &inner));
        assert!(parse_metadata_response(&trailing).is_none());
        // Truncated outer TLV
        let full = metadata_body(alg::ECCP256, &point);
        assert!(parse_metadata_response(&full[..full.len() - 1]).is_none());
    }

    #[test]
    fn metadata_fallback_policy() {
        assert!(!metadata_status_allows_certificate_fallback(0x90, 0x00));
        assert!(!metadata_status_allows_certificate_fallback(0x6A, 0x82));
        assert!(metadata_status_allows_certificate_fallback(0x6D, 0x00));
        assert!(metadata_status_allows_certificate_fallback(0x6A, 0x81));
        assert!(metadata_status_allows_certificate_fallback(0x6E, 0x00));
    }

    // -------------------------------------------------------------------------
    // M1: authoritative public key lookup
    // -------------------------------------------------------------------------

    /// Session whose card answers SELECT, then `metadata` and `certificate`
    /// for GET METADATA / GET DATA.
    fn lookup_session(
        metadata: Result<ApduResponse>,
        certificate: Result<ApduResponse>,
    ) -> (PivSession, ScopedHandles) {
        let mut metadata = Some(metadata);
        let mut certificate = Some(certificate);
        let (mock, handles) = ScopedMock::new(move |apdu| match apdu.ins() {
            ins::SELECT => ok(Vec::new()),
            ins::GET_METADATA => metadata.take().expect("one GET METADATA"),
            ins::GET_DATA => certificate.take().expect("one GET DATA"),
            other => panic!("unexpected INS {other:#04x}"),
        });
        (PivSession::new(Box::new(mock)), handles)
    }

    #[test]
    fn get_public_key_prefers_metadata_and_reports_stale_certificate() {
        let key_a = sample_p256_uncompressed_point();
        let key_b = second_p256_uncompressed_point();

        // Metadata and certificate agree
        let (mut session, handles) = lookup_session(
            ok(metadata_body(alg::ECCP256, &key_a)),
            ok(cert_object(&key_a)),
        );
        let info = session
            .exclusive(|piv| {
                piv.select()?;
                piv.get_slot_public_key(Slot::Authentication)
            })
            .unwrap();
        assert_eq!(info.public_key, vk(&key_a));
        assert_eq!(info.source, PublicKeySource::Metadata);
        assert!(!info.stale_certificate);
        assert_eq!(
            scopes(&handles.events),
            vec![vec![ins::SELECT, ins::GET_METADATA, ins::GET_DATA]]
        );

        // Certificate describes another (destroyed) key: metadata wins, stale reported
        let (mut session, _) = lookup_session(
            ok(metadata_body(alg::ECCP256, &key_a)),
            ok(cert_object(&key_b)),
        );
        session.select().unwrap();
        let info = session.get_slot_public_key(Slot::Authentication).unwrap();
        assert_eq!(info.public_key, vk(&key_a));
        assert_eq!(info.source, PublicKeySource::Metadata);
        assert!(info.stale_certificate);

        // Certificate present but not P-256: also stale
        let rsa_cert = wrap_piv_cert(
            &build_test_x509_der(
                &[],
                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01],
                &[],
                &key_b,
            ),
            false,
        );
        let (mut session, _) =
            lookup_session(ok(metadata_body(alg::ECCP256, &key_a)), ok(rsa_cert));
        session.select().unwrap();
        let info = session.get_slot_public_key(Slot::Authentication).unwrap();
        assert_eq!(info.public_key, vk(&key_a));
        assert!(info.stale_certificate);

        // No certificate at all: key from metadata, nothing stale
        let (mut session, _) =
            lookup_session(ok(metadata_body(alg::ECCP256, &key_a)), sw(0x6A, 0x82));
        session.select().unwrap();
        let pk = session.get_public_key(Slot::Authentication).unwrap();
        assert_eq!(pk, vk(&key_a));
    }

    #[test]
    fn get_public_key_falls_back_to_certificate_when_metadata_unavailable() {
        let key_b = second_p256_uncompressed_point();

        for metadata in [
            sw(0x6D, 0x00),                     // instruction not supported (< 5.3)
            sw(0x6A, 0x81),                     // other non-success status word
            ok(vec![0x01, 0x01]),               // unparseable payload
            ok(der_tlv(0x01, &[alg::ECCP256])), // P-256 without a key
        ] {
            let (mut session, handles) = lookup_session(metadata, ok(cert_object(&key_b)));
            session.select().unwrap();
            let info = session.get_slot_public_key(Slot::Authentication).unwrap();
            assert_eq!(info.public_key, vk(&key_b));
            assert_eq!(info.source, PublicKeySource::Certificate);
            assert!(!info.stale_certificate);
            assert_eq!(
                scopes(&handles.events),
                vec![vec![ins::SELECT], vec![ins::GET_METADATA, ins::GET_DATA]]
            );
        }

        // Fallback with no certificate -> SlotEmpty (as before)
        let (mut session, _) = lookup_session(sw(0x6D, 0x00), sw(0x6A, 0x82));
        session.select().unwrap();
        assert!(matches!(
            session.get_public_key(Slot::Authentication),
            Err(Error::SlotEmpty(0x9A))
        ));
    }

    #[test]
    fn get_public_key_metadata_is_authoritative_for_empty_and_non_p256_slots() {
        let key_b = second_p256_uncompressed_point();

        // 6A82 from GET METADATA: no key; the (stale) certificate must not be used
        let (mut session, handles) = lookup_session(sw(0x6A, 0x82), ok(cert_object(&key_b)));
        session.select().unwrap();
        assert!(matches!(
            session.get_public_key(Slot::Authentication),
            Err(Error::SlotEmpty(0x9A))
        ));
        assert!(
            !handles
                .sent
                .lock()
                .unwrap()
                .iter()
                .any(|a| a.ins() == ins::GET_DATA)
        );

        // Metadata reports an RSA key: InvalidKeyType, no fallback
        let (mut session, handles) = lookup_session(
            ok(metadata_body(0x07, &[0x81, 0x01, 0x00])),
            ok(cert_object(&key_b)),
        );
        session.select().unwrap();
        assert!(matches!(
            session.get_public_key(Slot::Authentication),
            Err(Error::InvalidKeyType(0x9A))
        ));
        assert!(
            !handles
                .sent
                .lock()
                .unwrap()
                .iter()
                .any(|a| a.ins() == ins::GET_DATA)
        );
    }

    #[test]
    fn get_public_key_propagates_transport_errors() {
        let key_a = sample_p256_uncompressed_point();

        // Transport failure on GET METADATA is not "unsupported"
        let (mut session, handles) =
            lookup_session(Err(Error::DeviceDisconnected), ok(cert_object(&key_a)));
        session.select().unwrap();
        assert!(matches!(
            session.get_public_key(Slot::Authentication),
            Err(Error::DeviceDisconnected)
        ));
        assert!(!session.is_selected());
        assert!(
            !handles
                .sent
                .lock()
                .unwrap()
                .iter()
                .any(|a| a.ins() == ins::GET_DATA)
        );

        // Transport failure on the certificate read after valid metadata
        let (mut session, _) = lookup_session(
            ok(metadata_body(alg::ECCP256, &key_a)),
            Err(Error::CardReset),
        );
        session.select().unwrap();
        assert!(matches!(
            session.get_public_key(Slot::Authentication),
            Err(Error::CardReset)
        ));
        assert!(!session.is_selected());
    }

    // -------------------------------------------------------------------------
    // M1 (b): certificate deleted after GENERATE
    // -------------------------------------------------------------------------

    fn generate_session(delete: Result<ApduResponse>) -> (PivSession, ScopedHandles, Vec<u8>) {
        let alg = ManagementKeyAlgorithm::Aes192;
        let mgmt_key = vec![0x42u8; 24];
        let point = sample_p256_uncompressed_point();
        let gen_resp = generate_response(&point);
        let mut delete = Some(delete);
        let (mock, handles) =
            ScopedMock::new(simulated_card(alg, mgmt_key, move |apdu| {
                match apdu.ins() {
                    ins::GENERATE_ASYMMETRIC => ok(gen_resp.clone()),
                    ins::PUT_DATA => {
                        assert_eq!(
                            apdu.to_bytes().unwrap(),
                            build_delete_certificate_apdu(Slot::Authentication)
                                .to_bytes()
                                .unwrap()
                        );
                        delete.take().expect("one PUT DATA")
                    }
                    other => panic!("unexpected INS {other:#04x}"),
                }
            }));
        (PivSession::new(Box::new(mock)), handles, point)
    }

    fn select_auth_generate(session: &mut PivSession) -> Result<GeneratedKey> {
        session.exclusive(|piv| {
            piv.select()?;
            piv.authenticate_management_key_with(&[0x42u8; 24], ManagementKeyAlgorithm::Aes192)?;
            piv.generate_key(Slot::Authentication)
        })
    }

    #[test]
    fn generate_key_deletes_certificate_in_the_same_scope() {
        for delete in [ok(Vec::new()), sw(0x6A, 0x82)] {
            let (mut session, handles, point) = generate_session(delete);
            let generated = select_auth_generate(&mut session).unwrap();
            assert_eq!(generated.public_key, vk(&point));
            assert!(generated.certificate_delete_error.is_none());
            assert!(session.is_mgmt_authenticated());
            assert_eq!(
                scopes(&handles.events),
                vec![vec![
                    ins::SELECT,
                    ins::AUTHENTICATE,
                    ins::AUTHENTICATE,
                    ins::GENERATE_ASYMMETRIC,
                    ins::PUT_DATA,
                ]]
            );
        }
    }

    #[test]
    fn generate_key_keeps_new_key_when_certificate_delete_fails() {
        // Card refuses the delete: key returned, failure reported
        let (mut session, _, point) = generate_session(sw(0x69, 0x82));
        let generated = select_auth_generate(&mut session).unwrap();
        assert_eq!(generated.public_key, vk(&point));
        assert!(matches!(
            generated.certificate_delete_error,
            Some(Error::SecurityStatusNotSatisfied)
        ));
        assert!(session.is_selected());

        // Transport failure during the delete: key still returned, state cleared
        let (mut session, _, point) = generate_session(Err(Error::CardReset));
        let generated = select_auth_generate(&mut session).unwrap();
        assert_eq!(generated.public_key, vk(&point));
        assert!(matches!(
            generated.certificate_delete_error,
            Some(Error::CardReset)
        ));
        assert!(!session.is_selected());
        assert!(!session.is_mgmt_authenticated());
    }

    // -------------------------------------------------------------------------
    // M3: exclusive scopes
    // -------------------------------------------------------------------------

    #[test]
    fn exclusive_scopes_cover_chains_auth_and_verify_then_sign() {
        let mut sign_resp = der_tlv(
            0x7C,
            &der_tlv(0x82, &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]),
        );
        sign_resp.extend_from_slice(&[0x90, 0x00]);
        let (mock, handles) = ScopedMock::new(simulated_card(
            ManagementKeyAlgorithm::Aes128,
            vec![0x11; 16],
            move |apdu| match apdu.ins() {
                ins::GET_DATA => Ok(ApduResponse::new(vec![0xAA, 0x61, 0x02])),
                ins::GET_RESPONSE => ok(vec![0xBB, 0xCC]),
                ins::VERIFY => ok(Vec::new()),
                ins::AUTHENTICATE => Ok(ApduResponse::new(sign_resp.clone())),
                other => panic!("unexpected INS {other:#04x}"),
            },
        ));
        let mut session = PivSession::new(Box::new(mock));

        session.select().unwrap();
        let data = session
            .transmit_full(&build_get_certificate_apdu(Slot::Authentication))
            .unwrap();
        assert_eq!(data, vec![0xAA, 0xBB, 0xCC]);
        session
            .authenticate_management_key_with(&[0x11; 16], ManagementKeyAlgorithm::Aes128)
            .unwrap();
        let sig = session
            .verify_pin_and_sign("123456", Slot::Authentication, &[0x42; 32])
            .unwrap();
        assert_eq!(sig, vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);

        assert_eq!(
            scopes(&handles.events),
            vec![
                vec![ins::SELECT],
                vec![ins::GET_DATA, ins::GET_RESPONSE],
                vec![ins::AUTHENTICATE, ins::AUTHENTICATE],
                vec![ins::VERIFY, ins::AUTHENTICATE],
            ]
        );
    }

    #[test]
    fn transmit_chained_runs_one_scope_and_nests_inline() {
        let mut calls = 0u8;
        let (mut mock, handles) = ScopedMock::new(move |apdu| {
            calls += 1;
            match (calls, apdu.ins()) {
                (1, ins::GET_DATA) => Ok(ApduResponse::new(vec![0x01, 0x61, 0x00])),
                (2, ins::GET_RESPONSE) => Ok(ApduResponse::new(vec![0x02, 0x90, 0x00])),
                (3, ins::GET_DATA) => sw(0x69, 0x82),
                (4, ins::GET_DATA) => Ok(ApduResponse::new(vec![0x03, 0x90, 0x00])),
                other => panic!("unexpected call {other:?}"),
            }
        });

        let apdu = build_get_certificate_apdu(Slot::Authentication);
        let response = transmit_chained(&mut mock, &apdu).unwrap();
        assert_eq!(response.data(), &[0x01, 0x02]);
        assert!(response.is_success());

        // A non-success status word is returned, not converted into an error
        let response = transmit_chained(&mut mock, &apdu).unwrap();
        assert!(response.data().is_empty());
        assert_eq!(response.status_word(), 0x6982);

        // Nested use inside an outer scope runs inline (ScopedMock panics on nested begin)
        mock.exclusive(&mut |scoped| {
            let response = transmit_chained(scoped, &apdu)?;
            assert_eq!(response.data(), &[0x03]);
            Ok(())
        })
        .unwrap();

        assert_eq!(
            scopes(&handles.events),
            vec![
                vec![ins::GET_DATA, ins::GET_RESPONSE],
                vec![ins::GET_DATA],
                vec![ins::GET_DATA],
            ]
        );
        // 6100 -> GET RESPONSE with Le = 256
        assert_eq!(handles.sent.lock().unwrap()[1].le(), Some(256));
    }

    #[test]
    fn failed_scope_begin_clears_session_state() {
        let (mock, handles) = ScopedMock::new(|apdu| match apdu.ins() {
            ins::SELECT | ins::VERIFY => ok(Vec::new()),
            other => panic!("unexpected INS {other:#04x}"),
        });
        let mut session = PivSession::new(Box::new(mock));
        session.select().unwrap();
        session.verify_pin("123456").unwrap();
        assert!(session.is_authenticated());

        handles.fail_begin.store(true, Ordering::SeqCst);
        assert!(matches!(
            session.sign(Slot::Authentication, &[0u8; 32]),
            Err(Error::CardReset)
        ));
        assert!(!session.is_selected());
        assert!(!session.is_authenticated());

        session.select().unwrap();
        assert!(session.is_selected());
    }

    // -------------------------------------------------------------------------
    // M6: card reset recovery
    // -------------------------------------------------------------------------

    #[test]
    fn card_reset_mid_session_clears_state_and_select_recovers() {
        let alg = ManagementKeyAlgorithm::Tdes;
        let reset_pending = Arc::new(AtomicBool::new(true));
        let reset = Arc::clone(&reset_pending);
        let (mock, handles) =
            ScopedMock::new(simulated_card(
                alg,
                vec![0x01; 24],
                move |apdu| match apdu.ins() {
                    ins::VERIFY => ok(Vec::new()),
                    ins::AUTHENTICATE if reset.swap(false, Ordering::SeqCst) => {
                        Err(Error::CardReset)
                    }
                    other => panic!("unexpected INS {other:#04x}"),
                },
            ));
        let mut session = PivSession::new(Box::new(mock));

        session.select().unwrap();
        session.verify_pin("123456").unwrap();
        session
            .authenticate_management_key_with(&[0x01; 24], alg)
            .unwrap();
        assert!(session.is_selected() && session.is_authenticated());
        assert!(session.is_mgmt_authenticated());

        // Another client reset the card: the sign transmit reports CardReset
        assert!(matches!(
            session.sign(Slot::Authentication, &[0x42; 32]),
            Err(Error::CardReset)
        ));
        assert!(!session.is_selected());
        assert!(!session.is_authenticated());
        assert!(!session.is_mgmt_authenticated());

        // Without re-selecting, nothing is sent
        let sent_before = handles.sent.lock().unwrap().len();
        assert!(session.sign(Slot::Authentication, &[0x42; 32]).is_err());
        assert_eq!(handles.sent.lock().unwrap().len(), sent_before);

        // select() recovers the session; PIN must be verified again
        session.select().unwrap();
        assert!(session.is_selected());
        assert!(!session.is_authenticated());
        assert!(matches!(
            session.sign(Slot::Authentication, &[0x42; 32]),
            Err(Error::PinRequired)
        ));
        assert!(!reset_pending.load(Ordering::SeqCst));
    }

    #[test]
    fn status_word_errors_do_not_clear_session_state() {
        let (transport, _) = MockTransport::from_responses(vec![
            ApduResponse::new(vec![0x90, 0x00]), // SELECT
            ApduResponse::new(vec![0x90, 0x00]), // VERIFY
            ApduResponse::new(vec![0x6A, 0x80]), // GET DATA error SW
        ]);
        let mut session = PivSession::new(Box::new(transport));
        session.select().unwrap();
        session.verify_pin("123456").unwrap();
        assert!(session.transmit_full(&build_select_piv_apdu()).is_err());
        assert!(session.is_selected());
        assert!(session.is_authenticated());
    }

    // -------------------------------------------------------------------------
    // Test gaps: chaining, SELECT 61xx, mgmt auth 6982, PinRequired
    // -------------------------------------------------------------------------

    #[test]
    fn chaining_6c_on_get_response_and_error_mid_chain() {
        // 6Cxx in reply to GET RESPONSE -> GET RESPONSE retried with the corrected Le
        let (transport, sent) = MockTransport::from_responses(vec![
            ApduResponse::new(vec![0x90, 0x00]),             // SELECT
            ApduResponse::new(vec![0x01, 0x02, 0x61, 0x10]), // GET DATA chunk 1
            ApduResponse::new(vec![0x6C, 0x08]),             // GET RESPONSE wrong Le
            ApduResponse::new(vec![0x03, 0x04, 0x90, 0x00]), // GET RESPONSE retry
        ]);
        let mut session = PivSession::new(Box::new(transport));
        session.select().unwrap();
        let data = session
            .transmit_full(&build_get_certificate_apdu(Slot::Authentication))
            .unwrap();
        assert_eq!(data, vec![0x01, 0x02, 0x03, 0x04]);
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 4);
        assert_eq!(sent[2].ins(), ins::GET_RESPONSE);
        assert_eq!(sent[2].le(), Some(0x10));
        assert_eq!(sent[3].ins(), ins::GET_RESPONSE);
        assert_eq!(sent[3].le(), Some(0x08));
        drop(sent);

        // Error status word on a middle chunk of a 61xx chain fails the exchange
        let (transport, sent) = MockTransport::from_responses(vec![
            ApduResponse::new(vec![0x90, 0x00]),       // SELECT
            ApduResponse::new(vec![0x01, 0x61, 0x00]), // chunk 1, 256 more
            ApduResponse::new(vec![0x02, 0x61, 0x05]), // chunk 2, 5 more
            ApduResponse::new(vec![0x6A, 0x80]),       // chunk 3 fails
        ]);
        let mut session = PivSession::new(Box::new(transport));
        session.select().unwrap();
        assert!(matches!(
            session.transmit_full(&build_get_certificate_apdu(Slot::Authentication)),
            Err(Error::UnexpectedStatusWord(0x6A, 0x80))
        ));
        assert!(session.is_selected());
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 4);
        assert_eq!(sent[2].le(), Some(256));
        assert_eq!(sent[3].le(), Some(0x05));
    }

    #[test]
    fn select_handles_61xx_chaining() {
        let (transport, sent) = MockTransport::from_responses(vec![
            ApduResponse::new(vec![0x61, 0x03]),
            ApduResponse::new(vec![0x61, 0x11, 0x79, 0x90, 0x00]),
        ]);
        let mut session = PivSession::new(Box::new(transport));
        session.select().unwrap();
        assert!(session.is_selected());
        let sent = sent.lock().unwrap();
        assert_eq!(sent[1].ins(), ins::GET_RESPONSE);
        assert_eq!(sent[1].le(), Some(3));
    }

    #[test]
    fn mgmt_auth_step2_security_status_maps_to_authentication_failed() {
        let alg = ManagementKeyAlgorithm::Aes256;
        let key = vec![0x33u8; 32];
        let witness = encrypt_mgmt_challenge(alg, &key, &[0x99; 16]).unwrap();
        let mut witness_resp = der_tlv(0x7C, &der_tlv(0x80, &witness));
        witness_resp.extend_from_slice(&[0x90, 0x00]);
        let (transport, _) = MockTransport::from_responses(vec![
            ApduResponse::new(vec![0x90, 0x00]), // SELECT
            ApduResponse::new(witness_resp),     // step 1
            ApduResponse::new(vec![0x69, 0x82]), // step 2 rejected
        ]);
        let mut session = PivSession::new(Box::new(transport));
        session.select().unwrap();
        assert!(matches!(
            session.authenticate_management_key_with(&key, alg),
            Err(Error::AuthenticationFailed)
        ));
        assert!(!session.is_mgmt_authenticated());
    }

    #[test]
    fn sign_without_pin_returns_pin_required() {
        let (transport, sent) = MockTransport::from_responses(vec![
            ApduResponse::new(vec![0x90, 0x00]), // SELECT
        ]);
        let mut session = PivSession::new(Box::new(transport));
        session.select().unwrap();
        assert!(matches!(
            session.sign(Slot::Authentication, &[0u8; 32]),
            Err(Error::PinRequired)
        ));
        // A bad digest is rejected before the PIN is sent
        assert!(matches!(
            session.verify_pin_and_sign("123456", Slot::Authentication, &[0u8; 31]),
            Err(Error::InvalidSignature(_))
        ));
        assert_eq!(sent.lock().unwrap().len(), 1);
    }
}
