//! Ethereum signature types for secp256r1 (P-256) ECDSA.
//!
//! This module provides the [`Signature`] type that represents an Ethereum-compatible
//! ECDSA signature using the secp256r1 (NIST P-256) curve as specified in [EIP-7951].
//!
//! # Signature Format
//!
//! Ethereum signatures consist of three components:
//!
//! - `r`: The x-coordinate of the ephemeral public key (32 bytes, `1 <= r < N`)
//! - `s`: The signature scalar (32 bytes, `1 <= s < N`)
//! - `v`: The recovery parameter (1 byte, `0` or `1` for EIP-7951)
//!
//! # Example
//!
//! ```
//! use yubikey_evm_signer_core::Signature;
//!
//! // Create a signature from valid non-zero P-256 scalar bytes
//! let r = [1u8; 32];
//! let s = [2u8; 32];
//! let v = 0u8;
//! let sig = Signature::new(r, s, v).unwrap();
//!
//! assert_eq!(sig.v(), 0);
//! ```
//!
//! [EIP-7951]: https://eips.ethereum.org/EIPS/eip-7951

use core::fmt;

use alloy_primitives::U256;
use p256::FieldBytes;
use p256::ecdsa::Signature as P256Signature;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// An Ethereum ECDSA signature using the secp256r1 (P-256) curve.
///
/// This signature type is compatible with [EIP-7951], which enables native
/// secp256r1 signature verification on the EVM.
///
/// # Components
///
/// - `r`: 32-byte scalar representing the x-coordinate of the ephemeral point (`1 <= r < N`)
/// - `s`: 32-byte scalar of the signature (`1 <= s < N`)
/// - `v`: Recovery parameter (`0` or `1` for secp256r1)
///
/// # Wire Format
///
/// When serialized for on-chain use, the signature is encoded as 65 bytes:
/// `r (32 bytes) || s (32 bytes) || v (1 byte)`
///
/// [EIP-7951]: https://eips.ethereum.org/EIPS/eip-7951
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawSignature")]
pub struct Signature {
    /// The R component of the signature (32 bytes).
    #[serde(with = "hex_bytes")]
    r: [u8; 32],

    /// The S component of the signature (32 bytes).
    #[serde(with = "hex_bytes")]
    s: [u8; 32],

    /// The recovery parameter (`0` or `1`).
    v: u8,
}

/// Unvalidated intermediate representation used for `Deserialize`.
#[derive(Deserialize)]
struct RawSignature {
    #[serde(with = "hex_bytes")]
    r: [u8; 32],
    #[serde(with = "hex_bytes")]
    s: [u8; 32],
    v: u8,
}

impl TryFrom<RawSignature> for Signature {
    type Error = Error;

    fn try_from(raw: RawSignature) -> Result<Self> {
        Self::new(raw.r, raw.s, raw.v)
    }
}

/// Serde helper for hex encoding/decoding 32-byte arrays.
mod hex_bytes {
    use hex::{decode, encode};
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub(super) fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", encode(bytes)))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(&s);
        let bytes = decode(s).map_err(de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| de::Error::custom("expected 32 bytes"))
    }
}

impl Signature {
    /// The length of a serialized signature in bytes.
    pub const BYTE_LEN: usize = 65;

    /// Creates a new validated signature from raw components.
    ///
    /// # Arguments
    ///
    /// * `r` - The R component as a 32-byte big-endian array (`1 <= r < N`)
    /// * `s` - The S component as a 32-byte big-endian array (`1 <= s < N`)
    /// * `v` - The recovery parameter (`0` or `1`)
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a validated [`Signature`] instance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] if:
    ///
    /// - `r` is zero or `>= N`
    /// - `s` is zero or `>= N`
    /// - `v` is not `0` or `1`
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::Signature;
    ///
    /// let r = [1u8; 32];
    /// let s = [2u8; 32];
    /// let sig = Signature::new(r, s, 0).unwrap();
    /// assert_eq!(sig.v(), 0);
    /// ```
    pub fn new(r: [u8; 32], s: [u8; 32], v: u8) -> Result<Self> {
        if v > 1 {
            return Err(Error::InvalidSignature(format!(
                "invalid recovery parameter v: expected 0 or 1, got {v}"
            )));
        }

        P256Signature::from_scalars(FieldBytes::from(r), FieldBytes::from(s)).map_err(|_| {
            Error::InvalidSignature("signature scalars r and s must be in range 1..N".to_string())
        })?;

        Ok(Self { r, s, v })
    }

    /// Creates a signature from a 65-byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 65-byte slice containing `r || s || v`
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the signature, or an error if the slice is invalid.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] if:
    ///
    /// - The slice is not exactly 65 bytes
    /// - The R component is invalid (`0` or `>= N`)
    /// - The S component is invalid (`0` or `>= N`)
    /// - The recovery parameter is not `0` or `1`
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::Signature;
    ///
    /// let mut bytes = [0u8; 65];
    /// bytes[31] = 1;
    /// bytes[63] = 2;
    /// bytes[64] = 0;
    /// let sig = Signature::from_bytes(&bytes).unwrap();
    /// assert_eq!(sig.v(), 0);
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::BYTE_LEN {
            return Err(Error::InvalidSignature(format!(
                "expected {} bytes, got {}",
                Self::BYTE_LEN,
                bytes.len()
            )));
        }

        let r: [u8; 32] = bytes[0..32]
            .try_into()
            .map_err(|_| Error::InvalidSignature("invalid r component".to_string()))?;
        let s: [u8; 32] = bytes[32..64]
            .try_into()
            .map_err(|_| Error::InvalidSignature("invalid s component".to_string()))?;
        let v = bytes[64];

        Self::new(r, s, v)
    }

    /// Serializes the signature to a 65-byte array.
    ///
    /// # Returns
    ///
    /// A 65-byte array containing `r || s || v`.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::Signature;
    ///
    /// let sig = Signature::new([1u8; 32], [2u8; 32], 0).unwrap();
    /// let bytes = sig.to_bytes();
    /// assert_eq!(bytes.len(), 65);
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::BYTE_LEN] {
        let mut bytes = [0u8; Self::BYTE_LEN];
        bytes[0..32].copy_from_slice(&self.r);
        bytes[32..64].copy_from_slice(&self.s);
        bytes[64] = self.v;
        bytes
    }

    /// Returns the R component of the signature.
    ///
    /// # Returns
    ///
    /// A reference to the 32-byte R component.
    #[must_use]
    pub const fn r(&self) -> &[u8; 32] {
        &self.r
    }

    /// Returns the S component of the signature.
    ///
    /// # Returns
    ///
    /// A reference to the 32-byte S component.
    #[must_use]
    pub const fn s(&self) -> &[u8; 32] {
        &self.s
    }

    /// Returns the recovery parameter (`v`).
    ///
    /// # Returns
    ///
    /// The recovery parameter (`0` or `1`).
    #[must_use]
    pub const fn v(&self) -> u8 {
        self.v
    }

    /// Returns the R component as a [`U256`].
    ///
    /// # Returns
    ///
    /// The R component as an unsigned 256-bit integer.
    #[must_use]
    pub const fn r_u256(&self) -> U256 {
        U256::from_be_bytes(self.r)
    }

    /// Returns the S component as a [`U256`].
    ///
    /// # Returns
    ///
    /// The S component as an unsigned 256-bit integer.
    #[must_use]
    pub const fn s_u256(&self) -> U256 {
        U256::from_be_bytes(self.s)
    }

    /// Encodes the signature as a hex string with `0x` prefix.
    ///
    /// # Returns
    ///
    /// A hex-encoded [`String`] representation of the signature.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::Signature;
    ///
    /// let sig = Signature::new([1u8; 32], [2u8; 32], 0).unwrap();
    /// let hex = sig.to_hex();
    /// assert!(hex.starts_with("0x"));
    /// assert_eq!(hex.len(), 132); // "0x" + 130 hex chars
    /// ```
    #[must_use]
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }

    /// Parses a signature from a hex string.
    ///
    /// # Arguments
    ///
    /// * `hex_str` - A hex string, optionally prefixed with `0x` or `0X`
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the signature, or an error if parsing fails.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HexDecodeFailed`] if the hex string is invalid, or
    /// [`Error::InvalidSignature`] if the decoded bytes are not a valid 65-byte signature.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::Signature;
    ///
    /// let hex = format!("0x{}{}00", "01".repeat(32), "02".repeat(32));
    /// let sig = Signature::from_hex(&hex).unwrap();
    /// assert_eq!(sig.v(), 0);
    /// ```
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str
            .strip_prefix("0x")
            .or_else(|| hex_str.strip_prefix("0X"))
            .unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P256_N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];

    #[test]
    fn signature_new() {
        let r = [1u8; 32];
        let s = [2u8; 32];
        let v = 1u8;

        let sig = Signature::new(r, s, v).unwrap();

        assert_eq!(sig.r(), &r);
        assert_eq!(sig.s(), &s);
        assert_eq!(sig.v(), v);
    }

    #[test]
    fn signature_new_rejects_invalid_components() {
        let valid = [1u8; 32];

        // Invalid v
        assert!(matches!(
            Signature::new(valid, valid, 2),
            Err(Error::InvalidSignature(_))
        ));
        assert!(matches!(
            Signature::new(valid, valid, 27),
            Err(Error::InvalidSignature(_))
        ));

        // Zero r or s
        assert!(matches!(
            Signature::new([0u8; 32], valid, 0),
            Err(Error::InvalidSignature(_))
        ));
        assert!(matches!(
            Signature::new(valid, [0u8; 32], 0),
            Err(Error::InvalidSignature(_))
        ));

        // r or s >= N
        assert!(matches!(
            Signature::new(P256_N, valid, 0),
            Err(Error::InvalidSignature(_))
        ));
        assert!(matches!(
            Signature::new(valid, P256_N, 1),
            Err(Error::InvalidSignature(_))
        ));
        assert!(matches!(
            Signature::new([0xFF; 32], valid, 0),
            Err(Error::InvalidSignature(_))
        ));
    }

    #[test]
    fn signature_from_bytes() {
        let mut bytes = [0u8; 65];
        bytes[0..32].copy_from_slice(&[1u8; 32]);
        bytes[32..64].copy_from_slice(&[2u8; 32]);
        bytes[64] = 1;

        let sig = Signature::from_bytes(&bytes).unwrap();

        assert_eq!(sig.r(), &[1u8; 32]);
        assert_eq!(sig.s(), &[2u8; 32]);
        assert_eq!(sig.v(), 1);
    }

    #[test]
    fn signature_from_bytes_rejects_invalid() {
        assert!(matches!(
            Signature::from_bytes(&[1u8; 64]),
            Err(Error::InvalidSignature(_))
        ));
        // All zeros rejected
        assert!(matches!(
            Signature::from_bytes(&[0u8; 65]),
            Err(Error::InvalidSignature(_))
        ));
        // Invalid v = 2 rejected
        let mut bad_v = [1u8; 65];
        bad_v[64] = 2;
        assert!(matches!(
            Signature::from_bytes(&bad_v),
            Err(Error::InvalidSignature(_))
        ));
    }

    #[test]
    fn signature_to_bytes_roundtrip() {
        let sig = Signature::new([3u8; 32], [4u8; 32], 0).unwrap();
        let bytes = sig.to_bytes();
        let recovered = Signature::from_bytes(&bytes).unwrap();

        assert_eq!(sig, recovered);
    }

    #[test]
    fn signature_hex_roundtrip_and_prefixes() {
        let sig = Signature::new([5u8; 32], [6u8; 32], 1).unwrap();
        let hex = sig.to_hex();
        assert_eq!(Signature::from_hex(&hex).unwrap(), sig);

        // Uppercase 0X prefix
        let upper_prefix = format!("0X{}", hex.strip_prefix("0x").unwrap());
        assert_eq!(Signature::from_hex(&upper_prefix).unwrap(), sig);

        // No prefix
        let no_prefix = hex.strip_prefix("0x").unwrap();
        assert_eq!(Signature::from_hex(no_prefix).unwrap(), sig);
    }

    #[test]
    fn signature_serde_roundtrip_and_validation() {
        let sig = Signature::new([7u8; 32], [8u8; 32], 1).unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        let parsed: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, sig);

        // Uppercase 0X prefix accepted in JSON
        let upper_json = json.replace("0x", "0X");
        let parsed_upper: Signature = serde_json::from_str(&upper_json).unwrap();
        assert_eq!(parsed_upper, sig);

        // Invalid v rejected by serde
        let bad_v = format!(
            r#"{{"r":"0x{}","s":"0x{}","v":2}}"#,
            "01".repeat(32),
            "02".repeat(32)
        );
        assert!(serde_json::from_str::<Signature>(&bad_v).is_err());

        // Zero r rejected by serde
        let zero_r = format!(
            r#"{{"r":"0x{}","s":"0x{}","v":0}}"#,
            "00".repeat(32),
            "02".repeat(32)
        );
        assert!(serde_json::from_str::<Signature>(&zero_r).is_err());
    }

    #[test]
    fn signature_display() {
        let sig = Signature::new([1u8; 32], [2u8; 32], 0).unwrap();
        let display = format!("{sig}");
        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 132);
    }

    #[test]
    fn signature_r_u256_and_s_u256() {
        let mut r = [0u8; 32];
        r[31] = 1;
        let mut s = [0u8; 32];
        s[31] = 42;
        let sig = Signature::new(r, s, 0).unwrap();

        assert_eq!(sig.r_u256(), U256::from(1));
        assert_eq!(sig.s_u256(), U256::from(42));
    }
}
