//! Ethereum signature types for secp256r1 (P-256) ECDSA.
//!
//! This module provides the [`Signature`] type that represents an Ethereum-compatible
//! ECDSA signature using the secp256r1 (NIST P-256) curve as specified in [EIP-7951].
//!
//! # Signature Format
//!
//! Ethereum signatures consist of three components:
//!
//! - `r`: The x-coordinate of the ephemeral public key (32 bytes)
//! - `s`: The signature scalar (32 bytes)
//! - `v`: The recovery parameter (1 byte, typically 0 or 1 for EIP-7951)
//!
//! # Example
//!
//! ```
//! use yubikey_evm_signer_core::Signature;
//!
//! // Create a signature from raw bytes
//! let r = [0u8; 32];
//! let s = [0u8; 32];
//! let v = 0u8;
//! let sig = Signature::new(r, s, v);
//!
//! assert_eq!(sig.v(), 0);
//! ```
//!
//! [EIP-7951]: https://eips.ethereum.org/EIPS/eip-7951

use core::fmt;

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// An Ethereum ECDSA signature using the secp256r1 (P-256) curve.
///
/// This signature type is compatible with [EIP-7951], which enables native
/// secp256r1 signature verification on the EVM.
///
/// # Components
///
/// - `r`: 32-byte scalar representing the x-coordinate of the ephemeral point
/// - `s`: 32-byte scalar of the signature
/// - `v`: Recovery parameter (`0` or `1` for secp256r1)
///
/// # Wire Format
///
/// When serialized for on-chain use, the signature is encoded as 65 bytes:
/// `r (32 bytes) || s (32 bytes) || v (1 byte)`
///
/// [EIP-7951]: https://eips.ethereum.org/EIPS/eip-7951
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = decode(s).map_err(de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| de::Error::custom("expected 32 bytes"))
    }
}

impl Signature {
    /// The length of a serialized signature in bytes.
    pub const BYTE_LEN: usize = 65;

    /// Creates a new signature from raw components.
    ///
    /// # Arguments
    ///
    /// * `r` - The R component as a 32-byte array
    /// * `s` - The S component as a 32-byte array
    /// * `v` - The recovery parameter (should be `0` or `1`)
    ///
    /// # Returns
    ///
    /// A new [`Signature`] instance.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::Signature;
    ///
    /// let r = [1u8; 32];
    /// let s = [2u8; 32];
    /// let sig = Signature::new(r, s, 0);
    /// ```
    #[must_use]
    pub const fn new(r: [u8; 32], s: [u8; 32], v: u8) -> Self {
        Self { r, s, v }
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
    /// - The R component is invalid
    /// - The S component is invalid
    /// - The recovery parameter is not `0` or `1`
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::Signature;
    ///
    /// let bytes = [0u8; 65];
    /// let sig = Signature::from_bytes(&bytes).unwrap();
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

        Ok(Self::new(r, s, v))
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
    /// let sig = Signature::new([1u8; 32], [2u8; 32], 0);
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

    /// Returns the recovery parameter (v).
    ///
    /// # Returns
    ///
    /// The recovery parameter, typically 0 or 1 for secp256r1 signatures.
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
    /// let sig = Signature::new([0u8; 32], [0u8; 32], 0);
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
    /// * `hex_str` - A hex string, optionally prefixed with `0x`
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the signature, or an error if parsing fails.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HexDecodeFailed`] if the hex string is invalid, or
    /// [`Error::InvalidSignature`] if the decoded bytes are not 65 bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::Signature;
    ///
    /// let hex = "0x".to_string() + &"00".repeat(65);
    /// let sig = Signature::from_hex(&hex).unwrap();
    /// ```
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
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

    #[test]
    fn signature_new() {
        let r = [1u8; 32];
        let s = [2u8; 32];
        let v = 1u8;

        let sig = Signature::new(r, s, v);

        assert_eq!(sig.r(), &r);
        assert_eq!(sig.s(), &s);
        assert_eq!(sig.v(), v);
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
    fn signature_from_bytes_invalid_length() {
        let bytes = [0u8; 64];
        let result = Signature::from_bytes(&bytes);
        assert!(matches!(result, Err(Error::InvalidSignature(_))));
    }

    #[test]
    fn signature_to_bytes_roundtrip() {
        let sig = Signature::new([3u8; 32], [4u8; 32], 0);
        let bytes = sig.to_bytes();
        let recovered = Signature::from_bytes(&bytes).unwrap();

        assert_eq!(sig, recovered);
    }

    #[test]
    fn signature_hex_roundtrip() {
        let sig = Signature::new([5u8; 32], [6u8; 32], 1);
        let hex = sig.to_hex();
        let recovered = Signature::from_hex(&hex).unwrap();

        assert_eq!(sig, recovered);
    }

    #[test]
    fn signature_hex_without_prefix() {
        let sig = Signature::new([0u8; 32], [0u8; 32], 0);
        let hex = sig.to_hex();
        let hex_no_prefix = hex.strip_prefix("0x").unwrap();
        let recovered = Signature::from_hex(hex_no_prefix).unwrap();

        assert_eq!(sig, recovered);
    }

    #[test]
    fn signature_display() {
        let sig = Signature::new([0u8; 32], [0u8; 32], 0);
        let display = format!("{sig}");
        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 132);
    }

    #[test]
    fn signature_r_u256() {
        let mut r = [0u8; 32];
        r[31] = 1;
        let sig = Signature::new(r, [0u8; 32], 0);

        assert_eq!(sig.r_u256(), U256::from(1));
    }

    #[test]
    fn signature_s_u256() {
        let mut s = [0u8; 32];
        s[31] = 42;
        let sig = Signature::new([0u8; 32], s, 0);

        assert_eq!(sig.s_u256(), U256::from(42));
    }
}
