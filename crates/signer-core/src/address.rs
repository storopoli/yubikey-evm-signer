//! Ethereum address derivation from secp256r1 public keys.
//!
//! This module provides functionality to derive Ethereum addresses from
//! secp256r1 (NIST P-256) public keys. The derivation process follows
//! the standard Ethereum address computation:
//!
//! 1. Take the uncompressed public key (65 bytes: `0x04 || x || y`)
//! 2. Remove the `0x04` prefix to get 64 bytes (`x || y`)
//! 3. Compute the Keccak-256 hash of the 64 bytes
//! 4. Take the last 20 bytes of the hash as the address
//!
//! # Example
//!
//! ```
//! use yubikey_evm_signer_core::Address;
//!
//! // Zero address for demonstration
//! let addr = Address::zero();
//! assert!(addr.is_zero());
//! ```

use std::fmt;

use alloy_primitives::{Address as AlloyAddress, keccak256};
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// An Ethereum address (20 bytes).
///
/// This is a wrapper around [`alloy_primitives::Address`] that provides
/// additional methods for working with addresses derived from secp256r1
/// public keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Address(AlloyAddress);

impl Address {
    /// The length of an Ethereum address in bytes.
    pub const BYTE_LEN: usize = 20;

    /// Creates a new address from a 20-byte array.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 20-byte array representing the address
    ///
    /// # Returns
    ///
    /// A new [`Address`] instance.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::Address;
    ///
    /// let bytes = [0u8; 20];
    /// let addr = Address::new(bytes);
    /// ```
    #[must_use]
    pub const fn new(bytes: [u8; Self::BYTE_LEN]) -> Self {
        Self(AlloyAddress::new(bytes))
    }

    /// Returns the zero address (`0x0000...0000`).
    ///
    /// # Returns
    ///
    /// The zero address.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::Address;
    ///
    /// let zero = Address::zero();
    /// assert!(zero.is_zero());
    /// ```
    #[must_use]
    pub const fn zero() -> Self {
        Self(AlloyAddress::ZERO)
    }

    /// Checks if this is the zero address.
    ///
    /// # Returns
    ///
    /// `true` if this is the zero address, `false` otherwise.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Derives an Ethereum address from a secp256r1 public key.
    ///
    /// This function takes a P-256 verifying key (public key) and derives
    /// the corresponding Ethereum address by:
    ///
    /// 1. Encoding the public key as an uncompressed SEC1 point (65 bytes)
    /// 2. Removing the `0x04` prefix to get the raw x and y coordinates (64 bytes)
    /// 3. Computing the Keccak-256 hash of the 64 bytes
    /// 4. Taking the last 20 bytes as the address
    ///
    /// # Arguments
    ///
    /// * `public_key` - A reference to a P-256 verifying key
    ///
    /// # Returns
    ///
    /// The derived Ethereum [`Address`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// use p256::ecdsa::VerifyingKey;
    /// use yubikey_evm_signer_core::Address;
    ///
    /// // Assuming you have a verifying key from somewhere
    /// let public_key: VerifyingKey = /* ... */;
    /// let address = Address::from_public_key(&public_key);
    /// ```
    #[must_use]
    pub fn from_public_key(public_key: &VerifyingKey) -> Self {
        // Get the uncompressed public key (65 bytes: 0x04 || x || y)
        let encoded = public_key.to_encoded_point(false);
        let uncompressed = encoded.as_bytes();

        // Remove the 0x04 prefix to get just the x and y coordinates (64 bytes)
        let pubkey_bytes = &uncompressed[1..];

        // Compute Keccak-256 hash of the 64 bytes
        let hash = keccak256(pubkey_bytes);

        // Take the last 20 bytes as the address
        let mut address_bytes = [0u8; Self::BYTE_LEN];
        address_bytes.copy_from_slice(&hash[12..]);

        Self::new(address_bytes)
    }

    /// Derives an Ethereum address from raw uncompressed public key bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Either 65 bytes (`0x04 || x || y`) or 64 bytes (`x || y`)
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the derived [`Address`], or an error if the bytes are invalid.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if:
    /// - The byte length is not 64 or 65
    /// - For 65-byte input, the first byte is not `0x04`
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::Address;
    ///
    /// // 64-byte public key (x || y coordinates)
    /// let pubkey_bytes = [0u8; 64];
    /// let addr = Address::from_public_key_bytes(&pubkey_bytes).unwrap();
    /// ```
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self> {
        let pubkey_bytes = match bytes.len() {
            64 => bytes,
            65 => {
                if bytes[0] != 0x04 {
                    return Err(Error::InvalidPublicKey(
                        "65-byte public key must start with 0x04".to_string(),
                    ));
                }
                &bytes[1..]
            }
            len => {
                return Err(Error::InvalidPublicKey(format!(
                    "expected 64 or 65 bytes, got {len}"
                )));
            }
        };

        // Compute Keccak-256 hash
        let hash = keccak256(pubkey_bytes);

        // Take the last 20 bytes
        let mut address_bytes = [0u8; Self::BYTE_LEN];
        address_bytes.copy_from_slice(&hash[12..]);

        Ok(Self::new(address_bytes))
    }

    /// Returns the [`Address`] as a byte slice.
    ///
    /// # Returns
    ///
    /// A reference to the 20-byte address.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Self::BYTE_LEN] {
        self.0.as_ref()
    }

    /// Returns the [`Address`] as a 20-byte array.
    ///
    /// # Returns
    ///
    /// A copy of the 20-byte address.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; Self::BYTE_LEN] {
        self.0.0.0
    }

    /// Returns the [`Address`] as a checksummed hex string.
    ///
    /// Uses EIP-55 mixed-case checksum encoding.
    ///
    /// # Returns
    ///
    /// A checksummed hex string with `0x` prefix.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::Address;
    ///
    /// let addr = Address::zero();
    /// let hex = addr.to_checksum_hex();
    /// assert!(hex.starts_with("0x"));
    /// ```
    #[must_use]
    pub fn to_checksum_hex(&self) -> String {
        self.0.to_checksum(None)
    }

    /// Returns the [`Address`] as a lowercase hex string.
    ///
    /// # Returns
    ///
    /// A lowercase hex string with `0x` prefix.
    #[must_use]
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.as_bytes()))
    }

    /// Parses an [`Address`] from a hex string.
    ///
    /// # Arguments
    ///
    /// * `hex_str` - A hex string, optionally prefixed with `0x`
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`Address`], or an error if parsing fails.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HexDecodeFailed`] if the hex string is invalid, or
    /// [`Error::InvalidPublicKey`] if the decoded bytes are not 20 bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::Address;
    ///
    /// let addr = Address::from_hex("0x0000000000000000000000000000000000000000").unwrap();
    /// assert!(addr.is_zero());
    /// ```
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)?;

        if bytes.len() != Self::BYTE_LEN {
            return Err(Error::AddressDerivationFailed(format!(
                "expected {} bytes, got {}",
                Self::BYTE_LEN,
                bytes.len()
            )));
        }

        let mut address_bytes = [0u8; Self::BYTE_LEN];
        address_bytes.copy_from_slice(&bytes);
        Ok(Self::new(address_bytes))
    }

    /// Returns the inner [`alloy_primitives::Address`].
    ///
    /// # Returns
    ///
    /// The underlying alloy address type.
    #[must_use]
    pub const fn inner(&self) -> AlloyAddress {
        self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_checksum_hex())
    }
}

impl From<AlloyAddress> for Address {
    fn from(addr: AlloyAddress) -> Self {
        Self(addr)
    }
}

impl From<Address> for AlloyAddress {
    fn from(addr: Address) -> Self {
        addr.0
    }
}

impl From<[u8; 20]> for Address {
    fn from(bytes: [u8; 20]) -> Self {
        Self::new(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_new() {
        let bytes = [1u8; 20];
        let addr = Address::new(bytes);
        assert_eq!(addr.as_bytes(), &bytes);
    }

    #[test]
    fn address_zero() {
        let zero = Address::zero();
        assert!(zero.is_zero());
        assert_eq!(zero.as_bytes(), &[0u8; 20]);
    }

    #[test]
    fn address_from_public_key_bytes_64() {
        // 64-byte public key (x || y)
        let pubkey_bytes = [0u8; 64];
        let addr = Address::from_public_key_bytes(&pubkey_bytes).unwrap();

        // Verify the hash is computed correctly
        let expected_hash = keccak256(pubkey_bytes);
        let expected_addr: [u8; 20] = expected_hash[12..].try_into().unwrap();
        assert_eq!(addr.to_bytes(), expected_addr);
    }

    #[test]
    fn address_from_public_key_bytes_65() {
        // 65-byte public key (0x04 || x || y)
        let mut pubkey_bytes = [0u8; 65];
        pubkey_bytes[0] = 0x04;

        let addr = Address::from_public_key_bytes(&pubkey_bytes).unwrap();

        // Should be the same as deriving from 64 bytes
        let addr_64 = Address::from_public_key_bytes(&[0u8; 64]).unwrap();
        assert_eq!(addr, addr_64);
    }

    #[test]
    fn address_from_public_key_bytes_invalid_prefix() {
        let mut pubkey_bytes = [0u8; 65];
        pubkey_bytes[0] = 0x02; // Wrong prefix

        let result = Address::from_public_key_bytes(&pubkey_bytes);
        assert!(matches!(result, Err(Error::InvalidPublicKey(_))));
    }

    #[test]
    fn address_from_public_key_bytes_invalid_length() {
        let pubkey_bytes = [0u8; 63];
        let result = Address::from_public_key_bytes(&pubkey_bytes);
        assert!(matches!(result, Err(Error::InvalidPublicKey(_))));
    }

    #[test]
    fn address_hex_roundtrip() {
        let original = Address::new([0xab; 20]);
        let hex = original.to_hex();
        let recovered = Address::from_hex(&hex).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn address_from_hex_without_prefix() {
        let addr = Address::new([0xcd; 20]);
        let hex = addr.to_hex();
        let hex_no_prefix = hex.strip_prefix("0x").unwrap();
        let recovered = Address::from_hex(hex_no_prefix).unwrap();
        assert_eq!(addr, recovered);
    }

    #[test]
    fn address_display() {
        let addr = Address::zero();
        let display = format!("{addr}");
        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 42); // "0x" + 40 hex chars
    }

    #[test]
    fn address_from_alloy() {
        let alloy_addr = AlloyAddress::ZERO;
        let addr: Address = alloy_addr.into();
        assert!(addr.is_zero());
    }

    #[test]
    fn address_into_alloy() {
        let addr = Address::zero();
        let alloy_addr: AlloyAddress = addr.into();
        assert!(alloy_addr.is_zero());
    }

    #[test]
    fn address_checksum() {
        // Known checksum address test
        let bytes = hex::decode("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
            .unwrap()
            .try_into()
            .unwrap();
        let addr = Address::new(bytes);
        let checksum = addr.to_checksum_hex();

        // EIP-55 checksum should preserve mixed case
        assert!(checksum.contains(|c: char| c.is_ascii_uppercase()));
    }
}
