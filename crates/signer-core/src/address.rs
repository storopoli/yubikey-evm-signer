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
//! # Not a secp256k1 account
//!
//! An address derived from a P-256 key identifies that key; it is **not** an
//! externally owned account. Ethereum mainnet and standard EVM chains validate
//! transaction signatures with secp256k1 `ecrecover`, so P-256 signatures never
//! recover to this address there, and anything sent to it on such chains cannot
//! be spent with the YubiKey key. Verifiers using the [EIP-7951] `P256VERIFY`
//! precompile need the public key `(qx, qy)` itself, not this address.
//!
//! [EIP-7951]: https://eips.ethereum.org/EIPS/eip-7951
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
use p256::Sec1Point;
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

    /// Derives an Ethereum-style address from a secp256r1 public key.
    ///
    /// The result is `keccak256(X‖Y)[12..]`, a stable identifier of the P-256
    /// key. It is not a secp256k1 externally owned account: standard EVM chains
    /// will not accept P-256 transaction signatures from it, and funds sent to it
    /// there cannot be spent with this key (see the [module docs](crate::address)).
    ///
    /// This function takes a P-256 verifying key (public key) and derives
    /// the address by:
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
        let encoded = public_key.to_sec1_point(false);
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

    /// Derives an Ethereum-style address from encoded P-256 public key bytes.
    ///
    /// Validates that the bytes encode a valid non-identity point on the NIST P-256
    /// curve before deriving the address from its uncompressed coordinates. Like
    /// [`Self::from_public_key`], the result identifies the P-256 key and is not a
    /// secp256k1 account.
    ///
    /// # Arguments
    ///
    /// * `bytes` - One of:
    ///   - 64 bytes: raw uncompressed coordinates (`x || y`)
    ///   - 65 bytes: SEC1 uncompressed point (`0x04 || x || y`)
    ///   - 33 bytes: SEC1 compressed point (`0x02 || x` or `0x03 || x`)
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the derived [`Address`], or an error if the bytes
    /// do not represent a valid P-256 public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if:
    /// - The byte length is not 33, 64, or 65
    /// - The SEC1 tag prefix does not match the length
    /// - The point is not on the NIST P-256 curve or is the point at infinity
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::Address;
    ///
    /// // NIST P-256 generator point G (64-byte raw x || y)
    /// let pubkey_bytes = hex::decode(concat!(
    ///     "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    ///     "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    /// ))
    /// .unwrap();
    /// let addr = Address::from_public_key_bytes(&pubkey_bytes).unwrap();
    /// assert!(!addr.is_zero());
    /// ```
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self> {
        let point = match bytes.len() {
            64 => {
                let mut uncompressed = [0u8; 65];
                uncompressed[0] = 0x04;
                uncompressed[1..].copy_from_slice(bytes);
                Sec1Point::from_bytes(&uncompressed).map_err(|_| {
                    Error::InvalidPublicKey("invalid 64-byte P-256 public key".to_string())
                })?
            }
            65 => {
                if bytes[0] != 0x04 {
                    return Err(Error::InvalidPublicKey(
                        "65-byte public key must start with 0x04".to_string(),
                    ));
                }
                Sec1Point::from_bytes(bytes).map_err(|_| {
                    Error::InvalidPublicKey("invalid 65-byte P-256 public key".to_string())
                })?
            }
            33 => {
                if bytes[0] != 0x02 && bytes[0] != 0x03 {
                    return Err(Error::InvalidPublicKey(
                        "33-byte compressed public key must start with 0x02 or 0x03".to_string(),
                    ));
                }
                Sec1Point::from_bytes(bytes).map_err(|_| {
                    Error::InvalidPublicKey("invalid 33-byte compressed P-256 public key".into())
                })?
            }
            len => {
                return Err(Error::InvalidPublicKey(format!(
                    "expected 33, 64, or 65 bytes, got {len}"
                )));
            }
        };

        let verifying_key = VerifyingKey::from_sec1_point(&point).map_err(|_| {
            Error::InvalidPublicKey("public key is not a valid NIST P-256 curve point".to_string())
        })?;

        Ok(Self::from_public_key(&verifying_key))
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
    /// * `hex_str` - A hex string, optionally prefixed with `0x` or `0X`
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`Address`], or an error if parsing fails.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HexDecodeFailed`] if the hex string is invalid, or
    /// [`Error::AddressDerivationFailed`] if the decoded bytes are not 20 bytes.
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
        let hex_str = hex_str
            .strip_prefix("0x")
            .or_else(|| hex_str.strip_prefix("0X"))
            .unwrap_or(hex_str);
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

    /// NIST P-256 generator point G (64-byte raw x || y).
    const P256_G_RAW_HEX: &str = concat!(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    );

    /// NIST P-256 generator point G compressed (Gy is odd -> prefix 0x03).
    const P256_G_COMPRESSED_HEX: &str =
        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";

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
    fn address_from_public_key_bytes_all_valid_encodings() {
        let raw_64 = hex::decode(P256_G_RAW_HEX).unwrap();
        let mut uncompressed_65 = vec![0x04];
        uncompressed_65.extend_from_slice(&raw_64);
        let compressed_33 = hex::decode(P256_G_COMPRESSED_HEX).unwrap();

        let addr_64 = Address::from_public_key_bytes(&raw_64).unwrap();
        let addr_65 = Address::from_public_key_bytes(&uncompressed_65).unwrap();
        let addr_33 = Address::from_public_key_bytes(&compressed_33).unwrap();

        assert_eq!(addr_64, addr_65);
        assert_eq!(addr_64, addr_33);

        // Verify the address matches keccak256(x || y)[12..]
        let expected_hash = keccak256(&raw_64);
        let expected_addr: [u8; 20] = expected_hash[12..].try_into().unwrap();
        assert_eq!(addr_64.to_bytes(), expected_addr);
    }

    #[test]
    fn address_from_public_key_bytes_rejects_invalid_points() {
        // All-zero point (not on P-256 curve)
        assert!(matches!(
            Address::from_public_key_bytes(&[0u8; 64]),
            Err(Error::InvalidPublicKey(_))
        ));

        // 65-byte all-zero with 0x04 prefix (not on curve)
        let mut zero_65 = [0u8; 65];
        zero_65[0] = 0x04;
        assert!(matches!(
            Address::from_public_key_bytes(&zero_65),
            Err(Error::InvalidPublicKey(_))
        ));

        // Mutated y-coordinate (off curve)
        let mut off_curve = hex::decode(P256_G_RAW_HEX).unwrap();
        off_curve[63] ^= 0x01;
        assert!(matches!(
            Address::from_public_key_bytes(&off_curve),
            Err(Error::InvalidPublicKey(_))
        ));

        // Wrong 65-byte prefix
        let mut bad_prefix = vec![0x02];
        bad_prefix.extend_from_slice(&hex::decode(P256_G_RAW_HEX).unwrap());
        assert!(matches!(
            Address::from_public_key_bytes(&bad_prefix),
            Err(Error::InvalidPublicKey(_))
        ));

        // Wrong 33-byte prefix
        let mut bad_compressed = hex::decode(P256_G_COMPRESSED_HEX).unwrap();
        bad_compressed[0] = 0x04;
        assert!(matches!(
            Address::from_public_key_bytes(&bad_compressed),
            Err(Error::InvalidPublicKey(_))
        ));

        // Wrong length
        assert!(matches!(
            Address::from_public_key_bytes(&[0u8; 63]),
            Err(Error::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn address_hex_roundtrip_and_prefixes() {
        let original = Address::new([0xab; 20]);
        let hex = original.to_hex();
        assert_eq!(Address::from_hex(&hex).unwrap(), original);

        let upper_prefix = format!("0X{}", hex.strip_prefix("0x").unwrap());
        assert_eq!(Address::from_hex(&upper_prefix).unwrap(), original);

        let no_prefix = hex.strip_prefix("0x").unwrap();
        assert_eq!(Address::from_hex(no_prefix).unwrap(), original);

        // Wrong length returns AddressDerivationFailed
        assert!(matches!(
            Address::from_hex("0xdeadbeef"),
            Err(Error::AddressDerivationFailed(_))
        ));
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

        // Exact EIP-55 test vector
        assert_eq!(checksum, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }
}
