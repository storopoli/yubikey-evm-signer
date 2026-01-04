//! PIV slot definitions.
//!
//! This module defines the PIV (Personal Identity Verification) slots available
//! on YubiKey devices. Each slot can hold a key pair for different purposes.
//!
//! # Slot Overview
//!
//! | Slot | ID   | Purpose                          |
//! |------|------|----------------------------------|
//! | 9a   | 0x9A | PIV Authentication               |
//! | 9c   | 0x9C | Digital Signature                |
//! | 9d   | 0x9D | Key Management                   |
//! | 9e   | 0x9E | Card Authentication              |
//!
//! For Ethereum signing, slot 9a (Authentication) is typically recommended.
//!
//! # Example
//!
//! ```
//! use yubikey_evm_signer_core::yubikey::Slot;
//!
//! let slot = Slot::Authentication;
//! assert_eq!(slot.id(), 0x9A);
//! ```

use core::fmt;

use serde::{Deserialize, Serialize};

/// A PIV slot on the YubiKey.
///
/// PIV slots are used to store key pairs for different purposes.
/// Each slot has specific characteristics and intended uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Slot {
    /// PIV Authentication slot (`9a`).
    ///
    /// Used for authenticating to systems. This is the recommended slot
    /// for Ethereum key storage as it requires PIN verification before use.
    #[serde(rename = "9a")]
    Authentication = 0x9A,

    /// Digital Signature slot (`9c`).
    ///
    /// Used for document signing. Requires PIN for each use.
    #[serde(rename = "9c")]
    Signature = 0x9C,

    /// Key Management slot (`9d`).
    ///
    /// Used for encryption/decryption operations.
    #[serde(rename = "9d")]
    KeyManagement = 0x9D,

    /// Card Authentication slot (`9e`).
    ///
    /// Used for card authentication without PIN (e.g., door access).
    /// Not recommended for Ethereum signing due to lack of PIN protection.
    #[serde(rename = "9e")]
    CardAuthentication = 0x9E,
}

impl Slot {
    /// Returns the slot ID byte.
    ///
    /// # Returns
    ///
    /// The slot identifier as used in PIV APDU commands.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::yubikey::Slot;
    ///
    /// assert_eq!(Slot::Authentication.id(), 0x9A);
    /// assert_eq!(Slot::Signature.id(), 0x9C);
    /// ```
    #[must_use]
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Returns the object ID for retrieving the certificate/public key.
    ///
    /// # Returns
    ///
    /// The 3-byte object ID used in `GET DATA` commands.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::yubikey::Slot;
    ///
    /// let oid = Slot::Authentication.object_id();
    /// assert_eq!(oid, [0x5F, 0xC1, 0x05]);
    /// ```
    #[must_use]
    pub const fn object_id(self) -> [u8; 3] {
        match self {
            Self::Authentication => [0x5F, 0xC1, 0x05],
            Self::Signature => [0x5F, 0xC1, 0x0A],
            Self::KeyManagement => [0x5F, 0xC1, 0x0B],
            Self::CardAuthentication => [0x5F, 0xC1, 0x01],
        }
    }

    /// Returns a human-readable name for the slot.
    ///
    /// # Returns
    ///
    /// A string describing the slot's purpose.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::yubikey::Slot;
    ///
    /// assert_eq!(Slot::Authentication.name(), "Authentication (9a)");
    /// ```
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Authentication => "Authentication (9a)",
            Self::Signature => "Digital Signature (9c)",
            Self::KeyManagement => "Key Management (9d)",
            Self::CardAuthentication => "Card Authentication (9e)",
        }
    }

    /// Checks if this slot requires PIN verification for signing.
    ///
    /// # Returns
    ///
    /// `true` if PIN is required, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::yubikey::Slot;
    ///
    /// assert!(Slot::Authentication.requires_pin());
    /// assert!(!Slot::CardAuthentication.requires_pin());
    /// ```
    #[must_use]
    pub const fn requires_pin(self) -> bool {
        !matches!(self, Self::CardAuthentication)
    }

    /// Checks if this slot is recommended for Ethereum signing.
    ///
    /// Returns `true` for slots that require PIN protection.
    ///
    /// # Returns
    ///
    /// `true` if recommended for Ethereum, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::yubikey::Slot;
    ///
    /// assert!(Slot::Authentication.recommended_for_ethereum());
    /// assert!(!Slot::CardAuthentication.recommended_for_ethereum());
    /// ```
    #[must_use]
    pub const fn recommended_for_ethereum(self) -> bool {
        self.requires_pin()
    }

    /// Creates a slot from its ID byte.
    ///
    /// # Arguments
    ///
    /// * `id` - The slot ID byte
    ///
    /// # Returns
    ///
    /// [`Some(Slot)`](Some) if the ID is valid, [`None`] otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::yubikey::Slot;
    ///
    /// assert_eq!(Slot::from_id(0x9A), Some(Slot::Authentication));
    /// assert_eq!(Slot::from_id(0xFF), None);
    /// ```
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x9A => Some(Self::Authentication),
            0x9C => Some(Self::Signature),
            0x9D => Some(Self::KeyManagement),
            0x9E => Some(Self::CardAuthentication),
            _ => None,
        }
    }

    /// Returns all available slots.
    ///
    /// # Returns
    ///
    /// An array of all PIV slots.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::yubikey::Slot;
    ///
    /// let slots = Slot::all();
    /// assert_eq!(slots.len(), 4);
    /// ```
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::Authentication,
            Self::Signature,
            Self::KeyManagement,
            Self::CardAuthentication,
        ]
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl TryFrom<u8> for Slot {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_id(value).ok_or(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_id() {
        assert_eq!(Slot::Authentication.id(), 0x9A);
        assert_eq!(Slot::Signature.id(), 0x9C);
        assert_eq!(Slot::KeyManagement.id(), 0x9D);
        assert_eq!(Slot::CardAuthentication.id(), 0x9E);
    }

    #[test]
    fn slot_object_id() {
        assert_eq!(Slot::Authentication.object_id(), [0x5F, 0xC1, 0x05]);
        assert_eq!(Slot::Signature.object_id(), [0x5F, 0xC1, 0x0A]);
    }

    #[test]
    fn slot_from_id() {
        assert_eq!(Slot::from_id(0x9A), Some(Slot::Authentication));
        assert_eq!(Slot::from_id(0x9C), Some(Slot::Signature));
        assert_eq!(Slot::from_id(0x9D), Some(Slot::KeyManagement));
        assert_eq!(Slot::from_id(0x9E), Some(Slot::CardAuthentication));
        assert_eq!(Slot::from_id(0xFF), None);
    }

    #[test]
    fn slot_requires_pin() {
        assert!(Slot::Authentication.requires_pin());
        assert!(Slot::Signature.requires_pin());
        assert!(Slot::KeyManagement.requires_pin());
        assert!(!Slot::CardAuthentication.requires_pin());
    }

    #[test]
    fn slot_recommended_for_ethereum() {
        assert!(Slot::Authentication.recommended_for_ethereum());
        assert!(Slot::Signature.recommended_for_ethereum());
        assert!(!Slot::CardAuthentication.recommended_for_ethereum());
    }

    #[test]
    fn slot_all() {
        let slots = Slot::all();
        assert_eq!(slots.len(), 4);
        assert!(slots.contains(&Slot::Authentication));
    }

    #[test]
    fn slot_display() {
        assert_eq!(format!("{}", Slot::Authentication), "Authentication (9a)");
    }

    #[test]
    fn slot_try_from() {
        assert_eq!(Slot::try_from(0x9A), Ok(Slot::Authentication));
        assert_eq!(Slot::try_from(0xFF), Err(()));
    }
}
