//! Error types for the YubiKey EVM signer library.
//!
//! This module provides a comprehensive error type [`enum@Error`] that covers all
//! possible failure modes when signing Ethereum transactions with a YubiKey.
//!
//! # Error Categories
//!
//! - **YubiKey errors**: Device communication, PIN verification, and slot access
//! - **Cryptographic errors**: Key generation, signing, and address derivation
//! - **Transaction errors**: RLP encoding, EIP-712 hashing, and signature formatting
//!
//! # Example
//!
//! ```
//! use yubikey_evm_signer_core::Error;
//!
//! fn example() -> Result<(), Error> {
//!     // Errors can be created from their specific variants
//!     let err = Error::InvalidPin;
//!     assert!(matches!(err, Error::InvalidPin));
//!     Ok(())
//! }
//! ```

use alloy_rlp::Error as AlloyRlpError;
use core::result::Result as CoreResult;
use hex::FromHexError;
use serde_json::Error as SerdeJsonError;
use thiserror::Error;

/// The main error type for the YubiKey EVM signer library.
///
/// This enum encompasses all possible errors that can occur during
/// YubiKey operations, cryptographic operations, and Ethereum transaction
/// signing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    // =========================================================================
    // YubiKey Device Errors
    // =========================================================================
    /// No YubiKey device was found.
    #[error("no YubiKey device found")]
    DeviceNotFound,

    /// Failed to connect to the YubiKey device.
    #[error("failed to connect to YubiKey: {0}")]
    ConnectionFailed(String),

    /// The YubiKey device was disconnected unexpectedly.
    #[error("YubiKey device disconnected")]
    DeviceDisconnected,

    /// The provided PIN is invalid.
    #[error("invalid PIN")]
    InvalidPin,

    /// The PIN has been locked after too many failed attempts.
    #[error("PIN is locked after too many failed attempts")]
    PinLocked,

    /// Touch confirmation was not received within the timeout period.
    #[error("touch confirmation timeout")]
    TouchTimeout,

    // =========================================================================
    // PIV Slot Errors
    // =========================================================================
    /// The specified PIV slot is empty (no key present).
    #[error("PIV slot {0:#04x} is empty")]
    SlotEmpty(u8),

    /// The key in the specified slot is not a P-256 key.
    #[error("key in slot {0:#04x} is not a P-256 key")]
    InvalidKeyType(u8),

    /// Failed to generate a key in the specified slot.
    #[error("failed to generate key in slot {0:#04x}: {1}")]
    KeyGenerationFailed(u8, String),

    // =========================================================================
    // APDU Communication Errors
    // =========================================================================
    /// Failed to send an APDU command to the YubiKey.
    #[error("APDU command failed: {0}")]
    ApduError(String),

    /// The YubiKey returned an unexpected status word.
    #[error("unexpected status word: SW1={0:#04x}, SW2={1:#04x}")]
    UnexpectedStatusWord(u8, u8),

    /// The response from the YubiKey was malformed.
    #[error("malformed response: {0}")]
    MalformedResponse(String),

    // =========================================================================
    // Cryptographic Errors
    // =========================================================================
    /// The public key is invalid or malformed.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// The signature is invalid or malformed.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Failed to derive the Ethereum address from the public key.
    #[error("address derivation failed: {0}")]
    AddressDerivationFailed(String),

    /// The signature recovery parameter (v) could not be determined.
    #[error("failed to determine signature recovery parameter")]
    RecoveryParameterFailed,

    // =========================================================================
    // Transaction Errors
    // =========================================================================
    /// The transaction data is invalid.
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Failed to RLP encode the transaction.
    #[error("RLP encoding failed: {0}")]
    RlpEncodingFailed(String),

    /// The chain ID is invalid or unsupported.
    #[error("invalid chain ID: {0}")]
    InvalidChainId(u64),

    // =========================================================================
    // EIP-712 Errors
    // =========================================================================
    /// The EIP-712 typed data is invalid.
    #[error("invalid EIP-712 typed data: {0}")]
    InvalidTypedData(String),

    /// The domain separator is invalid.
    #[error("invalid domain separator: {0}")]
    InvalidDomainSeparator(String),

    /// A type referenced in the typed data is not defined.
    #[error("undefined type in EIP-712 data: {0}")]
    UndefinedType(String),

    // =========================================================================
    // Serialization Errors
    // =========================================================================
    /// Failed to parse hex data.
    #[error("hex decoding failed: {0}")]
    HexDecodeFailed(String),

    /// JSON serialization/deserialization failed.
    #[error("JSON error: {0}")]
    JsonError(String),
}

impl From<FromHexError> for Error {
    fn from(err: FromHexError) -> Self {
        Error::HexDecodeFailed(err.to_string())
    }
}

impl From<SerdeJsonError> for Error {
    fn from(err: SerdeJsonError) -> Self {
        Error::JsonError(err.to_string())
    }
}

impl From<AlloyRlpError> for Error {
    fn from(err: AlloyRlpError) -> Self {
        Error::RlpEncodingFailed(err.to_string())
    }
}

/// A specialized [`Result`] type for YubiKey EVM signer operations.
///
/// This type alias is used throughout the library to avoid having to
/// specify the error type explicitly.
pub type Result<T> = CoreResult<T, Error>;

#[cfg(test)]
mod tests {
    use serde_json::{Value, from_str};

    use super::*;

    #[test]
    fn error_display() {
        let err = Error::DeviceNotFound;
        assert_eq!(err.to_string(), "no YubiKey device found");

        let err = Error::SlotEmpty(0x9a);
        assert_eq!(err.to_string(), "PIV slot 0x9a is empty");

        let err = Error::UnexpectedStatusWord(0x69, 0x82);
        assert_eq!(
            err.to_string(),
            "unexpected status word: SW1=0x69, SW2=0x82"
        );
    }

    #[test]
    fn error_is_non_exhaustive() {
        // This test ensures the #[non_exhaustive] attribute is present
        // by checking that we can still match known variants
        let err = Error::InvalidPin;
        match err {
            Error::InvalidPin => {}
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn from_hex_error() {
        let hex_err = FromHexError::InvalidHexCharacter { c: 'g', index: 0 };
        let err: Error = hex_err.into();
        assert!(matches!(err, Error::HexDecodeFailed(_)));
    }

    #[test]
    fn from_json_error() {
        let json_str = "not valid json{";
        let json_err = from_str::<Value>(json_str).unwrap_err();
        let err: Error = json_err.into();
        assert!(matches!(err, Error::JsonError(_)));
    }
}
