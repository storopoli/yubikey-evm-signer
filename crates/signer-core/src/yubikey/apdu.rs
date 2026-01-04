//! APDU (Application Protocol Data Unit) command and response types.
//!
//! This module provides types for constructing and parsing ISO 7816-4 APDU
//! commands and responses used to communicate with smart cards.
//!
//! # APDU Command Structure
//!
//! ```text
//! | CLA | INS | P1 | P2 | Lc | Data | Le |
//! |-----|-----|----|----|----|----- |----|
//! | 1B  | 1B  | 1B | 1B | 1B | Var  | 1B |
//! ```
//!
//! - **CLA**: Class byte (instruction class)
//! - **INS**: Instruction byte
//! - **P1, P2**: Parameter bytes
//! - **Lc**: Length of command data
//! - **Data**: Command data
//! - **Le**: Expected response length
//!
//! # APDU Response Structure
//!
//! ```text
//! | Data | SW1 | SW2 |
//! |------|-----|-----|
//! | Var  | 1B  | 1B  |
//! ```
//!
//! - **Data**: Response data
//! - **SW1, SW2**: Status word (indicates success/failure)
//!
//! # Example
//!
//! ```
//! use yubikey_evm_signer_core::yubikey::{Apdu, ApduResponse};
//!
//! // Create a SELECT command for the PIV applet
//! let apdu = Apdu::new(0x00, 0xA4, 0x04, 0x00, vec![
//!     0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00
//! ]);
//!
//! // Serialize to bytes
//! let bytes = apdu.to_bytes();
//! assert!(!bytes.is_empty());
//! ```

use crate::error::{Error, Result};

/// An APDU command.
///
/// Represents an ISO 7816-4 APDU command to be sent to a smart card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Apdu {
    /// Class byte.
    cla: u8,

    /// Instruction byte.
    ins: u8,

    /// Parameter 1.
    p1: u8,

    /// Parameter 2.
    p2: u8,

    /// Command data.
    data: Vec<u8>,

    /// Expected response length (0 = no limit).
    le: u16,
}

impl Apdu {
    /// Maximum short APDU data length.
    pub const MAX_SHORT_DATA: usize = 255;

    /// Creates a new APDU command.
    ///
    /// # Arguments
    ///
    /// * `cla` - Class byte
    /// * `ins` - Instruction byte
    /// * `p1` - Parameter 1
    /// * `p2` - Parameter 2
    /// * `data` - Command data
    ///
    /// # Returns
    ///
    /// A new [`Apdu`] instance with Le set to 0 (expect any length response).
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::yubikey::Apdu;
    ///
    /// let apdu = Apdu::new(0x00, 0xCB, 0x3F, 0xFF, vec![0x5C, 0x03, 0x5F, 0xC1, 0x05]);
    /// ```
    #[must_use]
    pub const fn new(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data,
            le: 0,
        }
    }

    /// Creates a new APDU command with an expected response length.
    ///
    /// # Arguments
    ///
    /// * `cla` - Class byte
    /// * `ins` - Instruction byte
    /// * `p1` - Parameter 1
    /// * `p2` - Parameter 2
    /// * `data` - Command data
    /// * `le` - Expected response length
    ///
    /// # Returns
    ///
    /// A new [`Apdu`] instance.
    #[must_use]
    pub const fn with_le(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>, le: u16) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data,
            le,
        }
    }

    /// Returns the class byte.
    #[must_use]
    pub const fn cla(&self) -> u8 {
        self.cla
    }

    /// Returns the instruction byte.
    #[must_use]
    pub const fn ins(&self) -> u8 {
        self.ins
    }

    /// Returns parameter 1.
    #[must_use]
    pub const fn p1(&self) -> u8 {
        self.p1
    }

    /// Returns parameter 2.
    #[must_use]
    pub const fn p2(&self) -> u8 {
        self.p2
    }

    /// Returns the command data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the expected response length.
    #[must_use]
    pub const fn le(&self) -> u16 {
        self.le
    }

    /// Serializes the APDU to bytes.
    ///
    /// This method encodes the APDU in short form (Lc ≤ 255) or
    /// extended form (Lc > 255) as appropriate.
    ///
    /// # Returns
    ///
    /// The serialized APDU bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::yubikey::Apdu;
    ///
    /// let apdu = Apdu::new(0x00, 0xA4, 0x04, 0x00, vec![0xA0, 0x00]);
    /// let bytes = apdu.to_bytes();
    /// assert_eq!(&bytes[0..4], &[0x00, 0xA4, 0x04, 0x00]);
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(5 + self.data.len() + 3);

        // Header
        bytes.push(self.cla);
        bytes.push(self.ins);
        bytes.push(self.p1);
        bytes.push(self.p2);

        let use_extended = self.data.len() > Self::MAX_SHORT_DATA || self.le > 256;

        if use_extended {
            // Extended APDU
            if !self.data.is_empty() {
                bytes.push(0x00); // Extended Lc marker
                bytes.push((self.data.len() >> 8) as u8);
                bytes.push(self.data.len() as u8);
                bytes.extend_from_slice(&self.data);
            }
            if self.le > 0 {
                if self.data.is_empty() {
                    bytes.push(0x00); // Extended Le marker
                }
                bytes.push((self.le >> 8) as u8);
                bytes.push(self.le as u8);
            }
        } else {
            // Short APDU
            if !self.data.is_empty() {
                bytes.push(self.data.len() as u8);
                bytes.extend_from_slice(&self.data);
            }
            if self.le > 0 {
                bytes.push(if self.le == 256 { 0x00 } else { self.le as u8 });
            }
        }

        bytes
    }
}

/// An APDU response from a smart card.
///
/// Contains the response data and status word indicating success or failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduResponse {
    /// Response data.
    data: Vec<u8>,

    /// Status word 1.
    sw1: u8,

    /// Status word 2.
    sw2: u8,
}

impl ApduResponse {
    /// Success status word (0x9000).
    pub const SW_SUCCESS: u16 = 0x9000;

    /// Creates a new APDU response from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw response bytes (data + SW1 + SW2)
    ///
    /// # Returns
    ///
    /// A new [`ApduResponse`] instance.
    ///
    /// # Panics
    ///
    /// Panics if the response is less than 2 bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::yubikey::ApduResponse;
    ///
    /// let response = ApduResponse::new(vec![0x01, 0x02, 0x90, 0x00]);
    /// assert!(response.is_success());
    /// assert_eq!(response.data(), &[0x01, 0x02]);
    /// ```
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        assert!(bytes.len() >= 2, "APDU response must be at least 2 bytes");

        let len = bytes.len();
        let sw1 = bytes[len - 2];
        let sw2 = bytes[len - 1];
        let data = bytes[..len - 2].to_vec();

        Self { data, sw1, sw2 }
    }

    /// Returns the response data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the response and returns the data.
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Returns status word 1.
    #[must_use]
    pub const fn sw1(&self) -> u8 {
        self.sw1
    }

    /// Returns status word 2.
    #[must_use]
    pub const fn sw2(&self) -> u8 {
        self.sw2
    }

    /// Returns the full status word as a [`u16`].
    #[must_use]
    pub const fn status_word(&self) -> u16 {
        ((self.sw1 as u16) << 8) | (self.sw2 as u16)
    }

    /// Checks if the response indicates success (`SW = 0x9000`).
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status_word() == Self::SW_SUCCESS
    }

    /// Checks if more data is available (`SW1 = 0x61`).
    #[must_use]
    pub const fn has_more_data(&self) -> bool {
        self.sw1 == 0x61
    }

    /// Returns the number of remaining bytes if more data is available.
    #[must_use]
    pub const fn remaining_bytes(&self) -> Option<u8> {
        if self.has_more_data() {
            Some(self.sw2)
        } else {
            None
        }
    }

    /// Checks the response status and returns an error if not successful.
    ///
    /// # Returns
    ///
    /// [`Ok(())`](Ok) if the status word is `0x9000` or indicates more data (`0x61xx`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStatusWord`] if the response indicates failure.
    pub const fn check(&self) -> Result<()> {
        if self.is_success() || self.has_more_data() {
            Ok(())
        } else {
            Err(self.to_error())
        }
    }

    /// Converts the status word to a descriptive error.
    #[must_use]
    pub const fn to_error(&self) -> Error {
        match (self.sw1, self.sw2) {
            (0x63, 0xC0..=0xCF) => {
                let attempts = self.sw2 & 0x0F;
                if attempts == 0 {
                    Error::PinLocked
                } else {
                    Error::InvalidPin
                }
            }
            (0x69, 0x82) => Error::InvalidPin,
            (0x69, 0x83) => Error::PinLocked,
            (0x6A, 0x82) => Error::SlotEmpty(0),
            _ => Error::UnexpectedStatusWord(self.sw1, self.sw2),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apdu_new() {
        let apdu = Apdu::new(0x00, 0xA4, 0x04, 0x00, vec![0xA0, 0x00]);

        assert_eq!(apdu.cla(), 0x00);
        assert_eq!(apdu.ins(), 0xA4);
        assert_eq!(apdu.p1(), 0x04);
        assert_eq!(apdu.p2(), 0x00);
        assert_eq!(apdu.data(), &[0xA0, 0x00]);
        assert_eq!(apdu.le(), 0);
    }

    #[test]
    fn apdu_with_le() {
        let apdu = Apdu::with_le(0x00, 0xCB, 0x3F, 0xFF, vec![0x5C], 256);

        assert_eq!(apdu.le(), 256);
    }

    #[test]
    fn apdu_to_bytes_short() {
        let apdu = Apdu::new(0x00, 0xA4, 0x04, 0x00, vec![0xA0, 0x00]);
        let bytes = apdu.to_bytes();

        assert_eq!(bytes, vec![0x00, 0xA4, 0x04, 0x00, 0x02, 0xA0, 0x00]);
    }

    #[test]
    fn apdu_to_bytes_no_data() {
        let apdu = Apdu::new(0x00, 0xA4, 0x04, 0x00, vec![]);
        let bytes = apdu.to_bytes();

        assert_eq!(bytes, vec![0x00, 0xA4, 0x04, 0x00]);
    }

    #[test]
    fn apdu_to_bytes_with_le() {
        let apdu = Apdu::with_le(0x00, 0xCB, 0x3F, 0xFF, vec![], 256);
        let bytes = apdu.to_bytes();

        // Le = 256 is encoded as 0x00 in short form
        assert_eq!(bytes, vec![0x00, 0xCB, 0x3F, 0xFF, 0x00]);
    }

    #[test]
    fn apdu_response_new() {
        let response = ApduResponse::new(vec![0x01, 0x02, 0x03, 0x90, 0x00]);

        assert_eq!(response.data(), &[0x01, 0x02, 0x03]);
        assert_eq!(response.sw1(), 0x90);
        assert_eq!(response.sw2(), 0x00);
        assert!(response.is_success());
    }

    #[test]
    fn apdu_response_status_word() {
        let response = ApduResponse::new(vec![0x90, 0x00]);

        assert_eq!(response.status_word(), 0x9000);
        assert!(response.is_success());
    }

    #[test]
    fn apdu_response_more_data() {
        let response = ApduResponse::new(vec![0x61, 0x10]);

        assert!(!response.is_success());
        assert!(response.has_more_data());
        assert_eq!(response.remaining_bytes(), Some(0x10));
    }

    #[test]
    fn apdu_response_check_success() {
        let response = ApduResponse::new(vec![0x90, 0x00]);
        assert!(response.check().is_ok());
    }

    #[test]
    fn apdu_response_check_more_data() {
        let response = ApduResponse::new(vec![0x61, 0x20]);
        assert!(response.check().is_ok());
    }

    #[test]
    fn apdu_response_check_error() {
        let response = ApduResponse::new(vec![0x6A, 0x82]);
        assert!(response.check().is_err());
    }

    #[test]
    fn apdu_response_pin_error() {
        let response = ApduResponse::new(vec![0x63, 0xC2]);
        let err = response.to_error();
        assert!(matches!(err, Error::InvalidPin));
    }

    #[test]
    fn apdu_response_pin_locked() {
        let response = ApduResponse::new(vec![0x63, 0xC0]);
        let err = response.to_error();
        assert!(matches!(err, Error::PinLocked));
    }

    #[test]
    fn apdu_response_into_data() {
        let response = ApduResponse::new(vec![0x01, 0x02, 0x90, 0x00]);
        let data = response.into_data();
        assert_eq!(data, vec![0x01, 0x02]);
    }
}
