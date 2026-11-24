//! APDU (Application Protocol Data Unit) command and response types.
//!
//! This module provides types for constructing and parsing ISO 7816-4 APDU
//! commands and responses used to communicate with smart cards.
//!
//! # APDU Command Structure
//!
//! ```text
//! | CLA | INS | P1 | P2 | Lc | Data | Le |
//! |-----|-----|----|----|----|------|----|
//! | 1B  | 1B  | 1B | 1B | Var| Var  | Var|
//! ```
//!
//! - **CLA**: Class byte (instruction class)
//! - **INS**: Instruction byte
//! - **P1, P2**: Parameter bytes
//! - **Lc**: Length of command data
//! - **Data**: Command data
//! - **Le**: Expected response length (optional)
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
//! use yubikey_evm_signer_core::yubikey::Apdu;
//!
//! // Create a SELECT command for the PIV applet
//! let apdu = Apdu::new(0x00, 0xA4, 0x04, 0x00, vec![
//!     0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00
//! ]);
//!
//! // Serialize to bytes
//! let bytes = apdu.to_bytes().unwrap();
//! assert!(!bytes.is_empty());
//! ```

use core::fmt;

use zeroize::Zeroize;

use super::slot::Slot;
use crate::error::{Error, Result};

/// An APDU command.
///
/// Represents an ISO 7816-4 APDU command to be sent to a smart card.
///
/// The [`Debug`](fmt::Debug) implementation never prints the command data (which
/// may carry a PIN or management key authentication material), only its length.
#[derive(Clone, PartialEq, Eq)]
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

    /// Optional expected response length (`1..=65536`).
    ///
    /// `None` omits the `Le` field entirely. `Some(256)` encodes as short `0x00`,
    /// and `Some(65536)` encodes as extended `0x00 0x00`.
    le: Option<u32>,
}

impl Apdu {
    /// Maximum short APDU data length (255 bytes).
    pub const MAX_SHORT_DATA: usize = 255;

    /// Maximum extended APDU data length (65,535 bytes).
    pub const MAX_EXTENDED_DATA: usize = 65_535;

    /// Maximum short APDU expected response length (256 bytes, encoded as `0x00`).
    pub const MAX_SHORT_LE: u32 = 256;

    /// Maximum extended APDU expected response length (65,536 bytes, encoded as `0x00 0x00`).
    pub const MAX_EXTENDED_LE: u32 = 65_536;

    /// Creates a new APDU command without an `Le` field.
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
    /// A new [`Apdu`] instance with `le` set to `None`.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::yubikey::Apdu;
    ///
    /// let apdu = Apdu::new(0x00, 0xCB, 0x3F, 0xFF, vec![0x5C, 0x03, 0x5F, 0xC1, 0x05]);
    /// assert_eq!(apdu.le(), None);
    /// ```
    #[must_use]
    pub const fn new(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data,
            le: None,
        }
    }

    /// Creates a new APDU command with an expected response length (`Le`).
    ///
    /// # Arguments
    ///
    /// * `cla` - Class byte
    /// * `ins` - Instruction byte
    /// * `p1` - Parameter 1
    /// * `p2` - Parameter 2
    /// * `data` - Command data
    /// * `le` - Expected response length (`1..=65536`; `256` encodes as short `0x00`,
    ///   `65536` encodes as extended `0x00 0x00`)
    ///
    /// # Returns
    ///
    /// A new [`Apdu`] instance.
    #[must_use]
    pub const fn with_le(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>, le: u32) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data,
            le: Some(le),
        }
    }

    /// Creates a new APDU command with an optional expected response length (`Le`).
    #[must_use]
    pub const fn with_optional_le(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: Vec<u8>,
        le: Option<u32>,
    ) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data,
            le,
        }
    }

    /// Returns a cloned copy of this APDU with a replaced `Le` value.
    #[must_use]
    pub fn with_le_override(&self, le: Option<u32>) -> Self {
        Self {
            cla: self.cla,
            ins: self.ins,
            p1: self.p1,
            p2: self.p2,
            data: self.data.clone(),
            le,
        }
    }

    /// Zeroizes the command data payload in place (useful for PINs and auth payloads).
    pub fn zeroize_data(&mut self) {
        self.data.zeroize();
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

    /// Returns the optional expected response length.
    #[must_use]
    pub const fn le(&self) -> Option<u32> {
        self.le
    }

    /// Serializes the APDU to ISO 7816-4 bytes.
    ///
    /// Encodes in short form when `data.len() <= 255` and `le <= Some(256)`, or
    /// extended form when `data.len() > 255` or `le > Some(256)`.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the serialized APDU bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ApduError`] if `data.len() > 65535` or `le` is `Some(0)` or `> 65536`.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::yubikey::Apdu;
    ///
    /// let apdu = Apdu::new(0x00, 0xA4, 0x04, 0x00, vec![0xA0, 0x00]);
    /// let bytes = apdu.to_bytes().unwrap();
    /// assert_eq!(&bytes[0..4], &[0x00, 0xA4, 0x04, 0x00]);
    /// ```
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.data.len() > Self::MAX_EXTENDED_DATA {
            return Err(Error::ApduError(format!(
                "APDU data length {} exceeds maximum {}",
                self.data.len(),
                Self::MAX_EXTENDED_DATA
            )));
        }

        if let Some(le) = self.le
            && (le == 0 || le > Self::MAX_EXTENDED_LE)
        {
            return Err(Error::ApduError(format!(
                "APDU Le {le} must be in range 1..={}",
                Self::MAX_EXTENDED_LE
            )));
        }

        let mut bytes = Vec::with_capacity(4 + 3 + self.data.len() + 3);

        // Header
        bytes.push(self.cla);
        bytes.push(self.ins);
        bytes.push(self.p1);
        bytes.push(self.p2);

        let use_extended = self.data.len() > Self::MAX_SHORT_DATA
            || matches!(self.le, Some(le) if le > Self::MAX_SHORT_LE);

        if use_extended {
            // Extended APDU (ISO 7816-4 Cases 2E, 3E, 4E)
            if !self.data.is_empty() {
                bytes.push(0x00); // Extended Lc marker
                bytes.push(((self.data.len() >> 8) & 0xFF) as u8);
                bytes.push((self.data.len() & 0xFF) as u8);
                bytes.extend_from_slice(&self.data);
            }
            if let Some(le) = self.le {
                if self.data.is_empty() {
                    bytes.push(0x00); // Extended Le marker (Case 2E)
                }
                let le_encoded: u16 = if le == Self::MAX_EXTENDED_LE {
                    0x0000
                } else {
                    le as u16
                };
                bytes.push((le_encoded >> 8) as u8);
                bytes.push((le_encoded & 0xFF) as u8);
            }
        } else {
            // Short APDU (ISO 7816-4 Cases 1, 2S, 3S, 4S)
            if !self.data.is_empty() {
                bytes.push(self.data.len() as u8);
                bytes.extend_from_slice(&self.data);
            }
            if let Some(le) = self.le {
                bytes.push(if le == Self::MAX_SHORT_LE {
                    0x00
                } else {
                    le as u8
                });
            }
        }

        Ok(bytes)
    }
}

impl fmt::Debug for Apdu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Apdu")
            .field("cla", &format_args!("{:#04x}", self.cla))
            .field("ins", &format_args!("{:#04x}", self.ins))
            .field("p1", &format_args!("{:#04x}", self.p1))
            .field("p2", &format_args!("{:#04x}", self.p2))
            .field("data_len", &self.data.len())
            .field("le", &self.le)
            .finish()
    }
}

/// An APDU response from a smart card.
///
/// Contains the response data and status word indicating success or failure.
///
/// The [`Debug`](fmt::Debug) implementation prints only the data length and the
/// status word, because some PIV data objects (for example a PIN-protected
/// management key) can carry secret material.
#[derive(Clone, PartialEq, Eq)]
pub struct ApduResponse {
    /// Response data.
    data: Vec<u8>,

    /// Status word 1.
    sw1: u8,

    /// Status word 2.
    sw2: u8,
}

impl ApduResponse {
    /// Success status word (`0x9000`).
    pub const SW_SUCCESS: u16 = 0x9000;

    /// Parses an APDU response from raw bytes without panicking.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw response bytes (`data || SW1 || SW2`)
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the parsed [`ApduResponse`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedResponse`] if `bytes` has fewer than 2 bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use yubikey_evm_signer_core::yubikey::ApduResponse;
    ///
    /// let response = ApduResponse::try_from_bytes(vec![0x01, 0x02, 0x90, 0x00]).unwrap();
    /// assert!(response.is_success());
    /// assert_eq!(response.data(), &[0x01, 0x02]);
    /// ```
    pub fn try_from_bytes(mut bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(Error::MalformedResponse(format!(
                "APDU response must be at least 2 bytes, got {}",
                bytes.len()
            )));
        }

        let sw2 = bytes.pop().expect("len >= 2");
        let sw1 = bytes.pop().expect("len >= 2");

        Ok(Self {
            data: bytes,
            sw1,
            sw2,
        })
    }

    /// Creates a new APDU response from raw bytes.
    ///
    /// Prefer [`Self::try_from_bytes`] for fallible parsing of untrusted transport data.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is shorter than 2 bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self::try_from_bytes(bytes).expect("APDU response must be at least 2 bytes")
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

    /// Returns the `SW2` length byte if more data is available (`SW1 = 0x61`).
    #[must_use]
    pub const fn remaining_bytes(&self) -> Option<u8> {
        if self.has_more_data() {
            Some(self.sw2)
        } else {
            None
        }
    }

    /// Returns the card's requested `Le` if the status word is `0x6C XX` (wrong `Le`).
    ///
    /// `0x6C 0x00` indicates `256` bytes.
    #[must_use]
    pub const fn wrong_le(&self) -> Option<u16> {
        if self.sw1 == 0x6C {
            if self.sw2 == 0 {
                Some(256)
            } else {
                Some(self.sw2 as u16)
            }
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
    /// Returns a mapped [`Error`] if the status word indicates failure.
    pub const fn check(&self) -> Result<()> {
        if self.is_success() || self.has_more_data() {
            Ok(())
        } else {
            Err(self.to_error())
        }
    }

    /// Checks the response status in the context of a specific PIV [`Slot`].
    ///
    /// Maps `0x6A82` (referenced data not found) to [`Error::SlotEmpty`] with
    /// the slot's actual identifier.
    ///
    /// # Errors
    ///
    /// Returns a mapped [`Error`] if the status word indicates failure.
    pub const fn check_for_slot(&self, slot: Slot) -> Result<()> {
        if self.is_success() || self.has_more_data() {
            Ok(())
        } else {
            Err(self.to_error_for_slot(slot))
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
                    Error::InvalidPin {
                        remaining_attempts: Some(attempts),
                    }
                }
            }
            (0x69, 0x82) => Error::SecurityStatusNotSatisfied,
            (0x69, 0x83) => Error::PinLocked,
            _ => Error::UnexpectedStatusWord(self.sw1, self.sw2),
        }
    }

    /// Converts the status word to a descriptive error in the context of a PIV [`Slot`].
    ///
    /// Maps `0x6A82` to [`Error::SlotEmpty`] using `slot.id()`.
    #[must_use]
    pub const fn to_error_for_slot(&self, slot: Slot) -> Error {
        match (self.sw1, self.sw2) {
            (0x6A, 0x82) => Error::SlotEmpty(slot.id()),
            _ => self.to_error(),
        }
    }
}

impl fmt::Debug for ApduResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApduResponse")
            .field("data_len", &self.data.len())
            .field("sw", &format_args!("{:04X}", self.status_word()))
            .finish()
    }
}

impl TryFrom<Vec<u8>> for ApduResponse {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::try_from_bytes(bytes)
    }
}

impl TryFrom<&[u8]> for ApduResponse {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::try_from_bytes(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apdu_new_and_with_le() {
        let apdu = Apdu::new(0x00, 0xA4, 0x04, 0x00, vec![0xA0, 0x00]);
        assert_eq!(apdu.cla(), 0x00);
        assert_eq!(apdu.ins(), 0xA4);
        assert_eq!(apdu.p1(), 0x04);
        assert_eq!(apdu.p2(), 0x00);
        assert_eq!(apdu.data(), &[0xA0, 0x00]);
        assert_eq!(apdu.le(), None);

        let with_le = Apdu::with_le(0x00, 0xCB, 0x3F, 0xFF, vec![0x5C], 256);
        assert_eq!(with_le.le(), Some(256));
    }

    #[test]
    fn apdu_to_bytes_short_cases() {
        // Case 1: no data, no Le
        let c1 = Apdu::new(0x00, 0xA4, 0x04, 0x00, vec![]);
        assert_eq!(c1.to_bytes().unwrap(), vec![0x00, 0xA4, 0x04, 0x00]);

        // Case 2S: no data, Le = 256 (encoded as 0x00)
        let c2 = Apdu::with_le(0x00, 0xCB, 0x3F, 0xFF, vec![], 256);
        assert_eq!(c2.to_bytes().unwrap(), vec![0x00, 0xCB, 0x3F, 0xFF, 0x00]);

        // Case 3S: short data, no Le
        let c3 = Apdu::new(0x00, 0xA4, 0x04, 0x00, vec![0xA0, 0x00]);
        assert_eq!(
            c3.to_bytes().unwrap(),
            vec![0x00, 0xA4, 0x04, 0x00, 0x02, 0xA0, 0x00]
        );

        // Case 4S: short data, Le = 16
        let c4 = Apdu::with_le(0x00, 0x87, 0x11, 0x9A, vec![0x7C, 0x00], 16);
        assert_eq!(
            c4.to_bytes().unwrap(),
            vec![0x00, 0x87, 0x11, 0x9A, 0x02, 0x7C, 0x00, 0x10]
        );
    }

    #[test]
    fn apdu_to_bytes_extended_and_validation() {
        // Case 2E: no data, Le = 65536 -> 0x00 0x00 0x00
        let c2e = Apdu::with_le(0x00, 0xC0, 0x00, 0x00, vec![], 65_536);
        assert_eq!(
            c2e.to_bytes().unwrap(),
            vec![0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00]
        );

        // Case 4E: data len 256 + Le 65536 -> 0x00 0x01 0x00 <data> 0x00 0x00
        let c4e = Apdu::with_le(0x00, 0x87, 0x11, 0x9A, vec![0xAA; 256], 65_536);
        let bytes = c4e.to_bytes().unwrap();
        assert_eq!(bytes.len(), 4 + 3 + 256 + 2);
        assert_eq!(&bytes[4..7], &[0x00, 0x01, 0x00]);
        assert_eq!(&bytes[bytes.len() - 2..], &[0x00, 0x00]);

        // Case 4E: data len 256 + Le 256 -> Le is extended-encoded as 0x01 0x00
        let c4e_256 = Apdu::with_le(0x00, 0x87, 0x11, 0x9A, vec![0xBB; 256], 256);
        let bytes = c4e_256.to_bytes().unwrap();
        assert_eq!(bytes.len(), 4 + 3 + 256 + 2);
        assert_eq!(&bytes[..4], &[0x00, 0x87, 0x11, 0x9A]);
        assert_eq!(&bytes[4..7], &[0x00, 0x01, 0x00]);
        assert!(bytes[7..7 + 256].iter().all(|&b| b == 0xBB));
        assert_eq!(&bytes[bytes.len() - 2..], &[0x01, 0x00]);

        // Case 3E: data len 256, no Le -> 0x00 0x01 0x00 <data> with no trailing Le
        let c3e = Apdu::new(0x00, 0xDB, 0x3F, 0xFF, vec![0xCC; 256]);
        let bytes = c3e.to_bytes().unwrap();
        assert_eq!(bytes.len(), 4 + 3 + 256);
        assert_eq!(&bytes[4..7], &[0x00, 0x01, 0x00]);
        assert_eq!(bytes[bytes.len() - 1], 0xCC);

        // Reject Le = Some(0)
        assert!(matches!(
            Apdu::with_le(0x00, 0xA4, 0x00, 0x00, vec![], 0).to_bytes(),
            Err(Error::ApduError(_))
        ));

        // Reject Le > 65536
        assert!(matches!(
            Apdu::with_le(0x00, 0xA4, 0x00, 0x00, vec![], 65_537).to_bytes(),
            Err(Error::ApduError(_))
        ));

        // Reject data > 65535
        assert!(matches!(
            Apdu::new(0x00, 0xA4, 0x00, 0x00, vec![0u8; 65_536]).to_bytes(),
            Err(Error::ApduError(_))
        ));
    }

    #[test]
    fn apdu_response_try_from_bytes_and_try_from() {
        assert!(matches!(
            ApduResponse::try_from_bytes(vec![]),
            Err(Error::MalformedResponse(_))
        ));
        assert!(matches!(
            ApduResponse::try_from_bytes(vec![0x90]),
            Err(Error::MalformedResponse(_))
        ));

        let resp = ApduResponse::try_from(&[0x01u8, 0x02, 0x90, 0x00][..]).unwrap();
        assert_eq!(resp.data(), &[0x01, 0x02]);
        assert_eq!(resp.sw1(), 0x90);
        assert_eq!(resp.sw2(), 0x00);
        assert!(resp.is_success());

        let resp2 = ApduResponse::try_from(vec![0x90, 0x00]).unwrap();
        assert_eq!(resp2.status_word(), 0x9000);
    }

    #[test]
    fn apdu_response_status_word_mapping() {
        // 61 XX: more data
        let more = ApduResponse::try_from_bytes(vec![0x61, 0x10]).unwrap();
        assert!(more.has_more_data());
        assert_eq!(more.remaining_bytes(), Some(0x10));
        assert!(more.check().is_ok());

        // 6C XX: wrong Le
        let wrong_le_20 = ApduResponse::try_from_bytes(vec![0x6C, 0x20]).unwrap();
        assert_eq!(wrong_le_20.wrong_le(), Some(0x20));
        let wrong_le_256 = ApduResponse::try_from_bytes(vec![0x6C, 0x00]).unwrap();
        assert_eq!(wrong_le_256.wrong_le(), Some(256));

        // 63 C2: InvalidPin with 2 remaining attempts
        let pin_err = ApduResponse::try_from_bytes(vec![0x63, 0xC2]).unwrap();
        assert!(matches!(
            pin_err.to_error(),
            Error::InvalidPin {
                remaining_attempts: Some(2)
            }
        ));

        // 63 C0: PinLocked
        let pin_locked = ApduResponse::try_from_bytes(vec![0x63, 0xC0]).unwrap();
        assert!(matches!(pin_locked.to_error(), Error::PinLocked));

        // 69 82: SecurityStatusNotSatisfied (NOT blindly InvalidPin)
        let sec_err = ApduResponse::try_from_bytes(vec![0x69, 0x82]).unwrap();
        assert!(matches!(
            sec_err.to_error(),
            Error::SecurityStatusNotSatisfied
        ));

        // 6A 82: slot-aware mapping
        let not_found = ApduResponse::try_from_bytes(vec![0x6A, 0x82]).unwrap();
        assert!(matches!(
            not_found.to_error(),
            Error::UnexpectedStatusWord(0x6A, 0x82)
        ));
        assert!(matches!(
            not_found.to_error_for_slot(Slot::Signature),
            Error::SlotEmpty(0x9C)
        ));
    }

    #[test]
    fn apdu_debug_never_prints_command_or_response_data() {
        // VERIFY APDU carrying PIN "123456" padded with 0xFF
        let verify = Apdu::new(0x00, 0x20, 0x00, 0x80, b"123456\xFF\xFF".to_vec());
        let rendered = format!("{verify:?}");
        assert!(rendered.contains("data_len: 8"), "{rendered}");
        assert!(rendered.contains("0x20"), "{rendered}");
        assert!(!rendered.contains("123456"), "{rendered}");
        assert!(!rendered.contains("49, 50, 51"), "{rendered}");
        assert!(!rendered.contains("[0x31"), "{rendered}");
        assert!(
            !rendered.to_ascii_lowercase().contains("313233"),
            "{rendered}"
        );

        let response = ApduResponse::new(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00]);
        let rendered = format!("{response:?}");
        assert!(rendered.contains("data_len: 4"), "{rendered}");
        assert!(rendered.contains("9000"), "{rendered}");
        assert!(!rendered.contains("222"), "{rendered}");
        assert!(
            !rendered.to_ascii_lowercase().contains("dead"),
            "{rendered}"
        );
    }

    #[test]
    fn apdu_response_into_data() {
        let response = ApduResponse::try_from_bytes(vec![0x01, 0x02, 0x90, 0x00]).unwrap();
        assert_eq!(response.into_data(), vec![0x01, 0x02]);
    }
}
