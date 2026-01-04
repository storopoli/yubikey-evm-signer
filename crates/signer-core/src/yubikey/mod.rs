//! YubiKey PIV communication module.
//!
//! This module provides low-level communication with YubiKey devices using
//! the PIV (Personal Identity Verification) applet. It supports:
//!
//! - Device discovery and connection
//! - APDU command/response handling
//! - PIV operations (key generation, signing, authentication)
//!
//! # Architecture
//!
//! The module is organized into several submodules:
//!
//! - [`apdu`]: APDU command/response types and encoding
//! - [`piv`]: PIV-specific commands and operations
//! - [`slot`]: PIV slot definitions and management
//!
//! # Transport Abstraction
//!
//! The [`Transport`] trait abstracts over different communication methods:
//!
//! - CCID (smart card interface over USB)
//! - WebUSB (for browser-based applications)
//!
//! This allows the same PIV operations to work across native and WASM targets.
//!
//! # Example
//!
//! ```ignore
//! use yubikey_evm_signer_core::yubikey::{Transport, PivSession, Slot};
//!
//! // Assuming you have a transport implementation
//! let transport: Box<dyn Transport> = /* ... */;
//! let mut session = PivSession::new(transport);
//!
//! // Authenticate with PIN
//! session.verify_pin("123456")?;
//!
//! // Generate a key in slot 9a
//! let public_key = session.generate_key(Slot::Authentication)?;
//!
//! // Sign data
//! let signature = session.sign(Slot::Authentication, &data_to_sign)?;
//! ```

pub mod apdu;
pub mod piv;
pub mod slot;

#[cfg(feature = "pcsc")]
pub mod pcsc_transport;

pub use apdu::{Apdu, ApduResponse};
pub use piv::PivSession;
pub use slot::Slot;

#[cfg(feature = "pcsc")]
pub use pcsc_transport::PcscTransport;

use crate::error::Result;

/// A transport layer for communicating with a YubiKey.
///
/// This trait abstracts over different communication methods (CCID, WebUSB)
/// allowing the same PIV operations to work across native and WASM targets.
pub trait Transport {
    /// Sends an APDU command and receives a response.
    ///
    /// # Arguments
    ///
    /// * `apdu` - The APDU command to send
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the APDU response.
    ///
    /// # Errors
    ///
    /// Returns an error if communication fails.
    fn transmit(&mut self, apdu: &Apdu) -> Result<ApduResponse>;

    /// Checks if the transport is still connected.
    ///
    /// # Returns
    ///
    /// `true` if connected, `false` otherwise.
    fn is_connected(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A mock transport for testing.
    struct MockTransport {
        responses: VecDeque<ApduResponse>,
    }

    impl MockTransport {
        fn new(responses: Vec<ApduResponse>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
            }
        }
    }

    impl Transport for MockTransport {
        fn transmit(&mut self, _apdu: &Apdu) -> Result<ApduResponse> {
            self.responses
                .pop_front()
                .ok_or_else(|| crate::error::Error::ApduError("no response".to_string()))
        }

        fn is_connected(&self) -> bool {
            true
        }
    }

    #[test]
    fn mock_transport() {
        let response = ApduResponse::new(vec![0x90, 0x00]);
        let mut transport = MockTransport::new(vec![response]);

        let apdu = Apdu::new(0x00, 0xA4, 0x04, 0x00, vec![]);
        let result = transport.transmit(&apdu);

        assert!(result.is_ok());
        assert!(transport.is_connected());
    }
}
