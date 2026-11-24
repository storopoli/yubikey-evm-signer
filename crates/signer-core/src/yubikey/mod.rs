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
//! - [`piv`]: PIV-specific commands, sans-IO helpers, and session management
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
//! use yubikey_evm_signer_core::yubikey::{ManagementKeyAlgorithm, PivSession, Slot, Transport};
//!
//! // Assuming you have a transport implementation
//! let transport: Box<dyn Transport> = /* ... */;
//! let mut session = PivSession::new(transport);
//!
//! session.select()?;
//!
//! // Authenticate management key and generate a key in slot 9a in one exclusive scope
//! let generated = session.exclusive(|piv| {
//!     piv.authenticate_management_key_with(&mgmt_key, ManagementKeyAlgorithm::Aes192)?;
//!     piv.generate_key(Slot::Authentication)
//! })?;
//! let public_key = generated.public_key;
//!
//! // Verify PIN and sign a 32-byte digest in one exclusive scope
//! let signature = session.verify_pin_and_sign("123456", Slot::Authentication, &data_to_sign)?;
//! ```

pub mod apdu;
pub mod piv;
pub mod slot;

#[cfg(feature = "pcsc")]
pub mod pcsc_transport;

pub use apdu::{Apdu, ApduResponse};
pub use piv::{
    GeneratedKey, ManagementKeyAlgorithm, PivExclusive, PivSession, PublicKeySource, SlotPublicKey,
};
pub use slot::Slot;

#[cfg(feature = "pcsc")]
pub use pcsc_transport::PcscTransport;

use crate::error::Result;

/// A transport layer for communicating with a YubiKey.
///
/// This trait abstracts over different communication methods (CCID, WebUSB)
/// allowing the same PIV operations to work across native and WASM targets.
///
/// The trait is object-safe (`Box<dyn Transport>`); its [`AsDynTransport`]
/// supertrait is implemented automatically for every implementor.
pub trait Transport: AsDynTransport {
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

    /// Runs `f` as one exclusive scope with respect to other clients of the card.
    ///
    /// Every APDU that `f` sends through the [`Transport`] it receives is
    /// exchanged without another application being able to interleave its own
    /// commands (for PC/SC, inside one `SCardBeginTransaction` /
    /// `SCardEndTransaction` pair). Use it for multi-APDU operations whose
    /// card-side state must not be disturbed: `SELECT` → `VERIFY` →
    /// `GENERAL AUTHENTICATE`, both management key authentication steps, or a
    /// command together with its `0x6C XX` retry and `0x61 XX` `GET RESPONSE`
    /// chain.
    ///
    /// The default implementation simply calls `f(self)`, which is correct for
    /// transports that have no other clients (mocks, a WebUSB device claimed by a
    /// single page). Calling `exclusive` again on the transport handed to `f`
    /// runs the nested closure inline in the same scope and never deadlocks.
    ///
    /// # Arguments
    ///
    /// * `f` - The operation to run while the card is held exclusively
    ///
    /// # Returns
    ///
    /// The result of `f`.
    ///
    /// # Errors
    ///
    /// Returns the error from `f`, or a transport error if the exclusive scope
    /// could not be started (for example [`Error::CardReset`](crate::Error::CardReset)
    /// or [`Error::DeviceDisconnected`](crate::Error::DeviceDisconnected)); in
    /// the latter case `f` is not called.
    fn exclusive(&mut self, f: &mut dyn FnMut(&mut dyn Transport) -> Result<()>) -> Result<()> {
        f(self.as_dyn_transport())
    }
}

/// Upcasts a concrete [`Transport`] to `&mut dyn Transport`.
///
/// This is implemented automatically for every sized [`Transport`]; it only
/// exists so the provided [`Transport::exclusive`] can hand `self` to its closure
/// as a trait object. Implementors never need to implement it by hand.
pub trait AsDynTransport {
    /// Returns `self` as a `&mut dyn Transport`.
    fn as_dyn_transport(&mut self) -> &mut dyn Transport;
}

impl<T: Transport> AsDynTransport for T {
    fn as_dyn_transport(&mut self) -> &mut dyn Transport {
        self
    }
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
        let response = ApduResponse::try_from_bytes(vec![0x90, 0x00]).unwrap();
        let mut transport = MockTransport::new(vec![response]);

        let apdu = Apdu::new(0x00, 0xA4, 0x04, 0x00, vec![]);
        let result = transport.transmit(&apdu);

        assert!(result.is_ok());
        assert!(transport.is_connected());
    }
}
