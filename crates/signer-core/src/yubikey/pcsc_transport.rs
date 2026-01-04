//! PC/SC transport for native YubiKey communication.
//!
//! This module provides a [`Transport`] implementation using the PC/SC
//! (Personal Computer/Smart Card) interface, which works on macOS, Linux,
//! and Windows.
//!
//! # Example
//!
//! ```ignore
//! use yubikey_evm_signer_core::yubikey::{PcscTransport, PivSession, Slot};
//!
//! // Connect to the first available YubiKey
//! let transport = PcscTransport::connect()?;
//! let mut session = PivSession::new(Box::new(transport));
//!
//! session.select()?;
//! session.verify_pin("123456")?;
//!
//! let public_key = session.get_public_key(Slot::Authentication)?;
//! ```

use pcsc::{Card, Context, Protocols, Scope, ShareMode};

use super::Transport;
use super::apdu::{Apdu, ApduResponse};
use crate::error::{Error, Result};

/// YubiKey USB vendor ID.
const YUBIKEY_VENDOR: &str = "Yubico";

/// A PC/SC transport for communicating with a YubiKey.
///
/// This transport uses the system's PC/SC daemon to communicate with
/// the YubiKey's smart card interface (CCID).
pub struct PcscTransport {
    /// The PC/SC card handle.
    card: Card,
}

impl std::fmt::Debug for PcscTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcscTransport").finish_non_exhaustive()
    }
}

impl PcscTransport {
    /// Connects to the first available YubiKey.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the connected transport.
    ///
    /// # Errors
    ///
    /// - [`Error::DeviceNotFound`] if no YubiKey is found
    /// - [`Error::ConnectionFailed`] if connection fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// let transport = PcscTransport::connect()?;
    /// ```
    pub fn connect() -> Result<Self> {
        let ctx = Context::establish(Scope::User).map_err(|e| {
            Error::ConnectionFailed(format!("failed to establish PC/SC context: {e}"))
        })?;

        // List available readers
        let mut readers_buf = vec![0u8; 2048];
        let readers = ctx
            .list_readers(&mut readers_buf)
            .map_err(|e| Error::ConnectionFailed(format!("failed to list readers: {e}")))?;

        // Find a YubiKey reader
        let yubikey_reader = readers
            .into_iter()
            .find(|reader| {
                let name = reader.to_string_lossy();
                name.contains(YUBIKEY_VENDOR) || name.contains("YubiKey")
            })
            .ok_or(Error::DeviceNotFound)?;

        // Connect to the card
        let card = ctx
            .connect(yubikey_reader, ShareMode::Shared, Protocols::ANY)
            .map_err(|e| Error::ConnectionFailed(format!("failed to connect to YubiKey: {e}")))?;

        Ok(Self { card })
    }

    /// Lists all available YubiKey readers.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a list of reader names.
    ///
    /// # Errors
    ///
    /// Returns an error if PC/SC context cannot be established.
    pub fn list_readers() -> Result<Vec<String>> {
        let ctx = Context::establish(Scope::User).map_err(|e| {
            Error::ConnectionFailed(format!("failed to establish PC/SC context: {e}"))
        })?;

        let mut readers_buf = vec![0u8; 2048];
        let readers = ctx
            .list_readers(&mut readers_buf)
            .map_err(|e| Error::ConnectionFailed(format!("failed to list readers: {e}")))?;

        Ok(readers
            .into_iter()
            .filter(|r| {
                let name = r.to_string_lossy();
                name.contains(YUBIKEY_VENDOR) || name.contains("YubiKey")
            })
            .map(|r| r.to_string_lossy().into_owned())
            .collect())
    }
}

impl Transport for PcscTransport {
    fn transmit(&mut self, apdu: &Apdu) -> Result<ApduResponse> {
        let command = apdu.to_bytes();
        let mut response_buf = vec![0u8; 258]; // Max short APDU response

        let response = self
            .card
            .transmit(&command, &mut response_buf)
            .map_err(|e| Error::ApduError(format!("transmit failed: {e}")))?;

        if response.len() < 2 {
            return Err(Error::MalformedResponse("response too short".to_string()));
        }

        Ok(ApduResponse::new(response.to_vec()))
    }

    fn is_connected(&self) -> bool {
        // Try to get card status to check if still connected
        self.card.status2_owned().is_ok()
    }
}
