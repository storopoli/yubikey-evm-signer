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

use pcsc::{Card, Context, MAX_BUFFER_SIZE_EXTENDED, Protocols, Scope, ShareMode};

use super::Transport;
use super::apdu::{Apdu, ApduResponse};
use crate::error::{Error, Result};

/// Returns `true` if a PC/SC reader name identifies a YubiKey (case-insensitive).
fn is_yubikey_reader(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("yubikey") || lower.contains("yubico")
}

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
    /// - [`Error::DeviceNotFound`] if no YubiKey reader is available
    /// - [`Error::ConnectionFailed`] if establishing the PC/SC context or connecting fails
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

        let readers = match ctx.list_readers_owned() {
            Ok(readers) => readers,
            Err(pcsc::Error::NoReadersAvailable) => return Err(Error::DeviceNotFound),
            Err(e) => {
                return Err(Error::ConnectionFailed(format!(
                    "failed to list readers: {e}"
                )));
            }
        };

        let yubikey_reader = readers
            .into_iter()
            .find(|reader| is_yubikey_reader(&reader.to_string_lossy()))
            .ok_or(Error::DeviceNotFound)?;

        let card = ctx
            .connect(yubikey_reader.as_c_str(), ShareMode::Shared, Protocols::ANY)
            .map_err(|e| Error::ConnectionFailed(format!("failed to connect to YubiKey: {e}")))?;

        Ok(Self { card })
    }

    /// Connects to a specific PC/SC reader by exact name (for multi-YubiKey environments).
    ///
    /// # Arguments
    ///
    /// * `reader_name` - The exact reader name returned by [`Self::list_readers`]
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the connected transport.
    ///
    /// # Errors
    ///
    /// - [`Error::DeviceNotFound`] if no matching reader is currently available
    /// - [`Error::ConnectionFailed`] if establishing the PC/SC context or connecting fails
    pub fn connect_reader(reader_name: &str) -> Result<Self> {
        let ctx = Context::establish(Scope::User).map_err(|e| {
            Error::ConnectionFailed(format!("failed to establish PC/SC context: {e}"))
        })?;

        let readers = match ctx.list_readers_owned() {
            Ok(readers) => readers,
            Err(pcsc::Error::NoReadersAvailable) => return Err(Error::DeviceNotFound),
            Err(e) => {
                return Err(Error::ConnectionFailed(format!(
                    "failed to list readers: {e}"
                )));
            }
        };

        let target_reader = readers
            .into_iter()
            .find(|reader| reader.to_string_lossy() == reader_name)
            .ok_or(Error::DeviceNotFound)?;

        let card = ctx
            .connect(target_reader.as_c_str(), ShareMode::Shared, Protocols::ANY)
            .map_err(|e| {
                Error::ConnectionFailed(format!("failed to connect to reader '{reader_name}': {e}"))
            })?;

        Ok(Self { card })
    }

    /// Lists all available YubiKey readers.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a list of reader names (empty if no readers are present).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionFailed`] if the PC/SC context cannot be established
    /// or reader enumeration fails unexpectedly.
    pub fn list_readers() -> Result<Vec<String>> {
        let ctx = Context::establish(Scope::User).map_err(|e| {
            Error::ConnectionFailed(format!("failed to establish PC/SC context: {e}"))
        })?;

        let readers = match ctx.list_readers_owned() {
            Ok(readers) => readers,
            Err(pcsc::Error::NoReadersAvailable) => return Ok(Vec::new()),
            Err(e) => {
                return Err(Error::ConnectionFailed(format!(
                    "failed to list readers: {e}"
                )));
            }
        };

        Ok(readers
            .into_iter()
            .filter_map(|reader| {
                let name = reader.to_string_lossy();
                if is_yubikey_reader(&name) {
                    Some(name.into_owned())
                } else {
                    None
                }
            })
            .collect())
    }
}

impl Transport for PcscTransport {
    fn transmit(&mut self, apdu: &Apdu) -> Result<ApduResponse> {
        let command = apdu.to_bytes()?;
        let mut response_buf = vec![0u8; MAX_BUFFER_SIZE_EXTENDED];

        let response = self
            .card
            .transmit(&command, &mut response_buf)
            .map_err(|e| match e {
                pcsc::Error::RemovedCard => Error::DeviceDisconnected,
                other => Error::ApduError(format!("transmit failed: {other}")),
            })?;

        ApduResponse::try_from_bytes(response.to_vec())
    }

    fn is_connected(&self) -> bool {
        // Query card status to check whether the card is still present and responsive
        self.card.status2_owned().is_ok()
    }
}
