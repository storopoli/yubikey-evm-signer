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
//! // SELECT -> GET METADATA / GET DATA in one PC/SC transaction
//! let public_key = session.exclusive(|piv| {
//!     piv.select()?;
//!     piv.get_public_key(Slot::Authentication)
//! })?;
//! ```
//!
//! # Concurrency, exclusive sessions, and card resets
//!
//! [`PcscTransport::connect`] and [`PcscTransport::connect_reader`] open the
//! card in [`ShareMode::Shared`], so other PC/SC clients (`ykman`, `gpg`'s
//! `scdaemon`, another `yubikey-cli`) can use it too. Multi-APDU operations on
//! a shared handle must run inside [`Transport::exclusive`], which wraps them
//! in a PC/SC transaction (`SCardBeginTransaction` / `SCardEndTransaction` with
//! [`Disposition::LeaveCard`]).
//!
//! Whenever card-side authentication state (a verified PIV PIN or an
//! authenticated management key) may be established on the card — especially
//! across multiple requests such as in the local HTTP bridge — open the card
//! with [`PcscTransport::connect_exclusive`] or
//! [`PcscTransport::connect_reader_exclusive`] (`ShareMode::Exclusive`). While
//! an exclusive handle is alive, no other local PC/SC client can connect to the
//! card or use its authenticated state; dropping the transport disconnects with
//! `Disposition::ResetCard`, clearing PIN and management key authentication
//! before exclusive ownership is released.
//!
//! When another client (or a power/bus event) resets the card, the next
//! exchange reports [`Error::CardReset`] after reconnecting the handle in the
//! same share mode; the PIV applet must be selected again and the PIN
//! re-verified.

use pcsc::{
    Card, Context, Disposition, MAX_BUFFER_SIZE_EXTENDED, Protocols, Scope, ShareMode, Transaction,
};
use zeroize::Zeroizing;

use super::Transport;
use super::apdu::{Apdu, ApduResponse};
use crate::error::{Error, Result};

/// Maps a PC/SC error from an exchange with the card to a library [`Error`].
///
/// - [`pcsc::Error::ResetCard`] → [`Error::CardReset`]
/// - card removal, reader or resource-manager loss, and invalidated handles →
///   [`Error::DeviceDisconnected`]
/// - anything else → [`Error::ApduError`]
fn map_pcsc_error(err: pcsc::Error) -> Error {
    match err {
        pcsc::Error::ResetCard => Error::CardReset,
        pcsc::Error::RemovedCard
        | pcsc::Error::NoSmartcard
        | pcsc::Error::ReaderUnavailable
        | pcsc::Error::NoService
        | pcsc::Error::ServiceStopped
        | pcsc::Error::InvalidHandle => Error::DeviceDisconnected,
        other => Error::ApduError(format!("PC/SC transmit failed: {other}")),
    }
}

/// Maps the outcome of reconnecting a handle that reported [`pcsc::Error::ResetCard`].
///
/// The failed command is always reported as [`Error::CardReset`] unless the
/// reconnect shows the card or reader is gone ([`Error::DeviceDisconnected`]).
fn reset_outcome(reconnect: core::result::Result<(), pcsc::Error>) -> Error {
    match reconnect.map_err(map_pcsc_error) {
        Err(Error::DeviceDisconnected) => Error::DeviceDisconnected,
        _ => Error::CardReset,
    }
}

/// Maps a PC/SC connection error to [`Error::ConnectionFailed`], adding
/// actionable guidance when an exclusive connection hits a sharing violation.
fn map_connect_error(target: &str, share_mode: ShareMode, err: pcsc::Error) -> Error {
    match err {
        pcsc::Error::SharingViolation if share_mode == ShareMode::Exclusive => {
            Error::ConnectionFailed(format!(
                "failed to open exclusive connection to {target}: another PC/SC client is \
                 currently using the card (close other smart-card apps such as ykman or \
                 gpg-agent/scdaemon and retry)"
            ))
        }
        other => Error::ConnectionFailed(format!("failed to connect to {target}: {other}")),
    }
}

/// Re-establishes a handle after a reset without resetting the card again,
/// preserving `share_mode` so an exclusive handle never downgrades to shared.
fn reconnect_after_reset(card: &mut Card, share_mode: ShareMode) -> Error {
    reset_outcome(card.reconnect(share_mode, Protocols::ANY, Disposition::LeaveCard))
}

/// Result of one raw PC/SC exchange.
enum Exchange {
    /// The card answered.
    Response(ApduResponse),
    /// PC/SC reported an error.
    Failed(pcsc::Error),
}

/// Serializes `apdu`, transmits it on `card`, and zeroizes both the serialized
/// command (which may carry a PIN or management key material) and the receive
/// buffer on every exit path.
fn exchange(card: &Card, apdu: &Apdu) -> Result<Exchange> {
    let command = Zeroizing::new(apdu.to_bytes()?);
    let mut response_buf = Zeroizing::new(vec![0u8; MAX_BUFFER_SIZE_EXTENDED]);

    match card.transmit(command.as_slice(), response_buf.as_mut_slice()) {
        Ok(response) => ApduResponse::try_from_bytes(response.to_vec()).map(Exchange::Response),
        Err(e) => Ok(Exchange::Failed(e)),
    }
}

/// [`Transport`] view of a [`PcscTransport`] inside an open PC/SC transaction.
///
/// Its [`Transport::exclusive`] is the default (run inline), so nested scopes
/// never try to begin a second transaction.
struct TransactionTransport<'a, 'tx> {
    /// The open transaction.
    tx: &'a mut Transaction<'tx>,
}

impl Transport for TransactionTransport<'_, '_> {
    fn transmit(&mut self, apdu: &Apdu) -> Result<ApduResponse> {
        match exchange(self.tx, apdu)? {
            Exchange::Response(response) => Ok(response),
            Exchange::Failed(pcsc::Error::ResetCard) => Err(reset_outcome(self.tx.reconnect(
                ShareMode::Shared,
                Protocols::ANY,
                Disposition::LeaveCard,
            ))),
            Exchange::Failed(e) => Err(map_pcsc_error(e)),
        }
    }

    fn is_connected(&self) -> bool {
        self.tx.status2_owned().is_ok()
    }
}

/// Returns `true` if a PC/SC reader name identifies a YubiKey (case-insensitive).
fn is_yubikey_reader(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("yubikey") || lower.contains("yubico")
}

/// A PC/SC transport for communicating with a YubiKey.
///
/// This transport uses the system's PC/SC daemon to communicate with
/// the YubiKey's smart card interface (CCID). Dropping it disconnects the card
/// with [`Disposition::ResetCard`], clearing any verified PIN or management key
/// authentication on the card.
pub struct PcscTransport {
    /// The PC/SC card handle.
    card: Card,
    /// The PC/SC share mode (`Shared` or `Exclusive`) used to open `card`.
    share_mode: ShareMode,
}

impl std::fmt::Debug for PcscTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcscTransport")
            .field("exclusive", &self.is_exclusive())
            .finish_non_exhaustive()
    }
}

impl PcscTransport {
    /// Connects to the first available YubiKey in shared mode (`ShareMode::Shared`).
    ///
    /// Other local PC/SC clients can connect to the card concurrently; wrap
    /// multi-APDU sequences in [`Transport::exclusive`]. Prefer
    /// [`Self::connect_exclusive`] whenever a verified PIN or management key
    /// authentication will be used across calls.
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
        Self::connect_with_mode(ShareMode::Shared)
    }

    /// Connects to the first available YubiKey with exclusive access
    /// (`ShareMode::Exclusive`).
    ///
    /// No other local PC/SC client can connect to the card or use card-side
    /// PIN or management key authentication while this transport is alive.
    /// Dropping the transport resets the card (`Disposition::ResetCard`) before
    /// releasing exclusive ownership.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the exclusively connected transport.
    ///
    /// # Errors
    ///
    /// - [`Error::DeviceNotFound`] if no YubiKey reader is available
    /// - [`Error::ConnectionFailed`] if establishing the PC/SC context fails,
    ///   connecting fails, or another PC/SC client already holds the card
    pub fn connect_exclusive() -> Result<Self> {
        Self::connect_with_mode(ShareMode::Exclusive)
    }

    /// Connects to the first available YubiKey using `share_mode`.
    fn connect_with_mode(share_mode: ShareMode) -> Result<Self> {
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
            .connect(yubikey_reader.as_c_str(), share_mode, Protocols::ANY)
            .map_err(|e| map_connect_error("YubiKey", share_mode, e))?;

        Ok(Self { card, share_mode })
    }

    /// Connects to a specific PC/SC reader by exact name in shared mode
    /// (for multi-YubiKey environments).
    ///
    /// Prefer [`Self::connect_reader_exclusive`] whenever a verified PIN or
    /// management key authentication will be used across calls.
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
        Self::connect_reader_with_mode(reader_name, ShareMode::Shared)
    }

    /// Connects to a specific PC/SC reader by exact name with exclusive access
    /// (`ShareMode::Exclusive`).
    ///
    /// No other local PC/SC client can connect to the card while this transport
    /// is alive; dropping it resets the card before releasing exclusive access.
    ///
    /// # Arguments
    ///
    /// * `reader_name` - The exact reader name returned by [`Self::list_readers`]
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the exclusively connected transport.
    ///
    /// # Errors
    ///
    /// - [`Error::DeviceNotFound`] if no matching reader is currently available
    /// - [`Error::ConnectionFailed`] if establishing the PC/SC context fails,
    ///   connecting fails, or another PC/SC client already holds the card
    pub fn connect_reader_exclusive(reader_name: &str) -> Result<Self> {
        Self::connect_reader_with_mode(reader_name, ShareMode::Exclusive)
    }

    /// Connects to a specific PC/SC reader by exact name using `share_mode`.
    fn connect_reader_with_mode(reader_name: &str, share_mode: ShareMode) -> Result<Self> {
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
            .connect(target_reader.as_c_str(), share_mode, Protocols::ANY)
            .map_err(|e| map_connect_error(&format!("reader '{reader_name}'"), share_mode, e))?;

        Ok(Self { card, share_mode })
    }

    /// Returns `true` if this transport owns the card exclusively
    /// (`ShareMode::Exclusive`).
    #[must_use]
    pub const fn is_exclusive(&self) -> bool {
        matches!(self.share_mode, ShareMode::Exclusive)
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
        match exchange(&self.card, apdu)? {
            Exchange::Response(response) => Ok(response),
            Exchange::Failed(pcsc::Error::ResetCard) => {
                Err(reconnect_after_reset(&mut self.card, self.share_mode))
            }
            Exchange::Failed(e) => Err(map_pcsc_error(e)),
        }
    }

    fn is_connected(&self) -> bool {
        // Query card status to check whether the card is still present and responsive
        self.card.status2_owned().is_ok()
    }

    fn is_exclusive_session(&self) -> bool {
        self.is_exclusive()
    }

    fn exclusive(&mut self, f: &mut dyn FnMut(&mut dyn Transport) -> Result<()>) -> Result<()> {
        if self.is_exclusive() {
            // The handle already owns the card exclusively via ShareMode::Exclusive
            // for its entire lifetime (until Drop disconnects with ResetCard).
            return f(self);
        }

        let mut tx = match self.card.transaction2() {
            Ok(tx) => tx,
            Err((card, pcsc::Error::ResetCard)) => {
                return Err(reconnect_after_reset(card, self.share_mode));
            }
            Err((_, e)) => return Err(map_pcsc_error(e)),
        };

        let result = f(&mut TransactionTransport { tx: &mut tx });

        // Release the card for other clients without resetting it. A failure to
        // end the transaction does not invalidate responses already received
        // under it; a reset or removal surfaces on the next exchange.
        let _ = tx.end(Disposition::LeaveCard);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcsc_error_mapping() {
        assert!(matches!(
            map_pcsc_error(pcsc::Error::ResetCard),
            Error::CardReset
        ));
        for disconnected in [
            pcsc::Error::RemovedCard,
            pcsc::Error::NoSmartcard,
            pcsc::Error::ReaderUnavailable,
            pcsc::Error::NoService,
            pcsc::Error::ServiceStopped,
            pcsc::Error::InvalidHandle,
        ] {
            assert!(
                matches!(map_pcsc_error(disconnected), Error::DeviceDisconnected),
                "{disconnected:?}"
            );
        }
        for other in [
            pcsc::Error::Timeout,
            pcsc::Error::SharingViolation,
            pcsc::Error::UnresponsiveCard,
        ] {
            assert!(
                matches!(map_pcsc_error(other), Error::ApduError(_)),
                "{other:?}"
            );
        }
    }

    #[test]
    fn reset_outcome_after_reconnect() {
        assert!(matches!(reset_outcome(Ok(())), Error::CardReset));
        assert!(matches!(
            reset_outcome(Err(pcsc::Error::ResetCard)),
            Error::CardReset
        ));
        assert!(matches!(
            reset_outcome(Err(pcsc::Error::Timeout)),
            Error::CardReset
        ));
        assert!(matches!(
            reset_outcome(Err(pcsc::Error::RemovedCard)),
            Error::DeviceDisconnected
        ));
        assert!(matches!(
            reset_outcome(Err(pcsc::Error::NoSmartcard)),
            Error::DeviceDisconnected
        ));
    }

    #[test]
    fn yubikey_reader_detection() {
        assert!(is_yubikey_reader("Yubico YubiKey OTP+FIDO+CCID 00 00"));
        assert!(!is_yubikey_reader("Generic Smart Card Reader"));
    }

    #[test]
    fn connect_error_reports_exclusive_sharing_violation() {
        let exclusive_err = map_connect_error(
            "YubiKey",
            ShareMode::Exclusive,
            pcsc::Error::SharingViolation,
        );
        match exclusive_err {
            Error::ConnectionFailed(msg) => {
                assert!(msg.contains("exclusive connection"), "{msg}");
                assert!(msg.contains("another PC/SC client"), "{msg}");
            }
            other => panic!("expected ConnectionFailed, got {other:?}"),
        }

        let shared_err =
            map_connect_error("YubiKey", ShareMode::Shared, pcsc::Error::SharingViolation);
        match shared_err {
            Error::ConnectionFailed(msg) => {
                assert!(msg.contains("failed to connect to YubiKey"), "{msg}");
                assert!(!msg.contains("exclusive connection"), "{msg}");
            }
            other => panic!("expected ConnectionFailed, got {other:?}"),
        }

        let other_err = map_connect_error("YubiKey", ShareMode::Exclusive, pcsc::Error::Timeout);
        match other_err {
            Error::ConnectionFailed(msg) => {
                assert!(msg.contains("failed to connect to YubiKey"), "{msg}");
            }
            other => panic!("expected ConnectionFailed, got {other:?}"),
        }
    }
}
