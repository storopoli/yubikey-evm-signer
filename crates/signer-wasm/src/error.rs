//! JavaScript-friendly error types for WASM bindings.
//!
//! This module provides error types that can be properly propagated to
//! JavaScript code. All errors implement conversion to [`JsValue`] for
//! seamless integration with the JavaScript error handling model.

use std::{error, fmt};

use js_sys::Error as JsError;
use wasm_bindgen::prelude::*;
use yubikey_evm_signer_core::error::Error as CoreError;

/// Error type for WASM operations.
///
/// This enum represents all possible errors that can occur during
/// YubiKey operations in a browser environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasmError {
    /// WebUSB is not available in this browser or context.
    WebUsbNotSupported,

    /// No YubiKey device was found or selected by the user.
    DeviceNotFound,

    /// Failed to open the USB device.
    DeviceOpenFailed(String),

    /// Failed to claim the USB interface or blocked by browser policy.
    InterfaceClaimFailed(String),

    /// USB communication error.
    UsbError(String),

    /// Local PC/SC loopback bridge error.
    BridgeError(String),

    /// The PIV applet could not be selected.
    PivSelectFailed(String),

    /// The YubiKey was reset by another application; re-select and re-verify the PIN.
    CardReset,

    /// The session or the device is gone (bridge session expired, replaced or
    /// closed by a card reset, bridge or reader lost, YubiKey unplugged, or the
    /// WebUSB transport was closed after an unrecoverable error).
    ///
    /// The device must be reconnected; the message says why.
    Disconnected(String),

    /// The operation needs a verified PIN, but the PIN has not been verified yet.
    PinRequired,

    /// PIN verification failed.
    InvalidPin {
        /// Remaining attempts reported by the card, if known.
        remaining_attempts: Option<u8>,
    },

    /// PIN is locked after too many failed attempts.
    PinLocked,

    /// Security status is not satisfied (PIN, management key, or touch confirmation required).
    SecurityStatusNotSatisfied,

    /// Management key mutual authentication failed.
    AuthenticationFailed,

    /// The requested PIV slot identifier is invalid.
    InvalidSlot(String),

    /// Key generation failed.
    KeyGenerationFailed(String),

    /// Signing operation failed.
    SigningFailed(String),

    /// The operation timed out (e.g., waiting for touch or CCID WTX limit exceeded).
    Timeout,

    /// Invalid 32-byte digest hex string.
    InvalidHash(String),

    /// Invalid transaction data.
    InvalidTransaction(String),

    /// Invalid typed data (EIP-712).
    InvalidTypedData(String),

    /// Core library error.
    CoreError(String),

    /// JavaScript error from browser APIs.
    JsError(String),
}

impl fmt::Display for WasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WebUsbNotSupported => {
                write!(
                    f,
                    "WebUSB is not supported in this browser or requires a secure context (HTTPS/localhost)"
                )
            }
            Self::DeviceNotFound => {
                write!(
                    f,
                    "No YubiKey device found (note: Chromium blocks YubiKey VID 0x1050 and CCID class 0x0B on standard web pages; use YubiKeyDevice.connectBridge() with the local PC/SC bridge)"
                )
            }
            Self::DeviceOpenFailed(msg) => {
                write!(f, "Failed to open device: {msg}")
            }
            Self::InterfaceClaimFailed(msg) => {
                write!(f, "Failed to claim interface: {msg}")
            }
            Self::UsbError(msg) => {
                write!(f, "USB error: {msg}")
            }
            Self::BridgeError(msg) => {
                write!(f, "Bridge error: {msg}")
            }
            Self::PivSelectFailed(msg) => {
                write!(f, "Failed to select PIV applet: {msg}")
            }
            Self::CardReset => {
                write!(
                    f,
                    "YubiKey was reset by another application; reconnect and verify the PIN again"
                )
            }
            Self::Disconnected(msg) => {
                write!(f, "Disconnected: {msg}")
            }
            Self::PinRequired => {
                write!(f, "PIN verification required before this operation")
            }
            Self::InvalidPin {
                remaining_attempts: Some(n),
            } => {
                let unit = if *n == 1 { "attempt" } else { "attempts" };
                write!(f, "Invalid PIN ({n} {unit} remaining)")
            }
            Self::InvalidPin {
                remaining_attempts: None,
            } => {
                write!(f, "Invalid PIN")
            }
            Self::PinLocked => {
                write!(f, "PIN is locked")
            }
            Self::SecurityStatusNotSatisfied => {
                write!(
                    f,
                    "Security status not satisfied (PIN, management key authentication, or touch confirmation required)"
                )
            }
            Self::AuthenticationFailed => {
                write!(f, "Management key authentication failed")
            }
            Self::InvalidSlot(slot) => {
                write!(
                    f,
                    "Invalid PIV slot '{slot}' (expected one of: 9a, 9c, 9d, 9e)"
                )
            }
            Self::KeyGenerationFailed(msg) => {
                write!(f, "Key generation failed: {msg}")
            }
            Self::SigningFailed(msg) => {
                write!(f, "Signing failed: {msg}")
            }
            Self::Timeout => {
                write!(f, "Operation timed out")
            }
            Self::InvalidHash(msg) => {
                write!(f, "Invalid hash: {msg}")
            }
            Self::InvalidTransaction(msg) => {
                write!(f, "Invalid transaction: {msg}")
            }
            Self::InvalidTypedData(msg) => {
                write!(f, "Invalid typed data: {msg}")
            }
            Self::CoreError(msg) => {
                write!(f, "Core error: {msg}")
            }
            Self::JsError(msg) => {
                write!(f, "JavaScript error: {msg}")
            }
        }
    }
}

impl error::Error for WasmError {}

impl WasmError {
    /// Returns `true` if this error means the session or the device is gone, so
    /// all PIN, management key and cached key state must be discarded and the
    /// caller has to reconnect.
    #[must_use]
    pub const fn ends_session(&self) -> bool {
        matches!(self, Self::Disconnected(_) | Self::CardReset)
    }
}

impl From<WasmError> for JsValue {
    fn from(error: WasmError) -> Self {
        JsError::new(&error.to_string()).into()
    }
}

impl From<CoreError> for WasmError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::DeviceNotFound => Self::DeviceNotFound,
            CoreError::CardReset => Self::CardReset,
            CoreError::DeviceDisconnected => {
                Self::Disconnected("YubiKey device disconnected; reconnect to continue".to_string())
            }
            CoreError::PinRequired => Self::PinRequired,
            CoreError::InvalidPin { remaining_attempts } => Self::InvalidPin { remaining_attempts },
            CoreError::PinLocked => Self::PinLocked,
            CoreError::SecurityStatusNotSatisfied => Self::SecurityStatusNotSatisfied,
            CoreError::AuthenticationFailed => Self::AuthenticationFailed,
            CoreError::InvalidTransaction(msg) => Self::InvalidTransaction(msg),
            CoreError::InvalidTypedData(msg) => Self::InvalidTypedData(msg),
            other => Self::CoreError(other.to_string()),
        }
    }
}

impl From<JsValue> for WasmError {
    fn from(value: JsValue) -> Self {
        let msg = if let Some(s) = value.as_string() {
            s
        } else if let Some(err) = value.dyn_ref::<JsError>() {
            err.message().into()
        } else {
            format!("{value:?}")
        };
        Self::JsError(msg)
    }
}

/// Result type for WASM operations.
pub type WasmResult<T> = Result<T, WasmError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_and_core_mapping() {
        let error = WasmError::DeviceNotFound;
        assert!(error.to_string().contains("No YubiKey device found"));
        assert!(error.to_string().contains("connectBridge"));

        let pin_err: WasmError = CoreError::InvalidPin {
            remaining_attempts: Some(2),
        }
        .into();
        assert_eq!(pin_err.to_string(), "Invalid PIN (2 attempts remaining)");

        let single_pin: WasmError = CoreError::InvalidPin {
            remaining_attempts: Some(1),
        }
        .into();
        assert_eq!(single_pin.to_string(), "Invalid PIN (1 attempt remaining)");

        let sec_err: WasmError = CoreError::SecurityStatusNotSatisfied.into();
        assert_eq!(sec_err, WasmError::SecurityStatusNotSatisfied);

        let auth_err: WasmError = CoreError::AuthenticationFailed.into();
        assert_eq!(auth_err, WasmError::AuthenticationFailed);

        let reset_err: WasmError = CoreError::CardReset.into();
        assert_eq!(reset_err, WasmError::CardReset);
        assert!(reset_err.to_string().contains("reset"));

        let pin_required: WasmError = CoreError::PinRequired.into();
        assert_eq!(pin_required, WasmError::PinRequired);
        assert!(!pin_required.ends_session());

        // Session-ending errors
        assert!(reset_err.ends_session());
        let gone: WasmError = CoreError::DeviceDisconnected.into();
        assert!(gone.ends_session());
        assert!(gone.to_string().starts_with("Disconnected: "));
        assert!(gone.to_string().contains("reconnect"));
        assert!(!WasmError::Timeout.ends_session());
        assert!(!WasmError::BridgeError("x".to_string()).ends_session());
    }
}
