//! JavaScript-friendly error types for WASM bindings.
//!
//! This module provides error types that can be properly propagated to
//! JavaScript code. All errors implement conversion to [`JsValue`] for
//! seamless integration with the JavaScript error handling model.
//!
//! # Example
//!
//! ```ignore
//! use yubikey_evm_signer_wasm::error::WasmError;
//!
//! // Errors can be returned from async functions and will be
//! // converted to JavaScript Error objects automatically
//! async fn connect() -> Result<(), WasmError> {
//!     Err(WasmError::DeviceNotFound)
//! }
//! ```

use std::{error, fmt};

use js_sys::Error as JsError;
use wasm_bindgen::prelude::*;
use yubikey_evm_signer_core::error::Error as CoreError;

/// Error type for WASM operations.
///
/// This enum represents all possible errors that can occur during
/// YubiKey operations in a browser environment. Each variant is
/// designed to provide useful information to JavaScript callers.
#[derive(Debug, Clone)]
pub enum WasmError {
    /// WebUSB is not available in this browser.
    WebUsbNotSupported,

    /// No YubiKey device was found or selected by the user.
    DeviceNotFound,

    /// Failed to open the USB device.
    DeviceOpenFailed(String),

    /// Failed to claim the USB interface.
    InterfaceClaimFailed(String),

    /// USB communication error.
    UsbError(String),

    /// The PIV applet could not be selected.
    PivSelectFailed(String),

    /// PIN verification failed.
    InvalidPin,

    /// PIN is locked after too many failed attempts.
    PinLocked,

    /// Key generation failed.
    KeyGenerationFailed(String),

    /// Signing operation failed.
    SigningFailed(String),

    /// The operation timed out (e.g., waiting for touch).
    Timeout,

    /// Invalid transaction data.
    InvalidTransaction(String),

    /// Invalid typed data (EIP-712).
    InvalidTypedData(String),

    /// Core library error.
    CoreError(String),

    /// JavaScript error from WebUSB API.
    JsError(String),
}

impl fmt::Display for WasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WebUsbNotSupported => {
                write!(f, "WebUSB is not supported in this browser")
            }
            Self::DeviceNotFound => {
                write!(f, "No YubiKey device found")
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
            Self::PivSelectFailed(msg) => {
                write!(f, "Failed to select PIV applet: {msg}")
            }
            Self::InvalidPin => {
                write!(f, "Invalid PIN")
            }
            Self::PinLocked => {
                write!(f, "PIN is locked")
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

impl From<WasmError> for JsValue {
    fn from(error: WasmError) -> Self {
        JsError::new(&error.to_string()).into()
    }
}

impl From<CoreError> for WasmError {
    fn from(error: CoreError) -> Self {
        Self::CoreError(error.to_string())
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
    fn error_display() {
        let error = WasmError::DeviceNotFound;
        assert_eq!(error.to_string(), "No YubiKey device found");
    }
}
