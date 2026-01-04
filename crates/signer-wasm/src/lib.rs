//! YubiKey EVM Signer WASM Library
//!
//! This crate provides WebAssembly bindings for the YubiKey EVM Signer,
//! enabling browser-based applications to sign Ethereum transactions
//! using a YubiKey's secp256r1 (P-256) keys via EIP-7951.
//!
//! # Browser Support
//!
//! This library requires WebUSB, which is only supported in Chromium-based
//! browsers (Chrome, Edge, Opera, Brave). Firefox and Safari do not support
//! WebUSB.
//!
//! # Security Requirements
//!
//! - HTTPS context required (WebUSB security requirement)
//! - User gesture required to initiate device connection
//! - User must grant USB permission through browser dialog
//!
//! # Quick Start
//!
//! ```javascript
//! import init, { YubiKeyDevice } from 'yubikey-evm-signer-wasm';
//!
//! // Initialize WASM module
//! await init();
//!
//! // Connect to YubiKey (must be triggered by user gesture)
//! const device = await YubiKeyDevice.connect();
//!
//! // Generate a new key (or use existing)
//! const address = await device.generateKey("123456");
//! console.log("Ethereum address:", address);
//!
//! // Sign a transaction
//! const tx = JSON.stringify({
//!     type: "eip1559",
//!     chain_id: 1,
//!     nonce: 0,
//!     max_priority_fee_per_gas: "1000000000",
//!     max_fee_per_gas: "20000000000",
//!     gas_limit: 21000,
//!     to: "0x...",
//!     value: "1000000000000000000",
//!     input: "0x"
//! });
//! const signature = await device.signTransaction("123456", tx);
//!
//! // Disconnect when done
//! await device.disconnect();
//! ```
//!
//! # API Reference
//!
//! ## [`YubiKeyDevice`]
//!
//! The main class for interacting with a YubiKey device.
//!
//! ### Methods
//!
//! - [`connect()`](YubiKeyDevice::connect) - Connect to a YubiKey device (requires user gesture)
//! - [`verifyPin(pin)`](YubiKeyDevice::verify_pin) - Verify the user's PIN
//! - [`generateKey(pin)`](YubiKeyDevice::generate_key) - Generate a new P-256 key pair
//! - [`getAddress()`](YubiKeyDevice::get_address) - Get the Ethereum address for the current key
//! - [`signHash(pin, hash)`](YubiKeyDevice::sign_hash) - Sign a 32-byte hash
//! - [`signTransaction(pin, txJson)`](YubiKeyDevice::sign_transaction) - Sign an Ethereum transaction
//! - [`signTypedData(pin, typedDataJson)`](YubiKeyDevice::sign_typed_data) - Sign EIP-712 typed data
//! - [`signMessage(pin, message)`](YubiKeyDevice::sign_message) - Sign a personal message (EIP-191)
//! - [`disconnect()`](YubiKeyDevice::disconnect) - Disconnect from the device
//! - [`isConnected()`](YubiKeyDevice::is_connected) - Check if still connected
//!
//! # EIP-7951 Compatibility
//!
//! All signatures produced by this library are compatible with EIP-7951,
//! which enables native secp256r1 signature verification on the EVM.
//! The signatures use the secp256r1 curve (NIST P-256) instead of the
//! traditional secp256k1 curve.

pub mod device;
pub mod error;
pub mod transport;

pub use device::YubiKeyDevice;
pub use error::{WasmError, WasmResult};
pub use transport::WebUsbTransport;

use wasm_bindgen::prelude::*;

/// Initializes the WASM module.
///
/// This function is automatically called when the module is loaded,
/// but can be called explicitly if needed.
#[wasm_bindgen(start)]
#[expect(clippy::missing_const_for_fn, reason = "not a stable API function")]
pub fn init() {
    // Nothing to initialize for now
}

/// Checks if WebUSB is supported in the current browser.
///
/// # Returns
///
/// `true` if WebUSB is available, `false` otherwise.
///
/// # Example
///
/// ```javascript
/// if (!isWebUsbSupported()) {
///     alert("WebUSB is not supported. Please use Chrome, Edge, or another Chromium browser.");
/// }
/// ```
#[wasm_bindgen(js_name = "isWebUsbSupported")]
pub fn is_webusb_supported() -> bool {
    if let Some(window) = web_sys::window() {
        let navigator: web_sys::Navigator = window.navigator();
        // Check if usb property exists on navigator
        js_sys::Reflect::has(&navigator, &JsValue::from_str("usb")).unwrap_or(false)
    } else {
        false
    }
}

/// Returns the library version.
///
/// # Returns
///
/// The version string (e.g., `"0.1.0"`).
#[wasm_bindgen(js_name = "getVersion")]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Import for WASM tests
    #[expect(unused_imports, reason = "import for WASM tests")]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[test]
    fn version() {
        let version = get_version();
        assert!(!version.is_empty());
    }
}
