//! YubiKey EVM Signer WASM Library.
//!
//! This crate provides WebAssembly bindings for the YubiKey EVM Signer,
//! enabling browser-based applications to sign Ethereum transactions, EIP-712
//! typed data, and EIP-191 messages using a YubiKey's secp256r1 (P-256) keys
//! for [EIP-7951] verification.
//!
//! # Browser & Transport Support
//!
//! Standard Chromium browsers block raw WebUSB access to YubiKey PIV applets
//! twice on regular web pages:
//!
//! 1. Chromium's USB blocklist (`usb_blocklist.cc`) blocks Yubico VID `0x1050`
//!    (PIDs `0x0010`–`0x0410`).
//! 2. Chromium enforces USB Smart Card class `0x0B` (CCID) as a WICG Protected
//!    Interface Class on regular `https://` and `http://localhost` pages.
//!
//! Because of this, this crate supports two transports:
//!
//! - **Local PC/SC Bridge (Recommended)**: [`YubiKeyDevice::connect_bridge`]
//!   connects to `yubikey-cli bridge` over a hardened loopback HTTP endpoint
//!   (`http://127.0.0.1:8765`) with per-session Bearer auth, exact `Origin`
//!   allowlist, and PIV-only APDU allowlist. Works in Chrome, Firefox, Safari,
//!   Edge, and Brave on macOS, Linux, and Windows.
//! - **WebUSB (Experimental)**: [`YubiKeyDevice::connect`] targets non-blocklisted
//!   CCID devices or Isolated Web Apps with unrestricted USB permissions.
//!
//! # Quick Start (Local PC/SC Bridge)
//!
//! ```javascript
//! import init, { YubiKeyDevice } from 'yubikey-evm-signer';
//!
//! // Initialize WASM module once
//! await init();
//!
//! // Connect to the local PC/SC bridge started with `just cli-bridge`
//! const device = await YubiKeyDevice.connectBridge(
//!     "http://127.0.0.1:8765",
//!     "<session-bearer-token>"
//! );
//!
//! // Read existing Ethereum address (non-destructive; requires PIV certificate in slot)
//! const address = await device.getAddress();
//! console.log("Ethereum address:", address);
//!
//! // Sign an EIP-1559 transaction (returns 65-byte low-S signature r || s || v)
//! const tx = JSON.stringify({
//!     type: "eip1559",
//!     chain_id: 1,
//!     nonce: 0,
//!     max_priority_fee_per_gas: "1000000000",
//!     max_fee_per_gas: "20000000000",
//!     gas_limit: 21000,
//!     to: "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD20",
//!     value: "1000000000000000000",
//!     input: "0x"
//! });
//! const signature = await device.signTransaction("<your-pin>", tx);
//!
//! // Disconnect when done
//! await device.disconnect();
//! ```
//!
//! [EIP-7951]: https://eips.ethereum.org/EIPS/eip-7951

pub mod bridge_transport;
pub mod device;
pub mod error;
pub mod transport;

pub use bridge_transport::BridgeTransport;
pub use device::YubiKeyDevice;
pub use error::{WasmError, WasmResult};
pub use transport::WebUsbTransport;

use wasm_bindgen::prelude::*;

/// Initializes the WASM module.
///
/// This function is automatically called when the module is loaded,
/// but can be called explicitly if needed.
#[wasm_bindgen(start)]
#[allow(clippy::missing_const_for_fn)]
pub fn init() {
    // Nothing to initialize for now
}

/// Checks whether WebUSB is available in the current browser context.
///
/// Requires both a secure context (`window.isSecureContext === true`) and a
/// non-null `navigator.usb` object. Note that even when this returns `true`,
/// Chromium blocks YubiKey VID `0x1050` and CCID class `0x0B` on standard web
/// pages; use [`YubiKeyDevice::connect_bridge`] for full cross-browser support.
#[wasm_bindgen(js_name = "isWebUsbSupported")]
pub fn is_webusb_supported() -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    if !window.is_secure_context() {
        return false;
    }
    let navigator: web_sys::Navigator = window.navigator();
    match js_sys::Reflect::get(&navigator, &JsValue::from_str("usb")) {
        Ok(usb) => !usb.is_null() && !usb.is_undefined() && usb.is_object(),
        Err(_) => false,
    }
}

/// Returns the library version string (e.g., `"0.0.1"`).
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
