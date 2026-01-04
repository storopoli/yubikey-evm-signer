//! WebUSB transport implementation for YubiKey communication.
//!
//! This module provides a WebUSB-based transport layer that implements
//! the [`Transport`] trait from the core library. It enables browser-based
//! applications to communicate with YubiKey devices via the WebUSB API.
//!
//! # Browser Support
//!
//! WebUSB is only supported in Chromium-based browsers (Chrome, Edge, Opera).
//! Firefox and Safari do not support WebUSB.
//!
//! # Security
//!
//! WebUSB requires a secure context (HTTPS) and user gesture for device
//! selection. The user must explicitly grant permission to access the device.
//!
//! # Example
//!
//! ```ignore
//! use yubikey_evm_signer_wasm::transport::WebUsbTransport;
//!
//! // Request device access (must be triggered by user gesture)
//! let transport = WebUsbTransport::request_device().await?;
//!
//! // Use transport with PIV session
//! let session = PivSession::new(Box::new(transport));
//! ```

use std::fmt;

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{UsbDevice, UsbEndpoint, UsbInterface};

use yubikey_evm_signer_core::yubikey::apdu::{Apdu, ApduResponse};

use crate::error::{WasmError, WasmResult};

/// YubiKey USB vendor ID.
const YUBIKEY_VENDOR_ID: u16 = 0x1050;

/// CCID (Chip Card Interface Device) interface class.
const CCID_INTERFACE_CLASS: u8 = 0x0B;

/// Maximum packet size for USB transfers.
const MAX_PACKET_SIZE: usize = 64;

/// CCID command: PC_to_RDR_XfrBlock
const CCID_PC_TO_RDR_XFRBLOCK: u8 = 0x6F;

/// CCID response: RDR_to_PC_DataBlock
const CCID_RDR_TO_PC_DATABLOCK: u8 = 0x80;

/// WebUSB transport for YubiKey communication.
///
/// This transport implementation uses the WebUSB API to communicate
/// with YubiKey devices in a browser environment.
pub struct WebUsbTransport {
    /// The USB device handle.
    device: UsbDevice,

    /// The CCID interface number.
    interface_number: u8,

    /// The bulk-out endpoint.
    endpoint_out: u8,

    /// The bulk-in endpoint.
    endpoint_in: u8,

    /// CCID sequence number for message ordering.
    sequence: u8,

    /// Whether the device is currently connected.
    connected: bool,
}

impl fmt::Debug for WebUsbTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebUsbTransport")
            .field("interface_number", &self.interface_number)
            .field("endpoint_out", &self.endpoint_out)
            .field("endpoint_in", &self.endpoint_in)
            .field("sequence", &self.sequence)
            .field("connected", &self.connected)
            .finish_non_exhaustive()
    }
}

impl WebUsbTransport {
    /// Requests access to a YubiKey device via WebUSB.
    ///
    /// This method must be called in response to a user gesture (e.g., button click).
    /// It displays the browser's device picker dialog allowing the user to select
    /// their YubiKey.
    ///
    /// # Returns
    ///
    /// A [`WasmResult`] containing the transport if successful.
    ///
    /// # Errors
    ///
    /// - [`WasmError::WebUsbNotSupported`] if WebUSB is not available
    /// - [`WasmError::DeviceNotFound`] if no device was selected
    /// - [`WasmError::DeviceOpenFailed`] if the device could not be opened
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Must be called from a click handler or similar user gesture
    /// let transport = WebUsbTransport::request_device().await?;
    /// ```
    pub async fn request_device() -> WasmResult<Self> {
        let window: web_sys::Window = web_sys::window().ok_or(WasmError::WebUsbNotSupported)?;
        let navigator: web_sys::Navigator = window.navigator();
        let usb = navigator.usb();

        // Create filter for YubiKey devices
        let filter = web_sys::UsbDeviceFilter::new();
        filter.set_vendor_id(YUBIKEY_VENDOR_ID);

        let filters = js_sys::Array::new();
        filters.push(&filter);

        let options = web_sys::UsbDeviceRequestOptions::new(&filters);

        // Request device access (shows browser picker)
        let device_promise = usb.request_device(&options);
        let device: UsbDevice = JsFuture::from(device_promise)
            .await
            .map_err(|_| WasmError::DeviceNotFound)?
            .unchecked_into();

        // Open the device
        JsFuture::from(device.open())
            .await
            .map_err(|e| WasmError::DeviceOpenFailed(format!("{e:?}")))?;

        // Find and claim the CCID interface
        let (interface_number, endpoint_out, endpoint_in) =
            Self::find_ccid_interface(&device).await?;

        // Select configuration if needed
        if device.configuration().is_none() {
            JsFuture::from(device.select_configuration(1))
                .await
                .map_err(|e| WasmError::DeviceOpenFailed(format!("config: {e:?}")))?;
        }

        // Claim the interface
        JsFuture::from(device.claim_interface(interface_number))
            .await
            .map_err(|e| WasmError::InterfaceClaimFailed(format!("{e:?}")))?;

        Ok(Self {
            device,
            interface_number,
            endpoint_out,
            endpoint_in,
            sequence: 0,
            connected: true,
        })
    }

    /// Finds the CCID interface and its endpoints on the device.
    async fn find_ccid_interface(device: &UsbDevice) -> WasmResult<(u8, u8, u8)> {
        let config = device
            .configuration()
            .ok_or_else(|| WasmError::DeviceOpenFailed("no configuration".to_string()))?;

        let interfaces = config.interfaces();
        for i in 0..interfaces.length() {
            let interface: UsbInterface = interfaces.get(i).unchecked_into();
            let alternates = interface.alternates();

            for j in 0..alternates.length() {
                let alt: web_sys::UsbAlternateInterface = alternates.get(j).unchecked_into();

                if alt.interface_class() == CCID_INTERFACE_CLASS {
                    let endpoints = alt.endpoints();
                    let mut endpoint_out = None;
                    let mut endpoint_in = None;

                    for k in 0..endpoints.length() {
                        let ep: UsbEndpoint = endpoints.get(k).unchecked_into();
                        let ep_type = ep.type_();

                        if ep_type == web_sys::UsbEndpointType::Bulk {
                            let direction = ep.direction();
                            if direction == web_sys::UsbDirection::Out {
                                endpoint_out = Some(ep.endpoint_number());
                            } else if direction == web_sys::UsbDirection::In {
                                endpoint_in = Some(ep.endpoint_number() | 0x80);
                            }
                        }
                    }

                    if let (Some(out), Some(inp)) = (endpoint_out, endpoint_in) {
                        return Ok((interface.interface_number(), out, inp));
                    }
                }
            }
        }

        Err(WasmError::DeviceOpenFailed(
            "CCID interface not found".to_string(),
        ))
    }

    /// Sends raw data to the device.
    async fn send_raw(&self, data: &[u8]) -> WasmResult<()> {
        let mut data_copy = data.to_vec();
        let promise = self
            .device
            .transfer_out_with_u8_slice(self.endpoint_out, &mut data_copy)
            .map_err(|e| WasmError::UsbError(format!("transfer_out: {e:?}")))?;

        let result = JsFuture::from(promise)
            .await
            .map_err(|e| WasmError::UsbError(format!("transfer_out: {e:?}")))?;

        let transfer: web_sys::UsbOutTransferResult = result.unchecked_into();
        if transfer.status() != web_sys::UsbTransferStatus::Ok {
            return Err(WasmError::UsbError(format!(
                "transfer status: {:?}",
                transfer.status()
            )));
        }

        Ok(())
    }

    /// Receives raw data from the device.
    async fn receive_raw(&self, max_len: usize) -> WasmResult<Vec<u8>> {
        let promise = self.device.transfer_in(
            self.endpoint_in & 0x7F, // Remove direction bit
            max_len as u32,
        );

        let result = JsFuture::from(promise)
            .await
            .map_err(|e| WasmError::UsbError(format!("transfer_in: {e:?}")))?;

        let transfer: web_sys::UsbInTransferResult = result.unchecked_into();
        if transfer.status() != web_sys::UsbTransferStatus::Ok {
            return Err(WasmError::UsbError(format!(
                "transfer status: {:?}",
                transfer.status()
            )));
        }

        if let Some(data) = transfer.data() {
            let data_view: js_sys::DataView = data;
            let len = data_view.byte_length();
            let mut buffer = vec![0u8; len];
            for (i, byte) in buffer.iter_mut().enumerate() {
                *byte = data_view.get_uint8(i);
            }
            Ok(buffer)
        } else {
            Ok(Vec::new())
        }
    }

    /// Wraps an APDU in a CCID message.
    fn wrap_ccid(&mut self, apdu_bytes: &[u8]) -> Vec<u8> {
        let len = apdu_bytes.len();
        let mut ccid = Vec::with_capacity(10 + len);

        // CCID header
        ccid.push(CCID_PC_TO_RDR_XFRBLOCK);
        ccid.extend_from_slice(&(len as u32).to_le_bytes());
        ccid.push(0); // Slot number
        ccid.push(self.sequence);
        ccid.push(0); // BWI (block waiting time)
        ccid.push(0); // Level parameter (short APDU)
        ccid.push(0); // Reserved

        // APDU data
        ccid.extend_from_slice(apdu_bytes);

        self.sequence = self.sequence.wrapping_add(1);

        ccid
    }

    /// Unwraps a CCID response to extract the APDU response.
    fn unwrap_ccid(&self, ccid: &[u8]) -> WasmResult<Vec<u8>> {
        if ccid.len() < 10 {
            return Err(WasmError::UsbError("CCID response too short".to_string()));
        }

        if ccid[0] != CCID_RDR_TO_PC_DATABLOCK {
            return Err(WasmError::UsbError(format!(
                "unexpected CCID message type: 0x{:02X}",
                ccid[0]
            )));
        }

        // Check for errors in status byte
        let error = ccid[8];
        if error != 0 {
            return Err(WasmError::UsbError(format!("CCID error: 0x{error:02X}")));
        }

        // Extract data length
        let data_len = u32::from_le_bytes([ccid[1], ccid[2], ccid[3], ccid[4]]) as usize;

        if ccid.len() < 10 + data_len {
            return Err(WasmError::UsbError("CCID data length mismatch".to_string()));
        }

        Ok(ccid[10..10 + data_len].to_vec())
    }

    /// Transmits an APDU and receives the response (async version).
    pub async fn transmit_async(&mut self, apdu: &Apdu) -> WasmResult<ApduResponse> {
        let apdu_bytes = apdu.to_bytes();
        let ccid_command = self.wrap_ccid(&apdu_bytes);

        // Send command
        self.send_raw(&ccid_command).await?;

        // Receive response
        let ccid_response = self.receive_raw(MAX_PACKET_SIZE * 4).await?;
        let apdu_response = self.unwrap_ccid(&ccid_response)?;

        if apdu_response.len() < 2 {
            return Err(WasmError::UsbError("APDU response too short".to_string()));
        }

        Ok(ApduResponse::new(apdu_response))
    }

    /// Closes the USB connection.
    pub async fn close(&mut self) -> WasmResult<()> {
        if self.connected {
            // Release the interface
            let _ = JsFuture::from(self.device.release_interface(self.interface_number)).await;

            // Close the device
            let _ = JsFuture::from(self.device.close()).await;

            self.connected = false;
        }
        Ok(())
    }
}

impl WebUsbTransport {
    /// Checks if the transport is connected.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.connected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ccid_constants() {
        assert_eq!(YUBIKEY_VENDOR_ID, 0x1050);
        assert_eq!(CCID_INTERFACE_CLASS, 0x0B);
    }
}
