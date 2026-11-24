//! WebUSB CCID transport implementation for YubiKey communication.
//!
//! This module provides a WebUSB-based CCID transport and pure, target-independent
//! CCID framing/parsing helpers.
//!
//! # Chromium WebUSB Restriction
//!
//! On standard web pages (`https://` or `http://localhost`), Chromium blocks
//! YubiKey PIV access over raw WebUSB both via the USB device blocklist
//! (Yubico VID `0x1050`, PIDs `0x0010`–`0x0410`) and the WICG Smart Card
//! protected interface class (`0x0B`). For standard browsers across macOS,
//! Linux, and Windows, prefer [`BridgeTransport`](crate::bridge_transport::BridgeTransport)
//! via [`YubiKeyDevice::connect_bridge`](crate::YubiKeyDevice::connect_bridge).

use std::fmt;

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{DomException, UsbConfiguration, UsbDevice, UsbEndpoint, UsbInterface};
use zeroize::Zeroize;

use yubikey_evm_signer_core::yubikey::Slot;
use yubikey_evm_signer_core::yubikey::apdu::{Apdu, ApduResponse};
use yubikey_evm_signer_core::yubikey::piv::build_get_response_apdu;

use crate::error::{WasmError, WasmResult};

/// YubiKey USB vendor ID (`0x1050`).
const YUBIKEY_VENDOR_ID: u16 = 0x1050;

/// CCID (Chip Card Interface Device) USB interface class (`0x0B`).
const CCID_INTERFACE_CLASS: u8 = 0x0B;

/// Default USB full-speed bulk packet size.
const DEFAULT_MAX_PACKET_SIZE: usize = 64;

/// CCID bulk message header length in bytes.
pub const CCID_HEADER_LEN: usize = 10;

/// Maximum CCID payload length accepted from the device (16 KiB).
pub const CCID_MAX_DATA_LEN: usize = 16 * 1024;

/// Maximum number of CCID WTX (time-extension) frames tolerated per command.
const CCID_MAX_WTX_ITERATIONS: usize = 64;

/// Maximum number of ISO 7816-4 `GET RESPONSE` chaining iterations.
const MAX_RESPONSE_CHUNKS: usize = 128;

/// Maximum consecutive leading USB zero-length packet (ZLP) terminators skipped
/// before the start of a CCID frame.
const CCID_MAX_LEADING_ZLPS: usize = 2;

/// CCID command: `PC_to_RDR_IccPowerOn` (`0x62`).
pub const CCID_PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;

/// CCID command: `PC_to_RDR_XfrBlock` (`0x6F`).
pub const CCID_PC_TO_RDR_XFRBLOCK: u8 = 0x6F;

/// CCID response: `RDR_to_PC_DataBlock` (`0x80`).
pub const CCID_RDR_TO_PC_DATABLOCK: u8 = 0x80;

/// Decoded command status bits (`bStatus[7:6]`) from a CCID response header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcidCommandStatus {
    /// `0x00`: Processed without error.
    ProcessedWithoutError,
    /// `0x40`: Failed (see `bError`).
    Failed,
    /// `0x80`: Time extension requested (WTX — host must keep reading).
    TimeExtensionRequested,
    /// `0xC0`: Reserved for future use.
    Reserved,
}

/// Parsed 10-byte CCID `RDR_to_PC_DataBlock` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CcidHeader {
    /// CCID message type (`bMessageType`).
    pub msg_type: u8,
    /// Payload length (`dwLength`).
    pub data_len: usize,
    /// Smart card slot index (`bSlot`).
    pub slot: u8,
    /// Sequence number (`bSeq`).
    pub seq: u8,
    /// ICC status bits (`bStatus & 0x03`; `0` = ICC present & active).
    pub icc_status: u8,
    /// Command status (`bStatus & 0xC0`).
    pub cmd_status: CcidCommandStatus,
    /// Error / WTX multiplier byte (`bError`).
    pub error: u8,
    /// Chain parameter (`bChainParameter`).
    pub chain_param: u8,
}

/// Result of unwrapping a single CCID `RDR_to_PC_DataBlock` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CcidDatablock {
    /// Complete APDU or ATR payload bytes.
    Data(Vec<u8>),
    /// Time extension (WTX) frame; host should read another response frame.
    TimeExtension,
}

/// Builds a 10-byte CCID `PC_to_RDR_IccPowerOn` frame with automatic voltage selection (`0x00`).
#[must_use]
pub fn wrap_ccid_power_on(seq: u8) -> Vec<u8> {
    vec![
        CCID_PC_TO_RDR_ICC_POWER_ON,
        0x00,
        0x00,
        0x00,
        0x00, // dwLength = 0
        0x00, // bSlot = 0
        seq,  // bSeq
        0x00, // bPowerSelect = auto
        0x00,
        0x00, // abRFU
    ]
}

/// Wraps raw APDU bytes into a CCID `PC_to_RDR_XfrBlock` frame.
///
/// # Errors
///
/// Returns [`WasmError::UsbError`] if `apdu_bytes.len()` exceeds [`CCID_MAX_DATA_LEN`].
pub fn wrap_ccid_xfr_block(seq: u8, apdu_bytes: &[u8]) -> WasmResult<Vec<u8>> {
    if apdu_bytes.len() > CCID_MAX_DATA_LEN {
        return Err(WasmError::UsbError(format!(
            "APDU length {} exceeds CCID maximum {}",
            apdu_bytes.len(),
            CCID_MAX_DATA_LEN
        )));
    }

    let len = apdu_bytes.len();
    let mut ccid = Vec::with_capacity(CCID_HEADER_LEN + len);

    ccid.push(CCID_PC_TO_RDR_XFRBLOCK);
    ccid.extend_from_slice(&(len as u32).to_le_bytes());
    ccid.push(0x00); // bSlot = 0
    ccid.push(seq); // bSeq
    ccid.push(0x00); // bBWI = 0
    ccid.push(0x00); // wLevelParameter low
    ccid.push(0x00); // wLevelParameter high
    ccid.extend_from_slice(apdu_bytes);

    Ok(ccid)
}

/// Parses and validates a 10-byte CCID `RDR_to_PC_DataBlock` header.
///
/// # Errors
///
/// Returns [`WasmError::UsbError`] if the slice is shorter than 10 bytes, the
/// message type is not `RDR_to_PC_DataBlock` (`0x80`), or `dwLength` exceeds
/// [`CCID_MAX_DATA_LEN`].
pub fn parse_ccid_header(bytes: &[u8]) -> WasmResult<CcidHeader> {
    if bytes.len() < CCID_HEADER_LEN {
        return Err(WasmError::UsbError(format!(
            "CCID response too short: expected at least {CCID_HEADER_LEN} bytes, got {}",
            bytes.len()
        )));
    }

    let msg_type = bytes[0];
    if msg_type != CCID_RDR_TO_PC_DATABLOCK {
        return Err(WasmError::UsbError(format!(
            "unexpected CCID message type: 0x{msg_type:02X}"
        )));
    }

    let data_len_u32 = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    let data_len = usize::try_from(data_len_u32)
        .map_err(|_| WasmError::UsbError("CCID data length overflow".to_string()))?;

    if data_len > CCID_MAX_DATA_LEN {
        return Err(WasmError::UsbError(format!(
            "CCID data length {data_len} exceeds maximum {CCID_MAX_DATA_LEN}"
        )));
    }

    let slot = bytes[5];
    let seq = bytes[6];
    let b_status = bytes[7];
    let icc_status = b_status & 0x03;
    let cmd_status = match b_status & 0xC0 {
        0x00 => CcidCommandStatus::ProcessedWithoutError,
        0x40 => CcidCommandStatus::Failed,
        0x80 => CcidCommandStatus::TimeExtensionRequested,
        _ => CcidCommandStatus::Reserved,
    };

    Ok(CcidHeader {
        msg_type,
        data_len,
        slot,
        seq,
        icc_status,
        cmd_status,
        error: bytes[8],
        chain_param: bytes[9],
    })
}

/// Unwraps a complete CCID `RDR_to_PC_DataBlock` frame and validates slot, sequence,
/// ICC status, command status, and length.
///
/// # Errors
///
/// Returns [`WasmError::UsbError`] on header mismatch, inactive ICC, CCID error
/// status, or truncated payload.
pub fn unwrap_ccid_datablock(ccid: &[u8], expected_seq: u8) -> WasmResult<CcidDatablock> {
    let header = parse_ccid_header(ccid)?;

    if header.slot != 0 {
        return Err(WasmError::UsbError(format!(
            "unexpected CCID slot {}, expected 0",
            header.slot
        )));
    }

    if header.seq != expected_seq {
        return Err(WasmError::UsbError(format!(
            "CCID sequence mismatch: expected {expected_seq}, got {}",
            header.seq
        )));
    }

    if header.icc_status != 0 {
        return Err(WasmError::UsbError(format!(
            "CCID ICC not present/active (icc_status=0x{:02X}, bError=0x{:02X})",
            header.icc_status, header.error
        )));
    }

    match header.cmd_status {
        CcidCommandStatus::TimeExtensionRequested => Ok(CcidDatablock::TimeExtension),
        CcidCommandStatus::Failed => Err(WasmError::UsbError(format!(
            "CCID command failed (bError=0x{:02X})",
            header.error
        ))),
        CcidCommandStatus::Reserved => Err(WasmError::UsbError(format!(
            "CCID reserved status (bStatus=0x{:02X}, bError=0x{:02X})",
            ccid[7], header.error
        ))),
        CcidCommandStatus::ProcessedWithoutError => {
            let end = CCID_HEADER_LEN
                .checked_add(header.data_len)
                .ok_or_else(|| WasmError::UsbError("CCID data length overflow".to_string()))?;

            if ccid.len() < end {
                return Err(WasmError::UsbError(format!(
                    "CCID frame truncated: need {end} bytes, got {}",
                    ccid.len()
                )));
            }

            Ok(CcidDatablock::Data(ccid[CCID_HEADER_LEN..end].to_vec()))
        }
    }
}

/// Discovered CCID USB interface and endpoint metadata.
struct CcidInterfaceInfo {
    interface_number: u8,
    alternate_setting: u8,
    endpoint_out: u8,
    endpoint_in: u8,
    max_packet_size: usize,
}

/// WebUSB CCID transport for browser-based YubiKey communication.
pub struct WebUsbTransport {
    /// The USB device handle.
    device: UsbDevice,

    /// The CCID interface number.
    interface_number: u8,

    /// The bulk-out endpoint number.
    endpoint_out: u8,

    /// The bulk-in endpoint number (without direction bit).
    endpoint_in: u8,

    /// Bulk-in endpoint packet size.
    max_packet_size: usize,

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
            .field("max_packet_size", &self.max_packet_size)
            .field("sequence", &self.sequence)
            .field("connected", &self.connected)
            .finish_non_exhaustive()
    }
}

impl WebUsbTransport {
    /// Requests access to a YubiKey device via WebUSB, claims its CCID interface,
    /// and powers on the ICC (`PC_to_RDR_IccPowerOn`).
    ///
    /// Must be called from a user gesture (e.g., button click).
    ///
    /// # Errors
    ///
    /// - [`WasmError::WebUsbNotSupported`] if WebUSB is unavailable or context is insecure
    /// - [`WasmError::DeviceNotFound`] if the user cancelled or no permitted device matched
    /// - [`WasmError::InterfaceClaimFailed`] if Chromium's protected class policy or OS driver blocks CCID
    /// - [`WasmError::DeviceOpenFailed`] / [`WasmError::UsbError`] on USB/CCID setup errors
    pub async fn request_device() -> WasmResult<Self> {
        if !crate::is_webusb_supported() {
            return Err(WasmError::WebUsbNotSupported);
        }

        let window: web_sys::Window = web_sys::window().ok_or(WasmError::WebUsbNotSupported)?;
        let navigator: web_sys::Navigator = window.navigator();
        let usb = navigator.usb();

        // Create filter for YubiKey devices
        let filter = web_sys::UsbDeviceFilter::new();
        filter.set_vendor_id(YUBIKEY_VENDOR_ID);

        let options = web_sys::UsbDeviceRequestOptions::new(&[filter]);

        // Request device access (shows browser picker)
        let device_promise = usb.request_device(&options);
        let device: UsbDevice = JsFuture::from(device_promise)
            .await
            .map_err(classify_request_device_error)?
            .unchecked_into();

        // Open the device
        JsFuture::from(device.open())
            .await
            .map_err(|e| WasmError::DeviceOpenFailed(format_js_error(&e)))?;

        // Run remaining setup, closing and releasing on any error
        match Self::setup_opened_device(device.clone()).await {
            Ok(transport) => Ok(transport),
            Err((err, claimed_iface)) => {
                if let Some(iface) = claimed_iface {
                    let _ = JsFuture::from(device.release_interface(iface)).await;
                }
                let _ = JsFuture::from(device.close()).await;
                Err(err)
            }
        }
    }

    /// Configures an opened USB device, claims the CCID interface, and sends `IccPowerOn`.
    async fn setup_opened_device(device: UsbDevice) -> Result<Self, (WasmError, Option<u8>)> {
        // Select configuration BEFORE inspecting device.configuration()
        if device.configuration().is_none() {
            let config_value = Self::first_configuration_value(&device);
            JsFuture::from(device.select_configuration(config_value))
                .await
                .map_err(|e| {
                    (
                        WasmError::DeviceOpenFailed(format!(
                            "select_configuration({config_value}): {}",
                            format_js_error(&e)
                        )),
                        None,
                    )
                })?;
        }

        // Find the CCID interface and endpoints
        let info = Self::find_ccid_interface(&device).map_err(|e| (e, None))?;

        // Claim the CCID interface
        JsFuture::from(device.claim_interface(info.interface_number))
            .await
            .map_err(|e| (classify_claim_interface_error(e), None))?;

        // Select alternate setting if non-zero
        if info.alternate_setting != 0 {
            JsFuture::from(
                device.select_alternate_interface(info.interface_number, info.alternate_setting),
            )
            .await
            .map_err(|e| {
                (
                    WasmError::InterfaceClaimFailed(format!(
                        "select_alternate_interface({}, {}): {}",
                        info.interface_number,
                        info.alternate_setting,
                        format_js_error(&e)
                    )),
                    Some(info.interface_number),
                )
            })?;
        }

        let mut transport = Self {
            device,
            interface_number: info.interface_number,
            endpoint_out: info.endpoint_out,
            endpoint_in: info.endpoint_in,
            max_packet_size: info.max_packet_size,
            sequence: 0,
            connected: true,
        };

        // Power on the ICC and validate the ATR DataBlock response
        let seq = transport.next_sequence();
        let power_on = wrap_ccid_power_on(seq);
        let atr = transport
            .send_ccid_and_wait(&power_on, seq)
            .await
            .map_err(|e| (e, Some(info.interface_number)))?;

        if atr.is_empty() {
            return Err((
                WasmError::UsbError("CCID IccPowerOn returned empty ATR".to_string()),
                Some(info.interface_number),
            ));
        }

        Ok(transport)
    }

    /// Returns the first available USB configuration value, defaulting to `1`.
    fn first_configuration_value(device: &UsbDevice) -> u8 {
        let configs = device.configurations();
        if configs.length() > 0 {
            let first: UsbConfiguration = configs.get(0).unchecked_into();
            first.configuration_value()
        } else {
            1
        }
    }

    /// Finds the CCID interface, alternate setting, and bulk endpoints on the device.
    fn find_ccid_interface(device: &UsbDevice) -> WasmResult<CcidInterfaceInfo> {
        let config = device.configuration().ok_or_else(|| {
            WasmError::DeviceOpenFailed("no active USB configuration".to_string())
        })?;

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
                    let mut max_packet_size = DEFAULT_MAX_PACKET_SIZE;

                    for k in 0..endpoints.length() {
                        let ep: UsbEndpoint = endpoints.get(k).unchecked_into();
                        if ep.type_() == web_sys::UsbEndpointType::Bulk {
                            match ep.direction() {
                                web_sys::UsbDirection::Out => {
                                    endpoint_out = Some(ep.endpoint_number());
                                }
                                web_sys::UsbDirection::In => {
                                    endpoint_in = Some(ep.endpoint_number());
                                    let pkt = ep.packet_size() as usize;
                                    if pkt > 0 {
                                        max_packet_size = pkt;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    if let (Some(out), Some(inp)) = (endpoint_out, endpoint_in) {
                        return Ok(CcidInterfaceInfo {
                            interface_number: interface.interface_number(),
                            alternate_setting: alt.alternate_setting(),
                            endpoint_out: out,
                            endpoint_in: inp,
                            max_packet_size,
                        });
                    }
                }
            }
        }

        Err(WasmError::DeviceOpenFailed(
            "CCID interface (class 0x0B) not found on USB device".to_string(),
        ))
    }

    /// Allocates the next CCID sequence number.
    const fn next_sequence(&mut self) -> u8 {
        let seq = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        seq
    }

    /// Sends all bytes to the bulk-out endpoint, handling partial transfers.
    async fn send_raw(&self, data: &[u8]) -> WasmResult<()> {
        let mut offset = 0usize;
        while offset < data.len() {
            let slice = &data[offset..];
            let promise = self
                .device
                .transfer_out_with_u8_slice(self.endpoint_out, slice)
                .map_err(|e| {
                    WasmError::UsbError(format!("transfer_out: {}", format_js_error(&e)))
                })?;

            let result = JsFuture::from(promise).await.map_err(|e| {
                WasmError::UsbError(format!("transfer_out: {}", format_js_error(&e)))
            })?;

            let transfer: web_sys::UsbOutTransferResult = result.unchecked_into();
            if transfer.status() != web_sys::UsbTransferStatus::Ok {
                return Err(WasmError::UsbError(format!(
                    "transfer_out status: {:?}",
                    transfer.status()
                )));
            }

            let written = transfer.bytes_written() as usize;
            if written == 0 {
                return Err(WasmError::UsbError(
                    "USB transfer_out wrote 0 bytes".to_string(),
                ));
            }
            offset = offset.saturating_add(written);
        }

        Ok(())
    }

    /// Receives a single USB bulk-in transfer of up to `max_len` bytes.
    async fn receive_raw(&self, max_len: usize) -> WasmResult<Vec<u8>> {
        let promise = self.device.transfer_in(self.endpoint_in, max_len as u32);

        let result = JsFuture::from(promise)
            .await
            .map_err(|e| WasmError::UsbError(format!("transfer_in: {}", format_js_error(&e))))?;

        let transfer: web_sys::UsbInTransferResult = result.unchecked_into();
        if transfer.status() != web_sys::UsbTransferStatus::Ok {
            return Err(WasmError::UsbError(format!(
                "transfer_in status: {:?}",
                transfer.status()
            )));
        }

        if let Some(data_view) = transfer.data() {
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

    /// Reads one complete multi-packet CCID `RDR_to_PC_DataBlock` message.
    async fn receive_ccid_message(&self, expected_seq: u8) -> WasmResult<CcidDatablock> {
        let chunk_size = self.max_packet_size.max(DEFAULT_MAX_PACKET_SIZE);
        let mut assembler = CcidFrameAssembler::new(expected_seq, chunk_size * 4);

        loop {
            let packet = self.receive_raw(chunk_size).await?;
            if let Some(block) = assembler.push_packet(&packet)? {
                return Ok(block);
            }
        }
    }

    /// Sends a CCID command and loops through WTX time extensions until data arrives.
    async fn send_ccid_and_wait(&self, ccid_msg: &[u8], expected_seq: u8) -> WasmResult<Vec<u8>> {
        self.send_raw(ccid_msg).await?;

        for _ in 0..CCID_MAX_WTX_ITERATIONS {
            match self.receive_ccid_message(expected_seq).await? {
                CcidDatablock::Data(data) => return Ok(data),
                CcidDatablock::TimeExtension => continue,
            }
        }

        Err(WasmError::Timeout)
    }

    /// Transmits a single APDU and receives its raw [`ApduResponse`].
    ///
    /// # Errors
    ///
    /// Returns [`WasmError::UsbError`], [`WasmError::Timeout`], or [`WasmError::CoreError`].
    pub async fn transmit_async(&mut self, apdu: &Apdu) -> WasmResult<ApduResponse> {
        if !self.connected {
            return Err(WasmError::UsbError(
                "WebUSB transport is disconnected".to_string(),
            ));
        }

        let mut apdu_bytes = apdu
            .to_bytes()
            .map_err(|e| WasmError::CoreError(e.to_string()))?;
        let seq = self.next_sequence();
        let mut ccid_command = wrap_ccid_xfr_block(seq, &apdu_bytes)?;
        apdu_bytes.zeroize();

        let send_result = self.send_ccid_and_wait(&ccid_command, seq).await;
        ccid_command.zeroize();

        let apdu_response = send_result?;
        ApduResponse::try_from_bytes(apdu_response).map_err(|e| WasmError::UsbError(e.to_string()))
    }

    /// Transmits an APDU, automatically handling ISO 7816-4 `0x6C XX` wrong-`Le`
    /// retries and `0x61 XX` `GET RESPONSE` chaining (capped at 16 KiB / 128 chunks).
    ///
    /// # Errors
    ///
    /// Returns transport, timeout, or mapped PIV status-word errors.
    pub async fn transmit_full_async(
        &mut self,
        apdu: &Apdu,
        slot: Option<Slot>,
    ) -> WasmResult<Vec<u8>> {
        transmit_apdu_full(self, apdu, slot).await
    }

    /// Closes the USB connection and releases the claimed interface.
    ///
    /// # Errors
    ///
    /// Always returns `Ok(())` after best-effort interface release and device close.
    pub async fn close(&mut self) -> WasmResult<()> {
        if self.connected {
            let _ = JsFuture::from(self.device.release_interface(self.interface_number)).await;
            let _ = JsFuture::from(self.device.close()).await;
            self.connected = false;
        }
        Ok(())
    }

    /// Checks if the transport is connected.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.connected
    }
}

impl AsyncApduTransport for WebUsbTransport {
    async fn transmit_one(&mut self, apdu: &Apdu) -> WasmResult<ApduResponse> {
        self.transmit_async(apdu).await
    }

    fn transport_error(&self, msg: String) -> WasmError {
        WasmError::UsbError(msg)
    }
}

/// Internal trait shared by browser APDU transports for ISO 7816-4 retry and chaining.
pub(crate) trait AsyncApduTransport {
    /// Transmits a single APDU and returns its raw response.
    async fn transmit_one(&mut self, apdu: &Apdu) -> WasmResult<ApduResponse>;

    /// Wraps a transport-level framing/limit message into the appropriate [`WasmError`].
    fn transport_error(&self, msg: String) -> WasmError;
}

/// Transmits an APDU across any [`AsyncApduTransport`], handling ISO 7816-4
/// `0x6C XX` wrong-`Le` retries and `0x61 XX` `GET RESPONSE` chaining (capped
/// at 16 KiB / 128 chunks).
pub(crate) async fn transmit_apdu_full<T: AsyncApduTransport>(
    transport: &mut T,
    apdu: &Apdu,
    slot: Option<Slot>,
) -> WasmResult<Vec<u8>> {
    let mut response = transport.transmit_one(apdu).await?;

    if let Some(correct_le) = response.wrong_le() {
        let mut retry_apdu = apdu.with_le_override(Some(u32::from(correct_le)));
        let retry_result = transport.transmit_one(&retry_apdu).await;
        retry_apdu.zeroize_data();
        response = retry_result?;
    }

    check_response(&response, slot)?;

    let mut remaining = response.remaining_bytes();
    let mut data = response.into_data();
    if data.len() > CCID_MAX_DATA_LEN {
        return Err(
            transport.transport_error("APDU response exceeded maximum allowed size".to_string())
        );
    }

    let mut chunks = 0usize;
    while let Some(sw2) = remaining {
        chunks += 1;
        if chunks > MAX_RESPONSE_CHUNKS {
            return Err(transport.transport_error(
                "APDU response exceeded maximum GET RESPONSE chunk limit".to_string(),
            ));
        }

        let get_resp = build_get_response_apdu(sw2);
        let mut chunk_resp = transport.transmit_one(&get_resp).await?;

        if let Some(correct_le) = chunk_resp.wrong_le() {
            let retry = get_resp.with_le_override(Some(u32::from(correct_le)));
            chunk_resp = transport.transmit_one(&retry).await?;
        }

        check_response(&chunk_resp, slot)?;

        remaining = chunk_resp.remaining_bytes();
        let chunk = chunk_resp.into_data();
        if data.len().saturating_add(chunk.len()) > CCID_MAX_DATA_LEN {
            return Err(transport.transport_error(
                "chained APDU response exceeded maximum allowed size".to_string(),
            ));
        }
        data.extend_from_slice(&chunk);
    }

    Ok(data)
}

/// Stateful assembler for multi-packet CCID `RDR_to_PC_DataBlock` USB transfers.
///
/// Tolerates up to [`CCID_MAX_LEADING_ZLPS`] leading zero-length packets (legal
/// USB bulk transfer terminators left behind by a previous packet-aligned CCID
/// frame) while rejecting mid-frame or unbounded empty transfers.
#[derive(Debug)]
struct CcidFrameAssembler {
    expected_seq: u8,
    buf: Vec<u8>,
    skipped_leading_zlps: usize,
}

impl CcidFrameAssembler {
    fn new(expected_seq: u8, initial_capacity: usize) -> Self {
        Self {
            expected_seq,
            buf: Vec::with_capacity(initial_capacity),
            skipped_leading_zlps: 0,
        }
    }

    fn push_packet(&mut self, packet: &[u8]) -> WasmResult<Option<CcidDatablock>> {
        if packet.is_empty() {
            if self.buf.is_empty() && self.skipped_leading_zlps < CCID_MAX_LEADING_ZLPS {
                self.skipped_leading_zlps += 1;
                return Ok(None);
            }
            return Err(WasmError::UsbError(
                "unexpected zero-length USB bulk-in transfer".to_string(),
            ));
        }

        let max_total = CCID_HEADER_LEN + CCID_MAX_DATA_LEN;
        if self.buf.len().saturating_add(packet.len()) > max_total {
            return Err(WasmError::UsbError(format!(
                "CCID response exceeded maximum frame size ({max_total} bytes)"
            )));
        }
        self.buf.extend_from_slice(packet);

        if self.buf.len() >= CCID_HEADER_LEN {
            let header = parse_ccid_header(&self.buf)?;
            let expected_total = CCID_HEADER_LEN + header.data_len;
            if self.buf.len() >= expected_total {
                return unwrap_ccid_datablock(&self.buf[..expected_total], self.expected_seq)
                    .map(Some);
            }
        }

        Ok(None)
    }
}

/// Checks an [`ApduResponse`] with optional slot-aware error mapping.
fn check_response(response: &ApduResponse, slot: Option<Slot>) -> WasmResult<()> {
    let res = match slot {
        Some(s) => response.check_for_slot(s),
        None => response.check(),
    };
    res.map_err(WasmError::from)
}

/// Formats a JS exception value into a concise message.
fn format_js_error(value: &JsValue) -> String {
    if let Some(dom) = value.dyn_ref::<DomException>() {
        format!("{}: {}", dom.name(), dom.message())
    } else if let Some(err) = value.dyn_ref::<js_sys::Error>() {
        err.message().into()
    } else if let Some(s) = value.as_string() {
        s
    } else {
        format!("{value:?}")
    }
}

/// Classifies `navigator.usb.requestDevice()` rejections by `DOMException` name.
fn classify_request_device_error(value: JsValue) -> WasmError {
    if let Some(dom) = value.dyn_ref::<DomException>() {
        match dom.name().as_str() {
            "NotFoundError" => return WasmError::DeviceNotFound,
            "SecurityError" => {
                return WasmError::InterfaceClaimFailed(format!(
                    "{} — Chromium blocks YubiKey VID 0x1050 and USB Smart Card (CCID, class 0x0B) on standard web pages; use YubiKeyDevice.connectBridge() with the local PC/SC bridge",
                    dom.message()
                ));
            }
            _ => {
                return WasmError::DeviceOpenFailed(format!("{}: {}", dom.name(), dom.message()));
            }
        }
    }
    WasmError::DeviceOpenFailed(format_js_error(&value))
}

/// Classifies `device.claimInterface()` rejections with Chromium CCID guidance.
fn classify_claim_interface_error(value: JsValue) -> WasmError {
    let details = format_js_error(&value);
    WasmError::InterfaceClaimFailed(format!(
        "{details} — Chromium protects USB Smart Card (CCID, class 0x0B) interfaces on standard web pages and OS PC/SC drivers may hold the device; use YubiKeyDevice.connectBridge() with the local PC/SC bridge"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ccid_constants_and_power_on_frame() {
        assert_eq!(YUBIKEY_VENDOR_ID, 0x1050);
        assert_eq!(CCID_INTERFACE_CLASS, 0x0B);

        let frame = wrap_ccid_power_on(7);
        assert_eq!(frame.len(), CCID_HEADER_LEN);
        assert_eq!(frame[0], CCID_PC_TO_RDR_ICC_POWER_ON);
        assert_eq!(&frame[1..5], &[0, 0, 0, 0]);
        assert_eq!(frame[5], 0); // slot 0
        assert_eq!(frame[6], 7); // seq 7
        assert_eq!(frame[7], 0); // auto voltage
    }

    #[test]
    fn ccid_xfr_block_wrap_and_size_limit() {
        let apdu = [0x00, 0xA4, 0x04, 0x00];
        let frame = wrap_ccid_xfr_block(3, &apdu).unwrap();
        assert_eq!(frame.len(), CCID_HEADER_LEN + 4);
        assert_eq!(frame[0], CCID_PC_TO_RDR_XFRBLOCK);
        assert_eq!(
            u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]),
            4
        );
        assert_eq!(frame[5], 0);
        assert_eq!(frame[6], 3);
        assert_eq!(&frame[10..], &apdu);

        // Oversized payload rejected
        let huge = vec![0u8; CCID_MAX_DATA_LEN + 1];
        assert!(matches!(
            wrap_ccid_xfr_block(0, &huge),
            Err(WasmError::UsbError(_))
        ));
    }

    #[test]
    fn ccid_unwrap_datablock_success_wtx_and_errors() {
        // 1. Valid response with payload [0x90, 0x00]
        let ok_frame = [
            CCID_RDR_TO_PC_DATABLOCK,
            2,
            0,
            0,
            0,    // dwLength = 2
            0,    // slot 0
            5,    // seq 5
            0x00, // icc active + processed ok
            0x00, // bError
            0x00, // bChainParameter
            0x90,
            0x00,
        ];
        assert_eq!(
            unwrap_ccid_datablock(&ok_frame, 5).unwrap(),
            CcidDatablock::Data(vec![0x90, 0x00])
        );

        // 2. WTX time extension (bStatus = 0x80, bError = 0x01 BWT multiplier!)
        let wtx_frame = [
            CCID_RDR_TO_PC_DATABLOCK,
            0,
            0,
            0,
            0,
            0,
            5,
            0x80, // WTX
            0x01, // BWT multiplier (NOT an error!)
            0x00,
        ];
        assert_eq!(
            unwrap_ccid_datablock(&wtx_frame, 5).unwrap(),
            CcidDatablock::TimeExtension
        );

        // 3. Command failed (bStatus = 0x40)
        let fail_frame = [
            CCID_RDR_TO_PC_DATABLOCK,
            0,
            0,
            0,
            0,
            0,
            5,
            0x40,
            0xFE, // ICC_MUTE
            0x00,
        ];
        assert!(matches!(
            unwrap_ccid_datablock(&fail_frame, 5),
            Err(WasmError::UsbError(msg)) if msg.contains("0xFE")
        ));

        // 4. Inactive ICC (icc_status = 1)
        let inactive_frame = [CCID_RDR_TO_PC_DATABLOCK, 0, 0, 0, 0, 0, 5, 0x01, 0x00, 0x00];
        assert!(matches!(
            unwrap_ccid_datablock(&inactive_frame, 5),
            Err(WasmError::UsbError(_))
        ));

        // 5. Sequence mismatch
        assert!(matches!(
            unwrap_ccid_datablock(&ok_frame, 6),
            Err(WasmError::UsbError(msg)) if msg.contains("sequence mismatch")
        ));

        // 6. Slot mismatch
        let mut wrong_slot = ok_frame;
        wrong_slot[5] = 1;
        assert!(matches!(
            unwrap_ccid_datablock(&wrong_slot, 5),
            Err(WasmError::UsbError(msg)) if msg.contains("slot")
        ));

        // 7. Truncated frame
        assert!(matches!(
            unwrap_ccid_datablock(&ok_frame[..11], 5),
            Err(WasmError::UsbError(msg)) if msg.contains("truncated")
        ));

        // 8. Length exceeding CCID_MAX_DATA_LEN
        let huge_len = (CCID_MAX_DATA_LEN as u32 + 1).to_le_bytes();
        let overflow_frame = [
            CCID_RDR_TO_PC_DATABLOCK,
            huge_len[0],
            huge_len[1],
            huge_len[2],
            huge_len[3],
            0,
            5,
            0x00,
            0x00,
            0x00,
        ];
        assert!(matches!(
            unwrap_ccid_datablock(&overflow_frame, 5),
            Err(WasmError::UsbError(msg)) if msg.contains("exceeds maximum")
        ));
    }

    #[test]
    fn ccid_frame_assembler_handles_leading_zlp_and_multi_packet_frames() {
        // 1. Leading ZLP (left over from a prior packet-aligned transfer) followed by a split frame
        let mut frame = vec![
            CCID_RDR_TO_PC_DATABLOCK,
            0x06,
            0x00,
            0x00,
            0x00,
            0x00,
            0x07,
            0x00,
            0x00,
            0x00,
        ];
        frame.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00]);

        let mut asm = CcidFrameAssembler::new(0x07, 64);
        assert!(asm.push_packet(&[]).unwrap().is_none());
        assert!(asm.push_packet(&frame[..8]).unwrap().is_none());
        assert!(asm.push_packet(&frame[8..12]).unwrap().is_none());
        assert_eq!(
            asm.push_packet(&frame[12..]).unwrap(),
            Some(CcidDatablock::Data(vec![
                0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00
            ]))
        );

        // 2. Mid-frame ZLP is rejected
        let mut mid_zlp = CcidFrameAssembler::new(0x07, 64);
        assert!(mid_zlp.push_packet(&frame[..8]).unwrap().is_none());
        assert!(matches!(
            mid_zlp.push_packet(&[]),
            Err(WasmError::UsbError(msg)) if msg.contains("zero-length")
        ));

        // 3. Unbounded consecutive leading ZLPs are rejected after CCID_MAX_LEADING_ZLPS
        let mut too_many_zlps = CcidFrameAssembler::new(0x07, 64);
        for _ in 0..CCID_MAX_LEADING_ZLPS {
            assert!(too_many_zlps.push_packet(&[]).unwrap().is_none());
        }
        assert!(matches!(
            too_many_zlps.push_packet(&[]),
            Err(WasmError::UsbError(msg)) if msg.contains("zero-length")
        ));
    }
}
