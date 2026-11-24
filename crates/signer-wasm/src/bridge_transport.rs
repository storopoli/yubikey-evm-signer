//! Browser HTTP transport for the local PC/SC loopback bridge.
//!
//! [`BridgeTransport`] talks to a locally running `yubikey-cli bridge` over
//! `http://127.0.0.1:<port>`, `http://localhost:<port>`, or `http://[::1]:<port>`
//! using browser `fetch()` with CORS and a per-session Bearer token. Because it
//! delegates smart card I/O to native PC/SC, it works with real YubiKeys across
//! macOS, Linux, and Windows in Chrome, Firefox, Safari, Edge, and Brave.

use std::fmt;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, RequestMode, RequestRedirect, Response};
use zeroize::Zeroizing;

use yubikey_evm_signer_core::yubikey::Slot;
use yubikey_evm_signer_core::yubikey::apdu::{Apdu, ApduResponse};

use crate::error::{WasmError, WasmResult};
use crate::transport::{AsyncApduTransport, transmit_apdu_full};

/// Validates that `url` is a strict plaintext loopback URL for the local PC/SC bridge.
///
/// Accepts only `http://127.0.0.1:<port>`, `http://localhost:<port>`, or
/// `http://[::1]:<port>` (with optional trailing `/`). Rejects non-loopback hosts,
/// HTTPS/other schemes, embedded credentials (`user:pass@`), paths, queries, and
/// fragments so PINs and management key traffic can never be sent to remote servers.
///
/// # Errors
///
/// Returns [`WasmError::BridgeError`] if the URL is not a valid loopback bridge URL.
pub fn validate_bridge_url(url: &str) -> WasmResult<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(WasmError::BridgeError(
            "Bridge URL must not be empty".to_string(),
        ));
    }

    if trimmed
        .bytes()
        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(WasmError::BridgeError(
            "Bridge URL must not contain whitespace or control characters".to_string(),
        ));
    }

    if trimmed.contains('@') || trimmed.contains('?') || trimmed.contains('#') {
        return Err(WasmError::BridgeError(
            "Bridge URL must not contain credentials, query parameters, or fragments".to_string(),
        ));
    }

    let Some(rest) = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("HTTP://"))
    else {
        return Err(WasmError::BridgeError(
            "Bridge URL must use http:// on a loopback address (e.g. http://127.0.0.1:8765)"
                .to_string(),
        ));
    };

    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains('/') {
        return Err(WasmError::BridgeError(
            "Bridge URL must not contain a path (expected http://127.0.0.1:<port>)".to_string(),
        ));
    }

    if let Some(port_str) = authority.strip_prefix("[::1]:") {
        let port = parse_valid_port(port_str)?;
        return Ok(format!("http://[::1]:{port}"));
    }

    let Some((host, port_str)) = authority.split_once(':') else {
        return Err(WasmError::BridgeError(
            "Bridge URL must specify an explicit loopback host and port (e.g. http://127.0.0.1:8765)"
                .to_string(),
        ));
    };

    // Reject extra colons (e.g. malformed IPv6)
    if port_str.contains(':') {
        return Err(WasmError::BridgeError(
            "Bridge URL authority is malformed".to_string(),
        ));
    }

    let host_lower = host.to_ascii_lowercase();
    if host_lower != "127.0.0.1" && host_lower != "localhost" {
        return Err(WasmError::BridgeError(format!(
            "Bridge URL host '{host}' is not loopback (only 127.0.0.1, localhost, or [::1] are permitted)"
        )));
    }

    let port = parse_valid_port(port_str)?;
    Ok(format!("http://{host_lower}:{port}"))
}

/// Parses a strictly decimal non-zero TCP port number.
fn parse_valid_port(port_str: &str) -> WasmResult<u16> {
    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WasmError::BridgeError(format!(
            "Invalid bridge port '{port_str}'"
        )));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| WasmError::BridgeError(format!("Invalid bridge port '{port_str}'")))?;
    if port == 0 {
        return Err(WasmError::BridgeError(
            "Bridge port must be between 1 and 65535".to_string(),
        ));
    }
    Ok(port)
}

/// Browser transport communicating with a local PC/SC loopback bridge via `fetch()`.
pub struct BridgeTransport {
    base_url: String,
    token: Zeroizing<String>,
    session_id: Option<Zeroizing<String>>,
    connected: bool,
}

impl fmt::Debug for BridgeTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BridgeTransport")
            .field("base_url", &self.base_url)
            .field("token", &"<redacted>")
            .field("has_session", &self.session_id.is_some())
            .field("connected", &self.connected)
            .finish()
    }
}

#[derive(Deserialize)]
struct ConnectResponse {
    session_id: String,
}

#[derive(Serialize)]
struct TransmitRequest<'a> {
    session_id: &'a str,
    apdu: &'a str,
}

#[derive(Deserialize)]
struct TransmitResponse {
    response: String,
}

#[derive(Serialize)]
struct DisconnectRequest<'a> {
    session_id: &'a str,
}

#[derive(Deserialize)]
struct BridgeErrorPayload {
    error: String,
}

impl BridgeTransport {
    /// Connects to a running local PC/SC loopback bridge and opens a PIV session.
    ///
    /// # Arguments
    ///
    /// * `url` - Loopback bridge URL (e.g. `"http://127.0.0.1:8765"`)
    /// * `token` - Per-session bearer token printed by `yubikey-cli bridge`
    ///
    /// # Errors
    ///
    /// Returns [`WasmError::BridgeError`] if the URL is non-loopback, the token is
    /// empty/invalid, the bridge is unreachable, or PIV selection fails.
    pub async fn connect(url: &str, token: &str) -> WasmResult<Self> {
        let base_url = validate_bridge_url(url)?;
        let token_trimmed = token.trim();
        if token_trimmed.is_empty()
            || token_trimmed
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(WasmError::BridgeError(
                "Bridge bearer token must be non-empty and contain no whitespace".to_string(),
            ));
        }

        let mut transport = Self {
            base_url,
            token: Zeroizing::new(token_trimmed.to_string()),
            session_id: None,
            connected: false,
        };

        let body = transport.post_json("/v1/connect", "{}").await?;
        let parsed: ConnectResponse = serde_json::from_str(&body).map_err(|e| {
            WasmError::BridgeError(format!("invalid /v1/connect response from bridge: {e}"))
        })?;

        if parsed.session_id.is_empty() {
            return Err(WasmError::BridgeError(
                "bridge returned an empty session_id".to_string(),
            ));
        }

        transport.session_id = Some(Zeroizing::new(parsed.session_id));
        transport.connected = true;
        Ok(transport)
    }

    /// Transmits a single APDU via `POST /v1/transmit`.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError::BridgeError`] or [`WasmError::CoreError`].
    pub async fn transmit_async(&mut self, apdu: &Apdu) -> WasmResult<ApduResponse> {
        let session_id = self
            .session_id
            .as_ref()
            .filter(|_| self.connected)
            .ok_or_else(|| WasmError::BridgeError("bridge transport is not connected".to_string()))?
            .clone();

        let apdu_bytes = Zeroizing::new(
            apdu.to_bytes()
                .map_err(|e| WasmError::CoreError(e.to_string()))?,
        );
        let apdu_hex = Zeroizing::new(hex::encode(&*apdu_bytes));

        let payload = Zeroizing::new(
            serde_json::to_string(&TransmitRequest {
                session_id: session_id.as_str(),
                apdu: apdu_hex.as_str(),
            })
            .map_err(|e| WasmError::BridgeError(format!("failed to serialize transmit: {e}")))?,
        );

        let resp_text = self.post_json("/v1/transmit", &payload).await?;

        let parsed: TransmitResponse = serde_json::from_str(&resp_text).map_err(|e| {
            WasmError::BridgeError(format!("invalid /v1/transmit response from bridge: {e}"))
        })?;

        let raw_response = hex::decode(parsed.response.trim()).map_err(|e| {
            WasmError::BridgeError(format!("invalid APDU response hex from bridge: {e}"))
        })?;

        ApduResponse::try_from_bytes(raw_response)
            .map_err(|e| WasmError::BridgeError(e.to_string()))
    }

    /// Transmits an APDU, handling `0x6C XX` wrong-`Le` retries and `0x61 XX`
    /// `GET RESPONSE` chaining (capped at 16 KiB / 128 chunks).
    ///
    /// # Errors
    ///
    /// Returns bridge, malformed-response, or mapped PIV status-word errors.
    pub async fn transmit_full_async(
        &mut self,
        apdu: &Apdu,
        slot: Option<Slot>,
    ) -> WasmResult<Vec<u8>> {
        transmit_apdu_full(self, apdu, slot).await
    }

    /// Disconnects the active bridge session (`POST /v1/disconnect`).
    ///
    /// # Errors
    ///
    /// Always returns `Ok(())` after best-effort disconnect cleanup.
    pub async fn close(&mut self) -> WasmResult<()> {
        if let Some(session_id) = self.session_id.take()
            && self.connected
            && let Ok(payload) = serde_json::to_string(&DisconnectRequest {
                session_id: session_id.as_str(),
            })
        {
            let _ = self.post_json("/v1/disconnect", &payload).await;
        }
        self.connected = false;
        Ok(())
    }

    /// Checks whether this bridge session is currently connected.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    /// Executes a `POST` request with JSON body and Bearer auth against the local bridge.
    async fn post_json(&mut self, path: &str, body: &str) -> WasmResult<String> {
        let window = web_sys::window().ok_or_else(|| {
            WasmError::BridgeError("browser Window object is not available".to_string())
        })?;

        let headers = Headers::new()
            .map_err(|e| WasmError::BridgeError(format!("failed to create Headers: {e:?}")))?;
        headers
            .set("Content-Type", "application/json")
            .map_err(|e| WasmError::BridgeError(format!("failed to set Content-Type: {e:?}")))?;
        let auth_header = Zeroizing::new(format!("Bearer {}", self.token.as_str()));
        headers
            .set("Authorization", auth_header.as_str())
            .map_err(|e| WasmError::BridgeError(format!("failed to set Authorization: {e:?}")))?;

        let init = RequestInit::new();
        init.set_method("POST");
        init.set_mode(RequestMode::Cors);
        init.set_redirect(RequestRedirect::Error);
        init.set_headers(&headers);
        init.set_body(&JsValue::from_str(body));

        let url = format!("{}{path}", self.base_url);
        let request = Request::new_with_str_and_init(&url, &init)
            .map_err(|e| WasmError::BridgeError(format!("failed to build fetch Request: {e:?}")))?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|_| {
                WasmError::BridgeError(format!(
                    "Failed to reach local PC/SC bridge at {}. Start it with `just cli-bridge` or `cargo run --example yubikey-cli -p yubikey-evm-signer-core --features pcsc -- bridge`.",
                    self.base_url
                ))
            })?;

        let response: Response = resp_value.unchecked_into();
        let status = response.status();

        let text_promise = response.text().map_err(|e| {
            WasmError::BridgeError(format!("failed to read bridge response body: {e:?}"))
        })?;
        let text_js = JsFuture::from(text_promise).await.map_err(|e| {
            WasmError::BridgeError(format!("failed to await bridge response text: {e:?}"))
        })?;
        let text = text_js.as_string().unwrap_or_default();

        if response.ok() {
            return Ok(text);
        }

        let server_msg = serde_json::from_str::<BridgeErrorPayload>(&text)
            .map(|p| p.error)
            .unwrap_or_else(|_| {
                if text.is_empty() {
                    format!("HTTP {status}")
                } else {
                    text
                }
            });

        match status {
            401 => Err(WasmError::BridgeError(
                "Bridge authentication failed (401 Unauthorized): verify your session bearer token"
                    .to_string(),
            )),
            403 => Err(WasmError::BridgeError(format!(
                "Bridge rejected request (403 Forbidden): {server_msg}"
            ))),
            409 | 503 => {
                self.connected = false;
                self.session_id = None;
                Err(WasmError::BridgeError(format!(
                    "Bridge session disconnected ({status}): {server_msg}"
                )))
            }
            _ => Err(WasmError::BridgeError(format!(
                "Bridge request failed (HTTP {status}): {server_msg}"
            ))),
        }
    }
}

impl AsyncApduTransport for BridgeTransport {
    async fn transmit_one(&mut self, apdu: &Apdu) -> WasmResult<ApduResponse> {
        self.transmit_async(apdu).await
    }

    fn transport_error(&self, msg: String) -> WasmError {
        WasmError::BridgeError(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_bridge_url_accepts_loopback_and_rejects_remote() {
        assert_eq!(
            validate_bridge_url("http://127.0.0.1:8765").unwrap(),
            "http://127.0.0.1:8765"
        );
        assert_eq!(
            validate_bridge_url("http://127.0.0.1:8765/").unwrap(),
            "http://127.0.0.1:8765"
        );
        assert_eq!(
            validate_bridge_url("  http://LOCALHOST:9000/ ").unwrap(),
            "http://localhost:9000"
        );
        assert_eq!(
            validate_bridge_url("http://[::1]:8765").unwrap(),
            "http://[::1]:8765"
        );

        let rejected = [
            "",
            "https://evil.com",
            "https://127.0.0.1:8765",
            "http://192.168.1.5:8765",
            "http://0.0.0.0:8765",
            "http://user:pass@127.0.0.1:8765",
            "http://localhost.evil.com:8765",
            "http://127.0.0.1:8765/v1/health",
            "http://127.0.0.1:8765?foo=bar",
            "http://127.0.0.1:8765#frag",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:99999",
            "http://127.0.0.1:8765\r\nEvil: 1",
        ];

        for bad in rejected {
            assert!(
                validate_bridge_url(bad).is_err(),
                "expected '{bad}' to be rejected"
            );
        }
    }
}
