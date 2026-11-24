//! Browser HTTP transport for the local PC/SC loopback bridge.
//!
//! [`BridgeTransport`] talks to a locally running `yubikey-cli bridge` over
//! `http://127.0.0.1:<port>` using browser `fetch()` with CORS and a bearer
//! token. Because it delegates smart card I/O to native PC/SC, it works with
//! real YubiKeys across macOS, Linux, and Windows in Chrome, Firefox, Safari,
//! Edge, and Brave.
//!
//! Only `127.0.0.1` is accepted: the bridge binds and answers only there, and a
//! `localhost` or `[::1]` URL could reach another local process listening on
//! the IPv6 loopback, which would receive the bearer token and the PIN.

use std::fmt;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, RequestMode, RequestRedirect, Response};
use zeroize::Zeroizing;

use yubikey_evm_signer_core::yubikey::Slot;
use yubikey_evm_signer_core::yubikey::apdu::{Apdu, ApduResponse};

use crate::error::{WasmError, WasmResult};
use crate::transport::{AsyncApduTransport, exchange_apdu_full, transmit_apdu_full};

/// Error message for every rejected bridge URL.
pub const BRIDGE_URL_ERROR: &str = "Bridge URL must be http://127.0.0.1:<port> with a port other \
     than 80 (localhost and [::1] are not accepted)";

/// Minimum bridge bearer token length, in characters (same rule as the bridge).
pub const BRIDGE_MIN_TOKEN_LEN: usize = 32;

/// Validates the local PC/SC bridge URL and returns its canonical form.
///
/// Accepts only `http://127.0.0.1:<port>` with a decimal port of 1 to 5 digits
/// in `1..=65535` other than `80`, an optional trailing `/`, and surrounding
/// whitespace. The result is `http://127.0.0.1:<port>` without the slash and
/// without leading zeros in the port. Every other URL is rejected, including
/// `localhost`, `[::1]`, other hosts, `https://`, credentials, paths, queries
/// and fragments. Port `80` (however it is spelled, e.g. `080`) is rejected
/// because browsers omit the default HTTP port from the `Host` header, which
/// the bridge requires to be exactly `127.0.0.1:<port>`.
///
/// # Errors
///
/// Returns [`WasmError::BridgeError`] with [`BRIDGE_URL_ERROR`].
pub fn validate_bridge_url(url: &str) -> WasmResult<String> {
    let reject = || WasmError::BridgeError(BRIDGE_URL_ERROR.to_string());
    let trimmed = url.trim();
    let authority_port = trimmed
        .strip_prefix("http://127.0.0.1:")
        .ok_or_else(reject)?;
    let port_str = authority_port.strip_suffix('/').unwrap_or(authority_port);
    if port_str.is_empty() || port_str.len() > 5 || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(reject());
    }
    match port_str.parse::<u16>() {
        Ok(port) if port != 0 && port != 80 => Ok(format!("http://127.0.0.1:{port}")),
        _ => Err(reject()),
    }
}

/// Validates a bridge bearer token (surrounding whitespace is ignored).
///
/// The bridge only accepts tokens of at least [`BRIDGE_MIN_TOKEN_LEN`] visible
/// ASCII characters, so anything else is rejected before a request is sent.
///
/// # Errors
///
/// Returns [`WasmError::BridgeError`] if the token is too short or contains
/// whitespace, control or non-ASCII characters.
pub fn validate_bridge_token(token: &str) -> WasmResult<&str> {
    let trimmed = token.trim();
    if trimmed.len() < BRIDGE_MIN_TOKEN_LEN || !trimmed.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(WasmError::BridgeError(format!(
            "Bridge bearer token must be at least {BRIDGE_MIN_TOKEN_LEN} visible ASCII characters \
             with no spaces; paste the token printed by `yubikey-cli bridge`"
        )));
    }
    Ok(trimmed)
}

/// Message for a `fetch()` that rejected without an HTTP response.
///
/// Either nothing listens at `base_url`, or the bridge is running but refused
/// this page's origin: that `403` carries no CORS headers, so the browser hides
/// it and `fetch()` rejects exactly as if the bridge were down.
#[must_use]
pub fn fetch_failure_message(base_url: &str, page_origin: &str) -> String {
    format!(
        "Failed to reach the local PC/SC bridge at {base_url}. Either the bridge is not \
         running (start it with `just cli-bridge` or `yubikey-cli bridge`), or it is running \
         but does not allow this page's origin {page_origin} (the browser hides the bridge's \
         reply in that case); restart it with `yubikey-cli bridge --allow-origin {page_origin}`."
    )
}

/// Maps a non-success bridge HTTP status and its `error` message to a [`WasmError`].
///
/// `409` (session unknown, replaced, expired, or closed after another PC/SC
/// client reset the card) and `503` (YubiKey or reader lost, or bridge shutting
/// down) end the session and map to [`WasmError::Disconnected`]; everything
/// else is a [`WasmError::BridgeError`]. The server's message is always kept
/// verbatim.
#[must_use]
pub fn bridge_http_error(status: u16, server_msg: &str) -> WasmError {
    match status {
        401 => WasmError::BridgeError(
            "Bridge authentication failed (401 Unauthorized): verify your session bearer token"
                .to_string(),
        ),
        403 => WasmError::BridgeError(format!(
            "Bridge refused the request (403 Forbidden): {server_msg}"
        )),
        404 => WasmError::BridgeError(format!("Bridge found no YubiKey (404): {server_msg}")),
        408 => WasmError::BridgeError(format!(
            "Bridge timed out reading the request (408 Request Timeout): {server_msg}; retry"
        )),
        409 => WasmError::Disconnected(format!(
            "bridge session ended (409 Conflict): {server_msg}. The session expired after being \
             idle, was replaced by another connection, or another PC/SC client reset the \
             YubiKey; reconnect (PIV selection, PIN and management key authentication must be \
             repeated)"
        )),
        413 => WasmError::BridgeError(format!(
            "Bridge rejected an oversized request (413 Payload Too Large): {server_msg}"
        )),
        503 => WasmError::Disconnected(format!(
            "bridge lost the YubiKey or is shutting down (503 Service Unavailable): \
             {server_msg}; reconnect once the YubiKey is plugged in and the bridge is running"
        )),
        _ => WasmError::BridgeError(format!(
            "Bridge request failed (HTTP {status}): {server_msg}"
        )),
    }
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
    /// * `token` - Bearer token printed by `yubikey-cli bridge` (valid until the bridge stops)
    ///
    /// # Errors
    ///
    /// Returns [`WasmError::BridgeError`] if the URL is not
    /// `http://127.0.0.1:<port>` with a port other than `80` (see
    /// [`validate_bridge_url`]), the token is not at least
    /// [`BRIDGE_MIN_TOKEN_LEN`] visible ASCII characters (both checked before any
    /// request), the bridge is unreachable or refuses the request, or PIV
    /// selection fails; [`WasmError::Disconnected`] on `409`/`503`.
    pub async fn connect(url: &str, token: &str) -> WasmResult<Self> {
        let base_url = validate_bridge_url(url)?;
        let token_trimmed = validate_bridge_token(token)?;

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
    /// Returns [`WasmError::BridgeError`] or [`WasmError::CoreError`];
    /// [`WasmError::Disconnected`] if the session is closed or the bridge answers
    /// `409`/`503` (the transport is then disconnected).
    pub async fn transmit_async(&mut self, apdu: &Apdu) -> WasmResult<ApduResponse> {
        let session_id = self
            .session_id
            .as_ref()
            .filter(|_| self.connected)
            .ok_or_else(|| {
                WasmError::Disconnected(
                    "the bridge session is closed; reconnect to the bridge".to_string(),
                )
            })?
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

    /// Exchanges an APDU like [`Self::transmit_full_async`] but returns the
    /// final status word instead of converting it into an error.
    ///
    /// # Errors
    ///
    /// Returns bridge or response-size errors.
    pub async fn exchange_full_async(&mut self, apdu: &Apdu) -> WasmResult<ApduResponse> {
        exchange_apdu_full(self, apdu).await
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
                let origin = window.origin();
                WasmError::BridgeError(fetch_failure_message(&self.base_url, &origin))
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

        let error = bridge_http_error(status, &server_msg);
        if error.ends_session() {
            // The bridge dropped (or never had) this session: never reuse it.
            self.connected = false;
            self.session_id = None;
        }
        Err(error)
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
    fn validate_bridge_url_accepts_only_127_0_0_1() {
        for (input, canonical) in [
            ("http://127.0.0.1:8765", "http://127.0.0.1:8765"),
            ("http://127.0.0.1:8765/", "http://127.0.0.1:8765"),
            ("  http://127.0.0.1:1 ", "http://127.0.0.1:1"),
            ("http://127.0.0.1:65535", "http://127.0.0.1:65535"),
            ("http://127.0.0.1:08765", "http://127.0.0.1:8765"),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
            ("http://127.0.0.1:81", "http://127.0.0.1:81"),
            ("http://127.0.0.1:800", "http://127.0.0.1:800"),
        ] {
            assert_eq!(validate_bridge_url(input).unwrap(), canonical, "{input}");
        }

        let rejected = [
            "",
            "http://localhost:8765",
            "http://LOCALHOST:8765",
            "http://[::1]:8765",
            "http://[::ffff:127.0.0.1]:8765",
            "http://127.0.0.2:8765",
            "http://127.1:8765",
            "HTTP://127.0.0.1:8765",
            "https://evil.com",
            "https://127.0.0.1:8765",
            "http://192.168.1.5:8765",
            "http://0.0.0.0:8765",
            "http://user:pass@127.0.0.1:8765",
            "http://127.0.0.1@evil.com:8765",
            "http://127.0.0.1.evil.com:8765",
            "http://127.0.0.1:8765/v1/health",
            "http://127.0.0.1:8765//",
            "http://127.0.0.1:8765?foo=bar",
            "http://127.0.0.1:8765#frag",
            "http://127.0.0.1",
            "http://127.0.0.1:",
            "http://127.0.0.1:0",
            "http://127.0.0.1:80",
            "http://127.0.0.1:80/",
            "http://127.0.0.1:080",
            "http://127.0.0.1:00080",
            "http://127.0.0.1:65536",
            "http://127.0.0.1:99999",
            "http://127.0.0.1:123456",
            "http://127.0.0.1:+8765",
            "http://127.0.0.1:8765\r\nEvil: 1",
            "http://127.0.0.1: 8765",
        ];

        for bad in rejected {
            assert_eq!(
                validate_bridge_url(bad),
                Err(WasmError::BridgeError(BRIDGE_URL_ERROR.to_string())),
                "expected '{bad}' to be rejected"
            );
        }
    }

    #[test]
    fn validate_bridge_token_requires_32_visible_ascii_characters() {
        let token = "A".repeat(BRIDGE_MIN_TOKEN_LEN);
        assert_eq!(validate_bridge_token(&token).unwrap(), token);
        assert_eq!(
            validate_bridge_token(&format!("  {token}\n")).unwrap(),
            token
        );
        let long = "x7-_~!".repeat(11);
        assert_eq!(validate_bridge_token(&long).unwrap(), long);

        for bad in [
            String::new(),
            "short-token".to_string(),
            "a".repeat(BRIDGE_MIN_TOKEN_LEN - 1),
            format!("{} b", "a".repeat(BRIDGE_MIN_TOKEN_LEN)),
            format!("{}\tb", "a".repeat(BRIDGE_MIN_TOKEN_LEN)),
            format!("{}\u{e9}", "a".repeat(BRIDGE_MIN_TOKEN_LEN)),
        ] {
            assert!(
                matches!(validate_bridge_token(&bad), Err(WasmError::BridgeError(msg)) if msg.contains("32 visible ASCII")),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn fetch_failure_names_both_causes_and_the_origin_fix() {
        let msg = fetch_failure_message("http://127.0.0.1:8765", "https://app.example");
        assert!(msg.contains("http://127.0.0.1:8765"));
        assert!(msg.contains("not running"));
        assert!(msg.contains("just cli-bridge"));
        assert!(msg.contains("does not allow this page's origin https://app.example"));
        assert!(msg.contains("yubikey-cli bridge --allow-origin https://app.example"));
    }

    #[test]
    fn bridge_statuses_map_to_clear_errors() {
        let generate_disabled = "APDU rejected by bridge policy: APDU command failed: key \
            generation is disabled on this bridge (...); restart the bridge with \
            --allow-generate to permit it";
        let forbidden = bridge_http_error(403, generate_disabled);
        assert!(!forbidden.ends_session());
        assert!(forbidden.to_string().contains("403 Forbidden"));
        assert!(forbidden.to_string().contains(generate_disabled));

        for status in [409, 503] {
            let err = bridge_http_error(status, "server says why");
            assert!(err.ends_session(), "{status}");
            let text = err.to_string();
            assert!(text.starts_with("Disconnected: "), "{text}");
            assert!(text.contains(&status.to_string()));
            assert!(text.contains("server says why"));
            assert!(text.contains("reconnect"));
        }
        assert!(bridge_http_error(409, "x").to_string().contains("reset"));
        assert!(bridge_http_error(409, "x").to_string().contains("expired"));

        for (status, marker) in [
            (401, "401 Unauthorized"),
            (404, "404"),
            (408, "408 Request Timeout"),
            (413, "413 Payload Too Large"),
            (502, "HTTP 502"),
        ] {
            let err = bridge_http_error(status, "detail");
            assert!(!err.ends_session(), "{status}");
            assert!(err.to_string().contains(marker), "{status}: {err}");
        }
    }
}
