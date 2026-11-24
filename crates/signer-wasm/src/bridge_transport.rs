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

/// Advice ending every error that discards an established bridge session.
const RECONNECT_ADVICE: &str = "reconnect with the bearer token the bridge currently prints (a \
     restarted bridge prints a new one); PIV selection, PIN and management key authentication \
     must be repeated";

/// Maps a `fetch()` that rejected without an HTTP response to a [`WasmError`].
///
/// Before a session is `established` (during `/v1/connect`) this is a
/// [`WasmError::BridgeError`] with [`fetch_failure_message`]. On an established
/// session it is [`WasmError::Disconnected`]: the bridge stopped, crashed, or
/// was restarted without this page's origin, so the session is gone.
#[must_use]
pub fn fetch_failure_error(base_url: &str, page_origin: &str, established: bool) -> WasmError {
    let reason = fetch_failure_message(base_url, page_origin);
    if established {
        WasmError::Disconnected(format!(
            "lost the bridge session because the bridge stopped answering. {reason} Then \
             {RECONNECT_ADVICE}"
        ))
    } else {
        WasmError::BridgeError(reason)
    }
}

/// Maps a failure to read a bridge response body (`detail`) to a [`WasmError`].
///
/// Before a session is `established` this is a [`WasmError::BridgeError`]
/// with `detail`. On an established session the connection to the bridge broke
/// mid-reply, so the session is treated as gone: [`WasmError::Disconnected`]
/// with the [`fetch_failure_message`] diagnostic.
#[must_use]
pub fn body_read_failure_error(
    detail: &str,
    base_url: &str,
    page_origin: &str,
    established: bool,
) -> WasmError {
    if established {
        WasmError::Disconnected(format!(
            "lost the bridge session because the connection broke while reading the bridge's \
             reply ({detail}). {} Then {RECONNECT_ADVICE}",
            fetch_failure_message(base_url, page_origin)
        ))
    } else {
        WasmError::BridgeError(detail.to_string())
    }
}

/// Maps a non-success bridge HTTP status and its `error` message to a [`WasmError`].
///
/// These statuses end the session and map to [`WasmError::Disconnected`]:
///
/// - `409`: session unknown, replaced, expired, or closed after another PC/SC
///   client reset the card;
/// - `503`: YubiKey or reader lost, or bridge shutting down;
/// - on an `established` session only, `401` (the bridge was restarted, so the
///   token is no longer valid) and `500` (the bridge's state is broken for good).
///
/// Everything else is a [`WasmError::BridgeError`] that keeps the session: the
/// bridge did not touch it (`400`, `403` APDU policy, `404`, `405`, `408`,
/// `413`, `415`, `431`, and `502` card communication errors). Before a session
/// is established, `401` means a mistyped token. The server's message is always
/// kept verbatim.
#[must_use]
pub fn bridge_http_error(status: u16, server_msg: &str, established: bool) -> WasmError {
    match status {
        401 if established => WasmError::Disconnected(format!(
            "bridge rejected the bearer token (401 Unauthorized): the bridge was restarted and \
             this session's token is no longer valid; {RECONNECT_ADVICE}"
        )),
        500 if established => WasmError::Disconnected(format!(
            "bridge internal error (500 Internal Server Error): {server_msg}; the bridge can no \
             longer serve this session. Restart the bridge, then {RECONNECT_ADVICE}"
        )),
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
    /// [`WasmError::Disconnected`] if the session is closed, the bridge stopped
    /// answering, or it answers `401`, `409`, `500` or `503` (the transport is
    /// then disconnected; see [`bridge_http_error`]).
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
    /// The transport is marked disconnected before the request is sent, and
    /// any failure (including an unreachable bridge) is ignored.
    ///
    /// # Errors
    ///
    /// Always returns `Ok(())` after best-effort disconnect cleanup.
    pub async fn close(&mut self) -> WasmResult<()> {
        let was_connected = std::mem::replace(&mut self.connected, false);
        if let Some(session_id) = self.session_id.take()
            && was_connected
            && let Ok(payload) = serde_json::to_string(&DisconnectRequest {
                session_id: session_id.as_str(),
            })
        {
            let _ = self.post_json("/v1/disconnect", &payload).await;
        }
        Ok(())
    }

    /// Checks whether this bridge session is currently connected.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    /// Executes a `POST` request with JSON body and Bearer auth against the local
    /// bridge, ending the session on an error that means it cannot be used again.
    async fn post_json(&mut self, path: &str, body: &str) -> WasmResult<String> {
        let result = self.send_json(path, body).await;
        self.end_session_on_error(result)
    }

    /// Marks the transport disconnected if `result` is an error that ends the
    /// session (see [`WasmError::ends_session`]), so the session is never reused.
    fn end_session_on_error<T>(&mut self, result: WasmResult<T>) -> WasmResult<T> {
        if matches!(&result, Err(e) if e.ends_session()) {
            self.connected = false;
            self.session_id = None;
        }
        result
    }

    /// Sends one `POST` request and maps every failure to a [`WasmError`]
    /// according to whether a session is established (see
    /// [`fetch_failure_error`], [`body_read_failure_error`], [`bridge_http_error`]).
    async fn send_json(&self, path: &str, body: &str) -> WasmResult<String> {
        let established = self.connected;
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
            .map_err(|_| fetch_failure_error(&self.base_url, &window.origin(), established))?;

        let response: Response = resp_value.unchecked_into();
        let status = response.status();

        let body_error = |detail: String| {
            body_read_failure_error(&detail, &self.base_url, &window.origin(), established)
        };
        let text_promise = response
            .text()
            .map_err(|e| body_error(format!("failed to read bridge response body: {e:?}")))?;
        let text_js = JsFuture::from(text_promise)
            .await
            .map_err(|e| body_error(format!("failed to await bridge response text: {e:?}")))?;
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

        Err(bridge_http_error(status, &server_msg, established))
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
        for established in [false, true] {
            let forbidden = bridge_http_error(403, generate_disabled, established);
            assert!(!forbidden.ends_session());
            assert!(forbidden.to_string().contains("403 Forbidden"));
            assert!(forbidden.to_string().contains(generate_disabled));

            for status in [409, 503] {
                let err = bridge_http_error(status, "server says why", established);
                assert!(err.ends_session(), "{status}");
                let text = err.to_string();
                assert!(text.starts_with("Disconnected: "), "{text}");
                assert!(text.contains(&status.to_string()));
                assert!(text.contains("server says why"));
                assert!(text.contains("reconnect"));
            }
            assert!(
                bridge_http_error(409, "x", established)
                    .to_string()
                    .contains("reset")
            );
            assert!(
                bridge_http_error(409, "x", established)
                    .to_string()
                    .contains("expired")
            );

            // The bridge left the session untouched: it stays usable.
            for (status, marker) in [
                (400, "HTTP 400"),
                (404, "404"),
                (405, "HTTP 405"),
                (408, "408 Request Timeout"),
                (413, "413 Payload Too Large"),
                (415, "HTTP 415"),
                (431, "HTTP 431"),
                (502, "HTTP 502"),
            ] {
                let err = bridge_http_error(status, "detail", established);
                assert!(!err.ends_session(), "{status}");
                assert!(
                    matches!(&err, WasmError::BridgeError(_)),
                    "{status}: {err:?}"
                );
                assert!(err.to_string().contains(marker), "{status}: {err}");
            }
        }

        // During /v1/connect a 401 is a mistyped token and a 500 a failed connect.
        let wrong_token = bridge_http_error(401, "missing or invalid bearer token", false);
        assert!(!wrong_token.ends_session());
        assert!(wrong_token.to_string().contains("401 Unauthorized"));
        assert!(
            wrong_token
                .to_string()
                .contains("verify your session bearer token")
        );
        let internal = bridge_http_error(500, "failed to generate session ID", false);
        assert!(!internal.ends_session());
        assert!(internal.to_string().contains("HTTP 500"));

        // On an established session a 401 means the bridge was restarted with a
        // new token, and a 500 that its state is broken for good.
        let restarted = bridge_http_error(401, "missing or invalid bearer token", true);
        assert!(restarted.ends_session());
        let text = restarted.to_string();
        assert!(text.starts_with("Disconnected: "), "{text}");
        assert!(text.contains("401 Unauthorized"));
        assert!(text.contains("no longer valid"));
        assert!(text.contains("reconnect with the bearer token the bridge currently prints"));

        let broken = bridge_http_error(500, "bridge state lock poisoned", true);
        assert!(broken.ends_session());
        let text = broken.to_string();
        assert!(text.starts_with("Disconnected: "), "{text}");
        assert!(text.contains("500 Internal Server Error"));
        assert!(text.contains("bridge state lock poisoned"));
        assert!(text.contains("Restart the bridge"));
        assert!(text.contains("reconnect"));
    }

    #[test]
    fn unreachable_bridge_ends_only_an_established_session() {
        let (url, origin) = ("http://127.0.0.1:8765", "https://app.example");
        let diagnostic = fetch_failure_message(url, origin);
        let detail = "failed to await bridge response text: JsValue(TypeError)";

        // Initial /v1/connect: keep the plain reachability / origin diagnostic.
        assert_eq!(
            fetch_failure_error(url, origin, false),
            WasmError::BridgeError(diagnostic.clone())
        );
        assert_eq!(
            body_read_failure_error(detail, url, origin, false),
            WasmError::BridgeError(detail.to_string())
        );

        // Established session: the session is gone, with the same diagnostic.
        for (err, specific) in [
            (fetch_failure_error(url, origin, true), "stopped answering"),
            (
                body_read_failure_error(detail, url, origin, true),
                "connection broke while reading the bridge's reply",
            ),
        ] {
            assert!(err.ends_session(), "{err}");
            let text = err.to_string();
            assert!(
                text.starts_with("Disconnected: lost the bridge session"),
                "{text}"
            );
            assert!(text.contains(specific), "{text}");
            assert!(text.contains(&diagnostic), "{text}");
            assert!(text.contains("not running"), "{text}");
            assert!(
                text.contains("yubikey-cli bridge --allow-origin https://app.example"),
                "{text}"
            );
            assert!(
                text.contains("reconnect with the bearer token the bridge currently prints"),
                "{text}"
            );
        }
        assert!(
            body_read_failure_error(detail, url, origin, true)
                .to_string()
                .contains(detail)
        );
    }

    fn connected_transport() -> BridgeTransport {
        BridgeTransport {
            base_url: "http://127.0.0.1:8765".to_string(),
            token: Zeroizing::new("t".repeat(BRIDGE_MIN_TOKEN_LEN)),
            session_id: Some(Zeroizing::new(
                "00112233445566778899aabbccddeeff".to_string(),
            )),
            connected: true,
        }
    }

    #[test]
    fn session_ending_errors_disconnect_the_transport() {
        use crate::transport::test_support::block_on;

        let (url, origin) = ("http://127.0.0.1:8765", "https://app.example");
        for err in [
            fetch_failure_error(url, origin, true),
            body_read_failure_error("detail", url, origin, true),
            bridge_http_error(401, "x", true),
            bridge_http_error(409, "x", true),
            bridge_http_error(500, "x", true),
            bridge_http_error(503, "x", true),
        ] {
            let mut transport = connected_transport();
            let result: WasmResult<String> = transport.end_session_on_error(Err(err.clone()));
            assert_eq!(result, Err(err.clone()));
            assert!(!transport.is_connected(), "{err}");
            assert!(transport.session_id.is_none(), "{err}");

            // Later calls fail fast without contacting the bridge...
            let apdu = Apdu::new(0x00, 0xCB, 0x3F, 0xFF, Vec::new());
            assert!(matches!(
                block_on(transport.transmit_async(&apdu)),
                Err(WasmError::Disconnected(msg)) if msg.contains("reconnect")
            ));
            // ...and closing the dead session sends nothing and never fails.
            assert_eq!(block_on(transport.close()), Ok(()));
            assert!(!transport.is_connected());
        }

        for err in [
            bridge_http_error(403, "APDU rejected by bridge policy", true),
            bridge_http_error(408, "x", true),
            bridge_http_error(413, "x", true),
            bridge_http_error(502, "x", true),
            WasmError::BridgeError("failed to build fetch Request".to_string()),
        ] {
            let mut transport = connected_transport();
            let result: WasmResult<String> = transport.end_session_on_error(Err(err.clone()));
            assert_eq!(result, Err(err.clone()));
            assert!(transport.is_connected(), "{err}");
            assert!(transport.session_id.is_some(), "{err}");
        }

        let mut transport = connected_transport();
        assert_eq!(
            transport.end_session_on_error(Ok("{}".to_string())),
            Ok("{}".to_string())
        );
        assert!(transport.is_connected());
    }
}
